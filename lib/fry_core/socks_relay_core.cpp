#include "socks_relay_core.h"

#include <cerrno>
#include <cstring>

namespace fry_relay {

namespace {

const uint8_t kMethodOk[2] = {0x05, 0x00};
const uint8_t kMethodNone[2] = {0x05, 0xFF};
const uint8_t kReplyOk[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
const uint8_t kReplyFail[10] = {0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0};

uint32_t elapsed(uint32_t now, uint32_t since) { return now - since; }  // wrap-safe

uint32_t remaining(uint32_t limit, uint32_t el) { return el >= limit ? 0 : limit - el; }

bool isHandshake(const Slot& s) { return s.phase == Phase::Greeting || s.phase == Phase::Request; }
bool isLive(const Slot& s) { return s.phase != Phase::Free && s.phase != Phase::Closed; }

void closeSlot(Slot& s, CloseReason why) {
  if (s.phase == Phase::Closed) return;
  s.phase = Phase::Closed;
  s.reason = why;
}

// Append a reply to the client-bound buffer. The buffer is empty or nearly so in every phase that
// queues one (handshake replies are 2 and 10 bytes), but compact first if the tail is short.
void queueClient(Slot& s, const uint8_t* d, size_t n) {
  if (s.u2cLen + n > kBufSize && s.u2cOff > 0) {
    memmove(s.u2c, s.u2c + s.u2cOff, s.u2cLen - s.u2cOff);
    s.u2cLen = static_cast<uint16_t>(s.u2cLen - s.u2cOff);
    s.u2cOff = 0;
  }
  if (s.u2cLen + n > kBufSize) return;  // cannot happen: at most 12 bytes before Relay
  memcpy(s.u2c + s.u2cLen, d, n);
  s.u2cLen = static_cast<uint16_t>(s.u2cLen + n);
}

// Drop exactly `n` consumed bytes from the front of the client-bound-for-upstream buffer and keep
// the rest: a CONNECT request (and even early payload) pipelined behind the greeting stays put.
void consumeFront(Slot& s, size_t n) {
  if (n > s.c2uLen) n = s.c2uLen;
  memmove(s.c2u, s.c2u + n, s.c2uLen - n);
  s.c2uLen = static_cast<uint16_t>(s.c2uLen - n);
  s.c2uOff = 0;
}

void enterFlush(Slot& s, CloseReason why, uint32_t now) {
  s.c2uOff = s.c2uLen = 0;  // anything the client sent after a rejected step is not forwarded
  s.flushReason = why;
  s.phase = Phase::Flush;
  s.phaseStartMs = now;
}

// Parse as far as the buffered bytes allow. One call can walk Greeting -> Request -> NeedConnect
// when the client pipelined everything into one segment.
void advance(Slot& s, uint32_t now) {
  for (;;) {
    if (s.phase == Phase::Greeting) {
      fry::Socks5Greeting g;
      size_t used = 0;
      fry::Socks5Result r = fry::parseGreeting(s.c2u, s.c2uLen, g, used);
      if (r == fry::Socks5Result::NeedMoreData) return;
      if (r == fry::Socks5Result::Ok) {
        queueClient(s, kMethodOk, sizeof(kMethodOk));
        consumeFront(s, used);
        s.phase = Phase::Request;
        s.phaseStartMs = now;
        continue;
      }
      queueClient(s, kMethodNone, sizeof(kMethodNone));
      enterFlush(s, CloseReason::HandshakeBad, now);
      return;
    }
    if (s.phase == Phase::Request) {
      size_t used = 0;
      fry::Socks5Result r = fry::parseConnectRequest(s.c2u, s.c2uLen, s.req, used);
      if (r == fry::Socks5Result::NeedMoreData) return;
      if (r == fry::Socks5Result::Ok) {
        consumeFront(s, used);
        s.phase = Phase::NeedConnect;
        s.phaseStartMs = now;
        return;
      }
      queueClient(s, kReplyFail, sizeof(kReplyFail));
      enterFlush(s, CloseReason::HandshakeBad, now);
      return;
    }
    return;
  }
}

// A byte moved in the Relay phase. Besides the idle clock, a half-closed session's cutoff follows
// it: halfCloseMs bounds the time without progress, not the total time after the first FIN.
void touch(Slot& s, uint32_t now) {
  s.lastActivityMs = now;
  if (s.halfClosing) s.halfCloseStartMs = now;
}

// Forward each FIN once (the flags are one-shot: every later recv/send result re-runs this), once
// the opposite buffer has drained, and finish when both sides are done.
void relayUpdate(Slot& s, uint32_t now) {
  if (s.phase != Phase::Relay) return;
  const bool c2uEmpty = s.c2uOff == s.c2uLen;
  const bool u2cEmpty = s.u2cOff == s.u2cLen;
  if (!s.clientRdOpen && c2uEmpty && !s.upWrShut) s.pendShutUp = true;
  if (!s.upRdOpen && u2cEmpty && !s.clientWrShut) s.pendShutClient = true;
  if (!s.clientRdOpen && !s.upRdOpen && c2uEmpty && u2cEmpty) {
    closeSlot(s, CloseReason::Done);
    return;
  }
  if ((!s.clientRdOpen || !s.upRdOpen) && !s.halfClosing) {
    s.halfClosing = true;
    s.halfCloseStartMs = now;
  }
}

IoResult classifyErrno(int err) {
  // EINPROGRESS / EALREADY come back from lwIP's recv() on a socket whose netconn is still in a
  // connect state (errno 119 on the bench). They mean "not yet", not "dead". ENOMEM / ENOBUFS is
  // lwIP's ERR_MEM from a full send queue or an exhausted pbuf pool: retry, the idle deadline
  // bounds it.
  if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR || err == EINPROGRESS ||
      err == EALREADY || err == ENOMEM || err == ENOBUFS) {
    return IoResult::WouldBlock;
  }
  if (err == ECONNRESET || err == EPIPE || err == ENOTCONN || err == ECONNABORTED ||
      err == ECONNREFUSED || err == ETIMEDOUT || err == EHOSTUNREACH || err == ENETUNREACH) {
    return IoResult::Closed;
  }
  return IoResult::Error;
}

}  // namespace

IoResult classifyRecv(long ret, int err) {
  if (ret > 0) return IoResult::Data;
  if (ret == 0) return IoResult::Eof;  // errno is stale here by definition
  return classifyErrno(err);
}

IoResult classifySend(long ret, int err) {
  if (ret > 0) return IoResult::Data;
  if (ret == 0) return IoResult::WouldBlock;
  return classifyErrno(err);
}

ConnectStart classifyConnectStart(int ret, int err) {
  if (ret == 0) return ConnectStart::Done;
  if (err == EINPROGRESS || err == EALREADY || err == EWOULDBLOCK || err == EAGAIN) {
    return ConnectStart::InProgress;
  }
  if (err == EISCONN) return ConnectStart::Done;
  return ConnectStart::Failed;
}

SelectAction classifySelect(int ret, int err) {
  if (ret > 0) return SelectAction::Ready;
  if (ret == 0) return SelectAction::Timeout;
  return err == EINTR ? SelectAction::Interrupted : SelectAction::Failed;
}

uint32_t selectFailBackoffMs(uint32_t consecutiveFailures) {
  const uint32_t n = consecutiveFailures > 10 ? 10 : consecutiveFailures;
  return n * 10;
}

void slotInit(Slot& s, int clientFd, uint32_t now) {
  s.phase = Phase::Greeting;
  s.reason = CloseReason::None;
  s.flushReason = CloseReason::None;
  s.clientFd = clientFd;
  s.upFd = kNoFd;
  s.acceptedMs = now;
  s.phaseStartMs = now;
  s.lastActivityMs = now;
  s.halfCloseStartMs = 0;
  s.halfClosing = false;
  s.clientRdOpen = true;
  s.upRdOpen = true;
  s.pendShutUp = false;
  s.pendShutClient = false;
  s.upWrShut = false;
  s.clientWrShut = false;
  s.c2uOff = s.c2uLen = 0;
  s.u2cOff = s.u2cLen = 0;
  s.req = fry::Socks5ConnectRequest();
}

Wants slotWants(const Slot& s) {
  Wants w;
  const bool c2uPending = s.c2uOff < s.c2uLen;
  const bool u2cPending = s.u2cOff < s.u2cLen;
  switch (s.phase) {
    case Phase::Greeting:
    case Phase::Request:
      w.clientRd = true;
      w.clientWr = u2cPending;
      break;
    case Phase::NeedConnect:
      w.clientWr = u2cPending;
      break;
    case Phase::Connecting:
      w.upWr = true;  // writable = the connect finished (or failed: SO_ERROR says which)
      w.clientWr = u2cPending;  // a pipelined client already waits for the method reply
      break;
    case Phase::Relay:
      w.clientRd = s.clientRdOpen && !c2uPending;
      w.upWr = c2uPending;
      w.upRd = s.upRdOpen && !u2cPending;
      w.clientWr = u2cPending;
      break;
    case Phase::Flush:
      w.clientWr = u2cPending;
      break;
    default:
      break;
  }
  return w;
}

uint8_t* recvDest(Slot& s, Side side, size_t& room) {
  room = 0;
  if (side == Side::Client) {
    if (isHandshake(s)) {
      room = kBufSize - s.c2uLen;
      return s.c2u + s.c2uLen;
    }
    if (s.phase == Phase::Relay && s.clientRdOpen && s.c2uOff == s.c2uLen) {
      s.c2uOff = s.c2uLen = 0;
      room = kBufSize;
      return s.c2u;
    }
    return s.c2u;
  }
  if (s.phase == Phase::Relay && s.upRdOpen && s.u2cOff == s.u2cLen) {
    s.u2cOff = s.u2cLen = 0;
    room = kBufSize;
    return s.u2c;
  }
  return s.u2c;
}

const uint8_t* sendSrc(const Slot& s, Side to, size_t& len) {
  if (to == Side::Up) {
    len = s.phase == Phase::Relay ? static_cast<size_t>(s.c2uLen - s.c2uOff) : 0;
    return s.c2u + s.c2uOff;
  }
  const bool mayWrite = isHandshake(s) || s.phase == Phase::NeedConnect ||
                        s.phase == Phase::Connecting || s.phase == Phase::Relay ||
                        s.phase == Phase::Flush;
  len = mayWrite ? static_cast<size_t>(s.u2cLen - s.u2cOff) : 0;
  return s.u2c + s.u2cOff;
}

void onRecv(Slot& s, Side from, long ret, int err, uint32_t now) {
  if (!isLive(s)) return;
  switch (classifyRecv(ret, err)) {
    case IoResult::Data: {
      size_t n = static_cast<size_t>(ret);
      if (from == Side::Client) {
        if (isHandshake(s)) {
          if (n > kBufSize - s.c2uLen) n = kBufSize - s.c2uLen;
          s.c2uLen = static_cast<uint16_t>(s.c2uLen + n);
          s.lastActivityMs = now;  // not silent: poolEvictIndex ages a slot by idle time
          advance(s, now);
        } else if (s.phase == Phase::Relay) {
          if (n > kBufSize - s.c2uLen) n = kBufSize - s.c2uLen;
          s.c2uLen = static_cast<uint16_t>(s.c2uLen + n);
          touch(s, now);
        }
      } else if (s.phase == Phase::Relay) {
        if (n > kBufSize - s.u2cLen) n = kBufSize - s.u2cLen;
        s.u2cLen = static_cast<uint16_t>(s.u2cLen + n);
        touch(s, now);
      }
      break;
    }
    case IoResult::Eof:
      if (isHandshake(s)) {
        closeSlot(s, CloseReason::HandshakeEof);
      } else if (s.phase == Phase::Relay) {
        (from == Side::Client ? s.clientRdOpen : s.upRdOpen) = false;
        touch(s, now);
      }
      break;
    case IoResult::WouldBlock:
      break;
    case IoResult::Closed:
    case IoResult::Error:
      closeSlot(s, isHandshake(s) ? CloseReason::HandshakeEof : CloseReason::IoError);
      break;
  }
  relayUpdate(s, now);
}

void onSend(Slot& s, Side to, long ret, int err, uint32_t now) {
  if (!isLive(s)) return;
  switch (classifySend(ret, err)) {
    case IoResult::Data: {
      size_t n = static_cast<size_t>(ret);
      if (to == Side::Up) {
        if (n > static_cast<size_t>(s.c2uLen - s.c2uOff)) n = s.c2uLen - s.c2uOff;
        s.c2uOff = static_cast<uint16_t>(s.c2uOff + n);
        if (s.c2uOff == s.c2uLen) s.c2uOff = s.c2uLen = 0;
      } else {
        if (n > static_cast<size_t>(s.u2cLen - s.u2cOff)) n = s.u2cLen - s.u2cOff;
        s.u2cOff = static_cast<uint16_t>(s.u2cOff + n);
        if (s.u2cOff == s.u2cLen) s.u2cOff = s.u2cLen = 0;
        if (s.phase == Phase::Flush && s.u2cLen == 0) closeSlot(s, s.flushReason);
      }
      if (s.phase == Phase::Relay) touch(s, now);
      break;
    }
    case IoResult::WouldBlock:
    case IoResult::Eof:
      break;
    case IoResult::Closed:
    case IoResult::Error:
      closeSlot(s, s.phase == Phase::Flush ? s.flushReason : CloseReason::IoError);
      break;
  }
  relayUpdate(s, now);
}

void onConnectStarted(Slot& s, int upFd, uint32_t now) {
  if (s.phase != Phase::NeedConnect) return;
  s.upFd = upFd;
  s.phase = Phase::Connecting;
  s.phaseStartMs = now;
}

static void connectFailed(Slot& s, CloseReason why, uint32_t now) {
  queueClient(s, kReplyFail, sizeof(kReplyFail));
  enterFlush(s, why, now);
}

void onConnectResult(Slot& s, bool ok, uint32_t now) {
  if (s.phase != Phase::NeedConnect && s.phase != Phase::Connecting) return;
  if (!ok) {
    connectFailed(s, CloseReason::ConnectFail, now);
    return;
  }
  queueClient(s, kReplyOk, sizeof(kReplyOk));
  s.phase = Phase::Relay;
  s.phaseStartMs = now;
  s.lastActivityMs = now;
}

void onTimer(Slot& s, const Timing& t, uint32_t now) {
  switch (s.phase) {
    case Phase::Greeting:
      if (elapsed(now, s.phaseStartMs) >= t.greetingMs) closeSlot(s, CloseReason::HandshakeTimeout);
      break;
    case Phase::Request:
      if (elapsed(now, s.phaseStartMs) >= t.requestMs) closeSlot(s, CloseReason::HandshakeTimeout);
      break;
    case Phase::NeedConnect:
    case Phase::Connecting:
      if (elapsed(now, s.phaseStartMs) >= t.connectMs) connectFailed(s, CloseReason::ConnectTimeout, now);
      break;
    case Phase::Relay:
      if (elapsed(now, s.lastActivityMs) >= t.idleMs) {
        closeSlot(s, CloseReason::Idle);
      } else if (s.halfClosing && elapsed(now, s.halfCloseStartMs) >= t.halfCloseMs) {
        closeSlot(s, CloseReason::HalfCloseTimeout);
      }
      break;
    case Phase::Flush:
      if (elapsed(now, s.phaseStartMs) >= t.flushMs) closeSlot(s, s.flushReason);
      break;
    default:
      break;
  }
}

uint32_t slotRemainingMs(const Slot& s, const Timing& t, uint32_t now) {
  switch (s.phase) {
    case Phase::Greeting:
      return remaining(t.greetingMs, elapsed(now, s.phaseStartMs));
    case Phase::Request:
      return remaining(t.requestMs, elapsed(now, s.phaseStartMs));
    case Phase::NeedConnect:
    case Phase::Connecting:
      return remaining(t.connectMs, elapsed(now, s.phaseStartMs));
    case Phase::Relay: {
      uint32_t r = remaining(t.idleMs, elapsed(now, s.lastActivityMs));
      if (s.halfClosing) {
        const uint32_t h = remaining(t.halfCloseMs, elapsed(now, s.halfCloseStartMs));
        if (h < r) r = h;
      }
      return r;
    }
    case Phase::Flush:
      return remaining(t.flushMs, elapsed(now, s.phaseStartMs));
    default:
      return kNoDeadline;
  }
}

bool takeShutdown(Slot& s, Side side) {
  bool& pend = side == Side::Up ? s.pendShutUp : s.pendShutClient;
  bool& done = side == Side::Up ? s.upWrShut : s.clientWrShut;
  if (!pend) return false;
  pend = false;
  done = true;  // relayUpdate never re-arms a FIN that has been handed out
  return true;
}

void slotForceClose(Slot& s, CloseReason why) { closeSlot(s, why); }

int poolFreeIndex(Slot* const* slots, int n) {
  for (int i = 0; i < n; i++) {
    if (!slots[i]) return i;
  }
  return -1;
}

int poolEvictIndex(Slot* const* slots, int n, uint32_t now, uint32_t minAgeMs) {
  int best = -1;
  uint32_t bestAge = 0;
  for (int i = 0; i < n; i++) {
    const Slot* s = slots[i];
    if (!s || !isHandshake(*s)) continue;
    const uint32_t age = elapsed(now, s->lastActivityMs);  // idle time, not time since accept
    if (age >= minAgeMs && (best < 0 || age > bestAge)) {
      best = i;
      bestAge = age;
    }
  }
  return best;
}

uint32_t poolSelectTimeoutMs(Slot* const* slots, int n, const Timing& t, uint32_t now,
                             uint32_t maxMs) {
  uint32_t ms = maxMs;
  for (int i = 0; i < n; i++) {
    const Slot* s = slots[i];
    if (!s || !isLive(*s)) continue;
    const uint32_t r = slotRemainingMs(*s, t, now);
    if (r < ms) ms = r;
  }
  return ms;
}

void buildWatchList(Slot* const* slots, int nSlots, int listenFd, bool watchListen,
                    int fdSetSize, WatchList& out) {
  out.n = 0;
  out.maxFd = -1;
  out.listenBad = false;
  for (int i = 0; i < kMaxSlots; i++) out.slotBad[i] = false;

  auto add = [&](int fd, bool rd, bool wr) -> bool {
    if (!rd && !wr) return true;
    if (!fdInRange(fd, fdSetSize)) return false;
    out.w[out.n].fd = fd;
    out.w[out.n].rd = rd;
    out.w[out.n].wr = wr;
    out.n++;
    if (fd > out.maxFd) out.maxFd = fd;
    return true;
  };

  if (watchListen && !add(listenFd, true, false)) out.listenBad = true;
  for (int i = 0; i < nSlots && i < kMaxSlots; i++) {
    const Slot* s = slots[i];
    if (!s || !isLive(*s)) continue;
    const Wants w = slotWants(*s);
    const bool a = add(s->clientFd, w.clientRd, w.clientWr);
    const bool b = add(s->upFd, w.upRd, w.upWr);
    if (!a || !b) out.slotBad[i] = true;
  }
}

}  // namespace fry_relay
