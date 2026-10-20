// lib/fry_core/socks_relay_core.*: how a forwarded FIN is carried out (FinAction).
//
// lwIP cannot safely half-close a socket whose peer is still open. shutdown(SHUT_WR) leaves the
// netconn attached to a pcb that becomes TIME_WAIT once the peer's FIN arrives; lwIP frees
// TIME_WAIT pcbs without telling the netconn when it runs out of pcbs (the ESP-IDF build does so
// from tcp_alloc as soon as 16 pcbs exist), and the close() that follows frees the pcb a second
// time. On an ESP32-C3 that was "CORRUPT HEAP: Bad head ... multi_heap_free" called from
// tcp_close_shutdown on the tcpip thread, a few seconds into a relay load test.
//
// So the core only allows a half-close toward a peer that has already sent its own FIN. Such a
// socket was read to EOF, which makes lwIP apply SHUT_RD (TF_RXCLOSED), so the SHUT_WR that follows
// takes the full-close branch and detaches the netconn from the pcb (IDF 4.4.7: api_lib.c:776,
// tcp.c:526, api_msg.c:1011-1012, :1127). Every other FIN becomes a close of that descriptor. The
// old code was wrong already on the EOF read, which touches the pcb as well (api_msg.c:1007).
// The first group pins that decision and the session bookkeeping around it; the second drives whole
// sessions through a model of the shim's socket handling and checks the invariants the firmware
// depends on, with a control run showing that the model does flag the old behaviour.
#include <unity.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <deque>
#include <vector>

#include "socks_relay_core.h"

using namespace fry_relay;

namespace {

const Timing kT;

const uint8_t kGreet[3] = {0x05, 0x01, 0x00};
const uint8_t kConnV4[10] = {0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50};  // 1.2.3.4:80

// recv() into the slot's destination and report the byte count, as the shim does.
void feed(Slot& s, Side from, const uint8_t* d, size_t n, uint32_t now) {
  size_t room = 0;
  uint8_t* dst = recvDest(s, from, room);
  TEST_ASSERT_TRUE_MESSAGE(room >= n, "recvDest offered too little room");
  memcpy(dst, d, n);
  onRecv(s, from, static_cast<long>(n), 0, now);
}

// Send everything pending toward `to` and report it.
size_t drain(Slot& s, Side to, uint32_t now) {
  size_t len = 0;
  sendSrc(s, to, len);
  if (len == 0) return 0;
  onSend(s, to, static_cast<long>(len), 0, now);
  return len;
}

void toRelay(Slot& s, int cfd, int ufd, uint32_t now) {
  slotInit(s, cfd, now);
  feed(s, Side::Client, kGreet, sizeof(kGreet), now);
  feed(s, Side::Client, kConnV4, sizeof(kConnV4), now);
  onConnectStarted(s, ufd, now);
  onConnectResult(s, true, now);
  drain(s, Side::Client, now);
  TEST_ASSERT_EQUAL((int)Phase::Relay, (int)s.phase);
}

// ---- the decision ------------------------------------------------------------------------

void test_fin_toward_an_open_peer_is_a_close() {
  Slot s;
  toRelay(s, 50, 51, 0);
  onRecv(s, Side::Client, 0, 0, 10);  // the client finished; the upstream is still open
  TEST_ASSERT_EQUAL((int)FinAction::Close, (int)takeFinAction(s, Side::Up));
  TEST_ASSERT_EQUAL((int)FinAction::None, (int)takeFinAction(s, Side::Up));  // one-shot
  TEST_ASSERT_EQUAL((int)FinAction::None, (int)takeFinAction(s, Side::Client));
}

void test_fin_toward_a_client_that_is_still_open_is_a_close_too() {
  Slot s;
  toRelay(s, 50, 51, 0);
  onRecv(s, Side::Up, 0, 0, 10);  // the upstream finished; the client is still open
  TEST_ASSERT_EQUAL((int)FinAction::Close, (int)takeFinAction(s, Side::Client));
  TEST_ASSERT_EQUAL((int)FinAction::None, (int)takeFinAction(s, Side::Client));
  TEST_ASSERT_EQUAL((int)FinAction::None, (int)takeFinAction(s, Side::Up));
}

void test_fin_toward_a_peer_that_already_sent_its_fin_is_a_half_close() {
  Slot s;
  toRelay(s, 50, 51, 0);
  onRecv(s, Side::Client, 0, 0, 10);
  onRecv(s, Side::Up, 0, 0, 11);  // both peers sent FIN before the shim got to either
  TEST_ASSERT_EQUAL((int)FinAction::HalfClose, (int)takeFinAction(s, Side::Up));
  TEST_ASSERT_EQUAL((int)FinAction::HalfClose, (int)takeFinAction(s, Side::Client));
  TEST_ASSERT_TRUE(slotClosed(s));
  TEST_ASSERT_EQUAL((int)CloseReason::Done, (int)s.reason);
}

void test_the_fin_waits_for_the_data_headed_to_that_peer() {
  Slot s;
  toRelay(s, 50, 51, 0);
  const uint8_t resp[3] = {'a', 'b', 'c'};
  feed(s, Side::Up, resp, 3, 10);
  onRecv(s, Side::Up, 0, 0, 11);  // upstream: reply, then FIN; the client has not been sent the reply yet
  TEST_ASSERT_EQUAL((int)FinAction::None, (int)takeFinAction(s, Side::Client));
  TEST_ASSERT_EQUAL(3, (int)drain(s, Side::Client, 12));
  TEST_ASSERT_EQUAL((int)FinAction::Close, (int)takeFinAction(s, Side::Client));  // only now
}

// ---- the session after a close -----------------------------------------------------------

void test_upstream_first_closing_the_client_ends_the_session() {
  Slot s;
  toRelay(s, 50, 51, 0);
  onRecv(s, Side::Up, 0, 0, 10);
  TEST_ASSERT_EQUAL((int)FinAction::Close, (int)takeFinAction(s, Side::Client));
  TEST_ASSERT_EQUAL((int)Phase::Relay, (int)s.phase);  // not before the shim reports the close
  onSideClosed(s, Side::Client, 11);
  TEST_ASSERT_TRUE(slotClosed(s));
  TEST_ASSERT_EQUAL((int)CloseReason::Done, (int)s.reason);
  // the FIN toward the upstream, whose peer had already finished, is a plain half-close
  TEST_ASSERT_EQUAL((int)FinAction::HalfClose, (int)takeFinAction(s, Side::Up));
}

void test_client_first_closing_the_upstream_ends_the_session() {
  Slot s;
  toRelay(s, 50, 51, 0);
  onRecv(s, Side::Client, 0, 0, 10);
  TEST_ASSERT_EQUAL((int)FinAction::Close, (int)takeFinAction(s, Side::Up));
  onSideClosed(s, Side::Up, 11);
  TEST_ASSERT_TRUE(slotClosed(s));
  TEST_ASSERT_EQUAL((int)CloseReason::Done, (int)s.reason);
  TEST_ASSERT_EQUAL((int)FinAction::HalfClose, (int)takeFinAction(s, Side::Client));
}

void test_a_reply_already_received_is_still_delivered_after_the_upstream_is_closed() {
  Slot s;
  toRelay(s, 50, 51, 0);
  const uint8_t resp[2] = {'O', 'K'};
  feed(s, Side::Up, resp, 2, 9);
  onRecv(s, Side::Client, 0, 0, 10);  // the client finishes while the reply sits in the buffer
  TEST_ASSERT_EQUAL((int)FinAction::Close, (int)takeFinAction(s, Side::Up));
  onSideClosed(s, Side::Up, 11);
  TEST_ASSERT_EQUAL((int)Phase::Relay, (int)s.phase);  // the reply is still queued for the client
  TEST_ASSERT_TRUE(slotWants(s).clientWr);
  TEST_ASSERT_EQUAL(2, (int)drain(s, Side::Client, 12));
  TEST_ASSERT_TRUE(slotClosed(s));
  TEST_ASSERT_EQUAL((int)FinAction::HalfClose, (int)takeFinAction(s, Side::Client));
}

void test_data_the_client_sent_before_the_upstream_finished_is_still_forwarded() {
  Slot s;
  toRelay(s, 50, 51, 0);
  const uint8_t req[3] = {'G', 'E', 'T'};
  feed(s, Side::Client, req, 3, 9);
  onRecv(s, Side::Up, 0, 0, 10);
  TEST_ASSERT_EQUAL((int)FinAction::Close, (int)takeFinAction(s, Side::Client));
  onSideClosed(s, Side::Client, 11);
  TEST_ASSERT_EQUAL((int)Phase::Relay, (int)s.phase);  // the request is still queued for the upstream
  TEST_ASSERT_TRUE(slotWants(s).upWr);
  TEST_ASSERT_EQUAL(3, (int)drain(s, Side::Up, 12));
  TEST_ASSERT_TRUE(slotClosed(s));
}

void test_a_closed_side_is_never_wanted_again() {
  Slot s;
  toRelay(s, 50, 51, 0);
  const uint8_t resp[2] = {'O', 'K'};
  feed(s, Side::Up, resp, 2, 9);
  onRecv(s, Side::Client, 0, 0, 10);
  TEST_ASSERT_EQUAL((int)FinAction::Close, (int)takeFinAction(s, Side::Up));
  onSideClosed(s, Side::Up, 11);
  s.upFd = kNoFd;  // what the shim does after closing it
  Wants w = slotWants(s);
  TEST_ASSERT_FALSE(w.upRd);
  TEST_ASSERT_FALSE(w.upWr);
  size_t room = 99, len = 99;
  recvDest(s, Side::Up, room);
  sendSrc(s, Side::Up, len);
  TEST_ASSERT_EQUAL(0, (int)room);
  TEST_ASSERT_EQUAL(0, (int)len);
  Slot* pool[kMaxSlots] = {&s, nullptr, nullptr, nullptr};
  WatchList wl;
  buildWatchList(pool, kMaxSlots, kNoFd, false, 64, wl);
  TEST_ASSERT_FALSE(wl.slotBad[0]);  // fd -1 is not mistaken for a descriptor outside select()'s range
}

void test_nothing_happens_on_a_slot_that_is_not_relaying() {
  Slot s;
  slotInit(s, 50, 0);
  TEST_ASSERT_EQUAL((int)FinAction::None, (int)takeFinAction(s, Side::Up));
  onSideClosed(s, Side::Client, 5);  // not in the Relay phase: bookkeeping only, no transition
  TEST_ASSERT_EQUAL((int)Phase::Greeting, (int)s.phase);
}

// ---- whole sessions against a model of the shim's socket handling --------------------------
//
// The model mirrors what src/esp32/vpn_wireguard.cpp does with the core (recv/send into the slot
// buffers, then forward the armed FINs) on two fake sockets. What it checks is what the firmware
// depends on: a FIN is never sent as a half-close toward a peer that is still open, no descriptor
// is touched after it was closed, every session ends, and the data of the direction that finished
// first arrives complete and in order.

struct Rng {
  uint32_t x;
  explicit Rng(uint32_t seed) : x(seed * 2654435761u + 12345u) {}
  uint32_t next() {
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return x;
  }
  uint32_t below(uint32_t n) { return n ? next() % n : 0; }
};

struct Event {
  int step;
  size_t bytes;  // 0 = FIN
};

struct Peer {
  uint8_t tag = 0;
  std::deque<uint8_t> rx;         // sent by the peer, not yet read by the relay
  std::vector<uint8_t> sentAll;   // everything the peer sent
  std::vector<uint8_t> got;       // what the relay delivered to the peer
  std::vector<Event> script;
  bool finDue = false;            // the peer's FIN reaches the relay once rx is read
  bool closed = false;            // the relay close()d the descriptor
  int eofSeenAt = -1;
};

struct Tally {
  int halfCloseOfOpenPeer = 0;  // shutdown(SHUT_WR) while the peer had not sent FIN
  int useAfterClose = 0;        // recv/send/shutdown/close on a closed descriptor
  int sessions = 0;
  int unfinished = 0;
  int badStream = 0;
  int badWatch = 0;
};

void schedule(Peer& p, Rng& r, size_t total, int finAt) {
  size_t left = total;
  int chunks = 1 + static_cast<int>(r.below(3));
  for (int i = 0; i < chunks && left > 0; i++) {
    size_t n = (i == chunks - 1) ? left : 1 + r.below(static_cast<uint32_t>(left));
    p.script.push_back({1 + static_cast<int>(r.below(static_cast<uint32_t>(finAt))), n});
    left -= n;
  }
  p.script.push_back({finAt, 0});
}

void applyEvents(Peer& p, int step) {
  for (const Event& e : p.script) {
    if (e.step != step || p.closed) continue;
    if (e.bytes == 0) {
      p.finDue = true;
    } else {
      for (size_t i = 0; i < e.bytes; i++) {
        const uint8_t b = static_cast<uint8_t>(p.tag * 37 + p.sentAll.size() * 7);
        p.sentAll.push_back(b);
        p.rx.push_back(b);
      }
    }
  }
}

void relayRecv(Slot& s, Peer& p, Side from, int step, Rng& r, Tally& t) {
  size_t room = 0;
  uint8_t* dst = recvDest(s, from, room);
  if (room == 0) return;
  if (p.closed) {
    t.useAfterClose++;
    return;
  }
  if (!p.rx.empty()) {
    const size_t n = std::min<size_t>(std::min(room, p.rx.size()), 1 + r.below(static_cast<uint32_t>(room)));
    for (size_t i = 0; i < n; i++) {
      dst[i] = p.rx.front();
      p.rx.pop_front();
    }
    onRecv(s, from, static_cast<long>(n), 0, static_cast<uint32_t>(step));
  } else if (p.finDue) {
    if (p.eofSeenAt < 0) p.eofSeenAt = step;
    onRecv(s, from, 0, ECONNRESET /* stale errno: must be ignored */, static_cast<uint32_t>(step));
  } else {
    onRecv(s, from, -1, EAGAIN, static_cast<uint32_t>(step));
  }
}

void relaySend(Slot& s, Peer& p, Side to, int step, Rng& r, Tally& t) {
  size_t len = 0;
  const uint8_t* src = sendSrc(s, to, len);
  if (len == 0) return;
  if (p.closed) {
    t.useAfterClose++;
    return;
  }
  if (r.below(5) == 0) {
    onSend(s, to, -1, EAGAIN, static_cast<uint32_t>(step));
    return;
  }
  const size_t n = 1 + r.below(static_cast<uint32_t>(len));
  p.got.insert(p.got.end(), src, src + n);
  onSend(s, to, static_cast<long>(n), 0, static_cast<uint32_t>(step));
}

// `legacy` is what the shim did before FinAction: shutdown(SHUT_WR) for every armed FIN.
void relayFin(Slot& s, Peer& p, Side side, int step, bool legacy, Tally& t) {
  int& fd = side == Side::Client ? s.clientFd : s.upFd;
  const uint32_t now = static_cast<uint32_t>(step);
  FinAction a;
  if (legacy) {
    a = takeShutdown(s, side) ? FinAction::HalfClose : FinAction::None;
  } else {
    a = takeFinAction(s, side);
  }
  switch (a) {
    case FinAction::None:
      break;
    case FinAction::HalfClose:
      if (fd >= 0) {
        if (p.closed) t.useAfterClose++;
        else if (!p.finDue) t.halfCloseOfOpenPeer++;
      }
      break;
    case FinAction::Close:
      if (fd >= 0) {
        p.rx.clear();  // the shim reads and discards what is queued, then close()s
        p.closed = true;
        fd = kNoFd;
      }
      onSideClosed(s, side, now);
      break;
  }
}

bool isPrefix(const std::vector<uint8_t>& a, const std::vector<uint8_t>& full) {
  return a.size() <= full.size() && std::equal(a.begin(), a.end(), full.begin());
}

void runSession(uint32_t seed, bool legacy, Tally& t) {
  Rng r(seed);
  Peer cl, up;
  cl.tag = 1;
  up.tag = 2;
  const int clFin = 3 + static_cast<int>(r.below(80));
  const int upFin = 3 + static_cast<int>(r.below(80));
  schedule(cl, r, r.below(3000), clFin);
  schedule(up, r, r.below(3000), upFin);

  Slot s;
  toRelay(s, 50, 51, 0);
  bool ended = false;
  for (int step = 1; step <= 6000 && !ended; step++) {
    applyEvents(cl, step);
    applyEvents(up, step);
    onTimer(s, kT, static_cast<uint32_t>(step));
    if (!slotClosed(s)) {
      relayRecv(s, cl, Side::Client, step, r, t);
      relaySend(s, up, Side::Up, step, r, t);
      relayRecv(s, up, Side::Up, step, r, t);
      relaySend(s, cl, Side::Client, step, r, t);
      relayFin(s, up, Side::Up, step, legacy, t);
      relayFin(s, cl, Side::Client, step, legacy, t);
      Slot* pool[kMaxSlots] = {&s, nullptr, nullptr, nullptr};
      WatchList wl;
      buildWatchList(pool, kMaxSlots, kNoFd, false, 64, wl);
      if (wl.slotBad[0]) t.badWatch++;
    }
    ended = slotClosed(s);
  }
  t.sessions++;
  if (!ended) {
    t.unfinished++;
    return;
  }
  if (!isPrefix(up.got, cl.sentAll) || !isPrefix(cl.got, up.sentAll)) t.badStream++;
  const bool clientFirst = cl.eofSeenAt >= 0 && (up.eofSeenAt < 0 || cl.eofSeenAt <= up.eofSeenAt);
  const bool upFirst = up.eofSeenAt >= 0 && (cl.eofSeenAt < 0 || up.eofSeenAt < cl.eofSeenAt);
  if (clientFirst && up.got != cl.sentAll) t.badStream++;  // everything the client sent reached the upstream
  if (upFirst && cl.got != up.sentAll) t.badStream++;      // everything the upstream sent reached the client
}

Tally runMany(bool legacy, int n) {
  Tally t;
  for (int i = 0; i < n; i++) runSession(1000u + static_cast<uint32_t>(i), legacy, t);
  return t;
}

void test_sessions_never_half_close_an_open_peer() {
  const Tally t = runMany(false, 3000);
  TEST_ASSERT_EQUAL(3000, t.sessions);
  TEST_ASSERT_EQUAL_MESSAGE(0, t.halfCloseOfOpenPeer, "shutdown(SHUT_WR) toward a peer that had not sent FIN");
  TEST_ASSERT_EQUAL_MESSAGE(0, t.useAfterClose, "a closed descriptor was used again");
  TEST_ASSERT_EQUAL_MESSAGE(0, t.badWatch, "a closed side is still watched");
  TEST_ASSERT_EQUAL_MESSAGE(0, t.unfinished, "a session never ended");
  TEST_ASSERT_EQUAL_MESSAGE(0, t.badStream, "data lost, duplicated or reordered");
}

void test_control_the_model_flags_the_old_half_close_behaviour() {
  const Tally t = runMany(true, 3000);
  TEST_ASSERT_EQUAL(3000, t.sessions);
  // Most sessions have one peer finishing while the other one is still open.
  TEST_ASSERT_TRUE_MESSAGE(t.halfCloseOfOpenPeer > 1000, "the model does not see the old behaviour");
  TEST_ASSERT_EQUAL(0, t.useAfterClose);
  TEST_ASSERT_EQUAL(0, t.unfinished);
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_fin_toward_an_open_peer_is_a_close);
  RUN_TEST(test_fin_toward_a_client_that_is_still_open_is_a_close_too);
  RUN_TEST(test_fin_toward_a_peer_that_already_sent_its_fin_is_a_half_close);
  RUN_TEST(test_the_fin_waits_for_the_data_headed_to_that_peer);
  RUN_TEST(test_upstream_first_closing_the_client_ends_the_session);
  RUN_TEST(test_client_first_closing_the_upstream_ends_the_session);
  RUN_TEST(test_a_reply_already_received_is_still_delivered_after_the_upstream_is_closed);
  RUN_TEST(test_data_the_client_sent_before_the_upstream_finished_is_still_forwarded);
  RUN_TEST(test_a_closed_side_is_never_wanted_again);
  RUN_TEST(test_nothing_happens_on_a_slot_that_is_not_relaying);
  RUN_TEST(test_sessions_never_half_close_an_open_peer);
  RUN_TEST(test_control_the_model_flags_the_old_half_close_behaviour);
  return UNITY_END();
}
