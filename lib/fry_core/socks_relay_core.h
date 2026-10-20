#pragma once
// Pure C++ core of the ESP32 SOCKS5 relay (src/esp32/vpn_wireguard.cpp): zero Arduino / lwIP
// includes, so the whole protocol and scheduling logic runs under `pio test -e native`.
//
// The shim in vpn_wireguard.cpp owns every system call (accept / recv / send / connect /
// select / close) and feeds the RESULT of each one back in here together with errno. This module
// never reads errno itself, never touches a socket and never looks at a clock: the caller passes
// `now` (a free-running 32-bit millisecond counter, wrap-safe) into every call that needs one.
//
// Why it exists (0.4.7 behaviours this replaces):
//   * errno was trusted without looking at the return value. recv() returns 0 at EOF without
//     setting errno, so a stale errno (EINPROGRESS = 119 left by the previous non-blocking
//     connect, ECONNRESET from an earlier peer, ...) was read as the state of THIS socket, and
//     Arduino's WiFiClient treats any errno other than EWOULDBLOCK on a failed read as a dead
//     connection and closes it: the client sees a SOCKS handshake that dies without a reply.
//   * the greeting parser's `consumed` was ignored and the buffer reset, dropping a CONNECT
//     request pipelined in the same TCP segment.
//   * one client at a time: a client stalled in the greeting or request stage blocked every
//     other client for up to 5 s per stage.
//   * select()'s return value was ignored, FD_SET was unguarded, and the accept path polled with
//     a fixed 5 ms vTaskDelay.
#include <cstddef>
#include <cstdint>

#include "socks5_parse.h"

namespace fry_relay {

constexpr size_t kBufSize = 1024;  // per-direction copy buffer; the handshake reads into c2u too
constexpr int kMaxSlots = 4;       // client slots served by one select loop (shim may use fewer)
constexpr int kNoFd = -1;
constexpr uint32_t kNoDeadline = 0xFFFFFFFFu;

struct Timing {
  uint32_t greetingMs = 5000;   // accept -> complete greeting
  uint32_t requestMs = 5000;    // greeting done -> complete CONNECT request
  uint32_t connectMs = 3000;    // upstream connect budget (WiFiClient's default was 3000 too)
  uint32_t flushMs = 2000;      // time to push a final reply to a client before closing
  uint32_t idleMs = 30000;      // relaying: no byte moved in either direction
  uint32_t halfCloseMs = 5000;  // relaying: one side hit EOF; no byte may stay idle longer than this
};

enum class Phase : uint8_t {
  Free = 0,
  Greeting,     // waiting for VER|NMETHODS|METHODS
  Request,      // method reply queued, waiting for the CONNECT request
  NeedConnect,  // request parsed; the shim must start the upstream connect now
  Connecting,   // asynchronous upstream connect in flight (shim watches upFd for writability)
  Relay,        // copying both ways
  Flush,        // a final reply is queued; close once it is sent (or flushMs passes)
  Closed,       // terminal: the shim closes both fds and frees the slot
};

enum class Side : uint8_t { Client = 0, Up = 1 };

enum class CloseReason : uint8_t {
  None = 0,
  Done,              // both directions finished
  HandshakeTimeout,  // greeting or request stage ran out of time
  HandshakeEof,      // client closed before sending a complete request
  HandshakeBad,      // greeting or request rejected (reply sent)
  ConnectFail,       // upstream connect failed (reply sent)
  ConnectTimeout,    // upstream connect exceeded connectMs (reply sent)
  Idle,
  HalfCloseTimeout,
  IoError,           // reset / broken pipe / unexpected errno
  Evicted,           // closed to make room for a new client
  FdGuard,           // a descriptor was outside the select() range
};

// ---- errno / return-value classification -------------------------------------------------
enum class IoResult : uint8_t {
  Data = 0,    // ret > 0: that many bytes moved
  Eof,         // recv() returned 0: the peer sent FIN (errno is NOT consulted)
  WouldBlock,  // nothing happened, retry after the next select (EAGAIN, EINTR, EINPROGRESS, ...)
  Closed,      // the connection is gone (ECONNRESET, EPIPE, ENOTCONN, ...)
  Error,       // anything else
};

// `ret` is what recv()/send() returned; `err` is errno captured right after the call. errno is
// only meaningful when ret < 0: a stale value next to ret >= 0 must be ignored.
IoResult classifyRecv(long ret, int err);
IoResult classifySend(long ret, int err);  // ret == 0 for a non-empty send is "no progress"

enum class ConnectStart : uint8_t { Done = 0, InProgress, Failed };
ConnectStart classifyConnectStart(int ret, int err);

enum class SelectAction : uint8_t {
  Ready = 0,     // ret > 0: look at the fd_sets
  Timeout,       // ret == 0: only timers can have changed (fd_sets are not meaningful)
  Interrupted,   // ret < 0 with EINTR: just loop
  Failed,        // ret < 0 otherwise: fd_sets are indeterminate; sweep for a bad fd and back off
};
SelectAction classifySelect(int ret, int err);
uint32_t selectFailBackoffMs(uint32_t consecutiveFailures);  // 10 ms per failure, capped at 100

inline bool fdInRange(int fd, int fdSetSize) { return fd >= 0 && fd < fdSetSize; }

// ---- per-client state machine --------------------------------------------------------------
struct Slot {
  Phase phase = Phase::Free;
  CloseReason reason = CloseReason::None;
  CloseReason flushReason = CloseReason::None;  // what a finished Flush is reported as
  int clientFd = kNoFd;
  int upFd = kNoFd;
  uint32_t acceptedMs = 0;
  uint32_t phaseStartMs = 0;
  uint32_t lastActivityMs = 0;
  uint32_t halfCloseStartMs = 0;
  bool halfClosing = false;
  bool clientRdOpen = true;  // false once the client sent FIN
  bool upRdOpen = true;      // false once the upstream sent FIN
  bool pendShutUp = false;   // shim should shutdown(upFd, SHUT_WR)
  bool pendShutClient = false;
  bool upWrShut = false;      // the FIN toward the upstream has been handed to the shim (one-shot)
  bool clientWrShut = false;  // likewise toward the client
  uint16_t c2uOff = 0, c2uLen = 0;  // client -> upstream pending bytes [off, len)
  uint16_t u2cOff = 0, u2cLen = 0;  // upstream -> client pending bytes (replies included)
  fry::Socks5ConnectRequest req;
  uint8_t c2u[kBufSize];
  uint8_t u2c[kBufSize];
};

void slotInit(Slot& s, int clientFd, uint32_t now);  // -> Phase::Greeting

struct Wants {
  bool clientRd = false, clientWr = false, upRd = false, upWr = false;
};
Wants slotWants(const Slot& s);

// Where the shim should recv() for `side` and how many bytes fit. room == 0 means "do not read
// now" (backpressure, or the phase does not read this side).
uint8_t* recvDest(Slot& s, Side side, size_t& room);
// The bytes the shim should send() TOWARD `to`; len == 0 means nothing pending.
const uint8_t* sendSrc(const Slot& s, Side to, size_t& len);

// Feed back the result of recv()/send() (and the errno captured after it).
void onRecv(Slot& s, Side from, long ret, int err, uint32_t now);
void onSend(Slot& s, Side to, long ret, int err, uint32_t now);

// Phase::NeedConnect -> the shim either got an immediate result (synchronous connect) or started
// an asynchronous one. A failed or timed-out connect queues the failure reply and flushes.
void onConnectStarted(Slot& s, int upFd, uint32_t now);               // -> Connecting
void onConnectResult(Slot& s, bool ok, uint32_t now);                 // ok -> Relay, else Flush
void onTimer(Slot& s, const Timing& t, uint32_t now);                 // enforce the deadlines
uint32_t slotRemainingMs(const Slot& s, const Timing& t, uint32_t now);  // kNoDeadline if none

// One-shot: true once when the shim must shutdown(fd of `side`, SHUT_WR) to forward a FIN.
bool takeShutdown(Slot& s, Side side);

// How the shim carries out that FIN. A shutdown(SHUT_WR) is only safe on a socket that was read to
// EOF: recv() == 0 made lwIP apply SHUT_RD (TF_RXCLOSED), so the SHUT_WR takes its full-close
// branch and detaches the netconn from the pcb. Toward a peer that is still open it would leave the
// netconn on a pcb that becomes TIME_WAIT when the peer's FIN arrives; lwIP frees TIME_WAIT pcbs
// without telling the netconn (ESP-IDF's tcp_alloc does, from 16 pcbs on), so the EOF recv and the
// close() that follow touch freed memory and free the pcb a second time: heap corruption. A FIN
// toward a peer that is still open is therefore carried out by closing the descriptor.
enum class FinAction : uint8_t {
  None = 0,
  HalfClose,  // shutdown(fd, SHUT_WR): this socket's peer has already sent its FIN
  Close,      // close the descriptor (draining it first), then call onSideClosed()
};
FinAction takeFinAction(Slot& s, Side side);  // consumes the one-shot FIN like takeShutdown
// The shim closed the descriptor of `side`: nothing is read from or written to it any more. The
// side counts as finished (the session ends once the data still queued for the peer is out).
void onSideClosed(Slot& s, Side side, uint32_t now);

inline bool slotClosed(const Slot& s) { return s.phase == Phase::Closed; }
void slotForceClose(Slot& s, CloseReason why);  // eviction / fd guard / shim-side failure

// ---- slot pool scheduling (slots[i] == nullptr means free) --------------------------------
int poolFreeIndex(Slot* const* slots, int n);
// Handshake-stage (Greeting/Request) slot that has been idle the longest and for at least
// minAgeMs, else -1. Idle time runs from accept or from the last byte received, so a client whose
// bytes are queued behind a blocked loop iteration is not mistaken for a stalled one. Relaying
// slots are never evicted.
int poolEvictIndex(Slot* const* slots, int n, uint32_t now, uint32_t minAgeMs);
// select() timeout: the nearest slot deadline, capped at maxMs. With no live slot this is maxMs:
// the loop blocks on the listening fd instead of polling.
uint32_t poolSelectTimeoutMs(Slot* const* slots, int n, const Timing& t, uint32_t now,
                             uint32_t maxMs);

struct Watch {
  int fd;
  bool rd;
  bool wr;
};
struct WatchList {
  Watch w[1 + 2 * kMaxSlots];
  int n = 0;
  int maxFd = -1;
  bool listenBad = false;
  bool slotBad[kMaxSlots] = {};
};
// Every fd the next select() should watch. A descriptor that is wanted but outside
// [0, fdSetSize) is never added (FD_SET on it is undefined or silently ignored): its slot is
// flagged in slotBad (the shim closes it) and the listening fd in listenBad.
void buildWatchList(Slot* const* slots, int nSlots, int listenFd, bool watchListen,
                    int fdSetSize, WatchList& out);

}  // namespace fry_relay
