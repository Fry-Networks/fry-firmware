#pragma once
// Registration housekeeping decisions for the ESP8266 (pure C++, so the native suite pins them).
//
// 1. Connection release. The registration (and the stale-token heal) sends "Connection: close" (HTTPClient::setReuse(false)),
//    so the server closes first and keeps the TIME_WAIT. The board then waits a short, bounded time for that FIN before it
//    closes its own side: it goes CLOSE_WAIT -> LAST_ACK -> gone, instead of a graceful active close that leaves a closing pcb
//    behind for minutes (which the first OTA check, holdForTimeWait in ota_client.cpp, then waits out).
// 2. Clock deferral. The TLS layer refuses a connection while SNTP has not set the clock. A registration that hits that
//    refusal is a deferral, not a failed attempt: no failure count, no backoff. It is re-checked every kRegClockRecheckMs
//    and only for kRegClockDeferMaxMs after the first refusal; past that it takes the normal failure path.
#include <cstdint>

namespace fry {

constexpr uint32_t kRegPeerCloseWaitMs = 1500;  // upper bound on waiting for the server's FIN
constexpr uint32_t kRegPeerClosePollMs = 10;    // poll step while waiting

// Keep waiting while the connection is still open and the bound has not passed.
inline bool regPeerCloseKeepWaiting(bool stillConnected, uint32_t waitedMs) {
  return stillConnected && waitedMs < kRegPeerCloseWaitMs;
}

// After the request is over the board closes its side (from CLOSE_WAIT, so only LAST_ACK is left). The pcb it leaves is counted by
// countClosingPcbs() (lib/fry_core/ota_timewait.h), the same count the first OTA check's hold uses; wait for it to reach zero so that
// check is not held by the registration's own closing connection. Bounded: a pcb that never clears costs at most kRegPcbSettleMaxMs.
constexpr uint32_t kRegPcbSettleMaxMs = 500;
constexpr uint32_t kRegPcbSettlePollMs = 10;

inline bool regPcbSettleKeepWaiting(uint32_t closingPcbs, uint32_t waitedMs) {
  return closingPcbs != 0 && waitedMs < kRegPcbSettleMaxMs;
}

constexpr uint32_t kRegClockRecheckMs = 2000;   // next registration pass while the clock is unset
constexpr uint32_t kRegClockDeferMaxMs = 60000; // total deferral allowed

enum class RegClockAction : uint8_t { Proceed, Defer };

// clockSane: the clock is set. deferring: a deferral is already running. sinceFirstDeferMs: time since the first one.
inline RegClockAction regClockAction(bool clockSane, bool deferring, uint32_t sinceFirstDeferMs) {
  if (clockSane) return RegClockAction::Proceed;
  if (!deferring) return RegClockAction::Defer;
  return sinceFirstDeferMs < kRegClockDeferMaxMs ? RegClockAction::Defer : RegClockAction::Proceed;
}

}  // namespace fry
