#pragma once
// No first manifest check until the boot's asynchronous heap events are over (ESP8266 and host only).
//
// A persistent 504 B block is allocated by an asynchronous event between two loop passes, 7770..7779 ms after the Wi-Fi connect (bench
// captures hmX1 / x2 / x2b / x3a / x3t2: connect logged at t=6568 / 6580 / 6587 / 6622 / 6575 ms, block seen at t=14341 / 14350 / 14358 /
// 14398 / 14354 ms; it tracks the connect, not the boot clock). Normally it lands in the first block of the big free region (offset 4120).
// A check that is running when it is allocated has its BearSSL thunk (6208 B) in that hole, so the 504 B request is placed in whatever
// gap the check's own pcbs left in the tail (offset 26600 in the sw9 capture) and stays there: the largest block drops to 17256 for the rest
// of the boot and every later manifest check is refused (17 of 17 over 40 minutes). A first check that started between about 9.3 s and
// 14.35 s (a check lasts about 5 s from its start) was caught by it; the older 7.8 s check ended before it.
//
// The boot check used to start as soon as the hold for TIME_WAIT pcbs let it: right away when the registration's connection was not yet
// in TIME_WAIT (tw=0 at 8.3 s), a second later after R1's start wait. The first check is therefore not started before 20 s of uptime
// (the event is over on a normal boot) and not before 10 s after tick() first ran. tick() is only reached once Wi-Fi is up, so its first
// call is never earlier than the connect, and a slow DHCP or association moves the check out with the event instead of into it. 10 s is the
// measured 7.78 s plus 2.2 s.
//
// Only the first check waits: the scheduled ones come 6 h later (or after a bounded retry, lib/fry_core/ota_retry.h). The wait never
// blocks: tick() returns and the decision is taken again on the next loop pass. ESP32's heap is not split this way, so the translation
// unit is empty there and the ESP32/C3/S3 images are untouched.
#if !defined(ARDUINO) || defined(ARDUINO_ARCH_ESP8266)

#include <cstdint>

#include "tls_boot_gate.h"

namespace fry {

constexpr uint32_t kOtaFirstCheckMinUptimeMs = 20000;
constexpr uint32_t kOtaFirstCheckAfterFirstTickMs = 10000;

// Milliseconds still to wait before the first check may start; 0 means go. nowMs: millis() now. firstTickMs: millis() at the first call of
// tick() (never 0 there: Wi-Fi comes up well after boot).
inline uint32_t otaFirstCheckWaitMs(uint32_t nowMs, uint32_t firstTickMs) {
  uint32_t earliest = firstTickMs + kOtaFirstCheckAfterFirstTickMs;
  if (earliest < kOtaFirstCheckMinUptimeMs) earliest = kOtaFirstCheckMinUptimeMs;
  return nowMs >= earliest ? 0 : earliest - nowMs;
}

// The first check also comes after the boot registration. The registration is the first TLS session of a boot and starts when the TLS gate
// opens (the connect anchor + kBootAsyncEventDoneMs); on a normal boot it is done 0.8 s later, and the first check follows at 20 s, 4.1 s
// after the gate opened (measured: gate open 15866 ms, registered 16698 ms, first check 20000 ms). With a late connect the boot clock says
// nothing: the gate opens at the late anchor + 9 s, and a check keyed off the clock alone started on the next loop pass after the
// registration and met its connection still closing. The slot is the measured gate-open-to-first-check time, rounded down. A registration
// that takes much longer than the slot (a slow server) can still be met by the check while its connection is closing; the hold for closing
// pcbs (ota_timewait.h) then covers that case, this gate does not.
constexpr uint32_t kOtaFirstCheckRegSlotMs = 4100;

// Milliseconds still to wait, counted from the connect anchor (fry_wifi::connectAnchorMs), before the first check may start; 0 means go.
// No connect seen: the whole window. An anchor still ahead of nowMs (association + lead) adds the distance to it. Wrap-safe, and an anchor
// more than half the counter range behind is long past (the gate never closes again with Wi-Fi up).
inline uint32_t otaFirstCheckAfterConnectWaitMs(uint32_t nowMs, uint32_t anchorMs, bool haveAnchor) {
  const uint32_t window = kBootAsyncEventDoneMs + kOtaFirstCheckRegSlotMs;
  if (!haveAnchor) return window;
  const int32_t ahead = static_cast<int32_t>(anchorMs - nowMs);
  if (ahead > 0 && static_cast<uint32_t>(ahead) <= kAssocToDetectLeadMs) return static_cast<uint32_t>(ahead) + window;
  const uint32_t elapsed = static_cast<uint32_t>(nowMs - anchorMs);
  return elapsed >= window ? 0 : window - elapsed;
}

}  // namespace fry

#endif  // !ARDUINO || ARDUINO_ARCH_ESP8266
