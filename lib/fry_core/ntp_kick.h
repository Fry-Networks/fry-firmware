#pragma once
// When the SNTP sync may be (re)started. Pure C++ so `pio test -e native` pins the rule.
//
// Why it matters: configTime() is not a status check, it RESTARTS the SNTP request. The WireGuard
// client asks for the clock on every retry (a few seconds apart while NTP is out), and a caller
// that re-issued configTime() each time would restart the sync before it could ever complete - the
// board would stay clockless and, with validated TLS refusing a clockless session, never register.
// So: start it once, and only re-issue the request if the previous start is genuinely old (the
// server may have been unreachable then); the bounded retry itself is unaffected.
#include <cstdint>

namespace fry {

// How long one configTime() is left alone before it may be issued again.
constexpr uint32_t kNtpRestartIntervalMs = 600000;  // 10 minutes

// True when SNTP should be started now: never started yet, or the last start is at least
// intervalMs old. Wrap-safe on a 32-bit millisecond counter.
bool ntpRestartDue(bool started, uint32_t nowMs, uint32_t startedMs,
                   uint32_t intervalMs = kNtpRestartIntervalMs);

}  // namespace fry
