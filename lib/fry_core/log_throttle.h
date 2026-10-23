#pragma once
// State-change log throttle: one line when a state CHANGES, and otherwise at most one line per
// interval. Exists because a polled subsystem that logs its current state on every pass turns a
// serial console into a flood: measured on capture e32-a3b-224212, "wg: no VPN config - skipping"
// went out every 5 s for as long as the board was unprovisioned, and the NVS open behind it wrote
// 4326 library error lines in 54 s.
//
// Pure C++ (no Arduino, no clock of its own): the caller passes millis(), so `pio test -e native`
// pins the rule instead of only a comment. Wrap-safe on a 32-bit millisecond counter.
#include <cstdint>

namespace fry {

// Every 10 minutes, the maximum steady-state rate of a repeated state line.
constexpr uint32_t kLogStateMinIntervalMs = 600000;

struct LogThrottle {
  bool everLogged = false;
  int32_t lastState = 0;
  uint32_t lastMs = 0;
};

// True when `state` has never been logged, differs from the last logged state (change is logged
// immediately, whatever the interval), or at least minIntervalMs have elapsed since the last
// logged line. Records the line when it returns true, so the caller logs unconditionally on true.
bool shouldLogState(LogThrottle& throttle, int32_t state, uint32_t nowMs, uint32_t minIntervalMs);

}  // namespace fry
