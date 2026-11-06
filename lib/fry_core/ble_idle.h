#pragma once
// When the BLE provisioning stack may be shut down. Pure C++ so `pio test -e native` pins the rule.
//
// Once the board has joined Wi-Fi and registered (provisioning state Connected) and advertising has
// stopped, nothing can discover it over BLE any more, yet the NimBLE host and controller keep their
// heap for the rest of the uptime. That heap is what the TLS sessions and the WireGuard tunnel need.
// The stack is released only after the board has stayed Connected with no central attached for a
// whole grace period: a link is never dropped from this side, and the app's own post-Connected
// disconnect has long finished by then.
#include <cstdint>

namespace fry {

// How long the board must stay Connected with nobody attached before the BLE stack is released.
constexpr uint32_t kBleIdleGraceMs = 30000;

class BleIdleTimer {
 public:
  // Call once per loop. Returns true exactly when the stack should be shut down now.
  // `up`: the stack is running. `connected`: provisioning state is Connected.
  // `centrals`: attached BLE centrals. Wrap-safe on a 32-bit millisecond counter.
  bool poll(bool up, bool connected, int centrals, uint32_t nowMs, uint32_t graceMs = kBleIdleGraceMs);

 private:
  bool idle_ = false;
  uint32_t sinceMs_ = 0;
};

}  // namespace fry
