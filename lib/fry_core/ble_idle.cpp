#include "ble_idle.h"

namespace fry {

bool BleIdleTimer::poll(bool up, bool connected, int centrals, uint32_t nowMs, uint32_t graceMs) {
  if (!up || !connected || centrals > 0) {
    idle_ = false;  // any activity restarts the grace period
    return false;
  }
  if (!idle_) {
    idle_ = true;
    sinceMs_ = nowMs;
    return false;
  }
  return static_cast<uint32_t>(nowMs - sinceMs_) >= graceMs;
}

}  // namespace fry
