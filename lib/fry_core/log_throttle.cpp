#include "log_throttle.h"

namespace fry {

bool shouldLogState(LogThrottle& throttle, int32_t state, uint32_t nowMs, uint32_t minIntervalMs) {
  const bool due = minIntervalMs != 0 &&
                   static_cast<uint32_t>(nowMs - throttle.lastMs) >= minIntervalMs;
  if (!throttle.everLogged || state != throttle.lastState || due) {
    throttle.everLogged = true;
    throttle.lastState = state;
    throttle.lastMs = nowMs;
    return true;
  }
  return false;
}

}  // namespace fry
