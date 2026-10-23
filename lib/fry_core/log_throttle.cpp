#include "log_throttle.h"

namespace fry {

bool shouldLogState(LogThrottle& throttle, int32_t state, uint32_t nowMs, uint32_t minIntervalMs) {
  if (!throttle.everLogged || state != throttle.lastState ||
      static_cast<uint32_t>(nowMs - throttle.lastMs) >= minIntervalMs) {
    throttle.everLogged = true;
    throttle.lastState = state;
    throttle.lastMs = nowMs;
    return true;
  }
  return false;
}

}  // namespace fry
