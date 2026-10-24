#include "ntp_kick.h"

namespace fry {

bool ntpRestartDue(bool started, uint32_t nowMs, uint32_t startedMs, uint32_t intervalMs) {
  if (!started) return true;
  return static_cast<uint32_t>(nowMs - startedMs) >= intervalMs;
}

}  // namespace fry
