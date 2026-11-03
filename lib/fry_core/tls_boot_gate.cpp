#include "tls_boot_gate.h"

#if !defined(ARDUINO) || defined(ARDUINO_ARCH_ESP8266)

namespace fry {

uint32_t tlsBootWaitMs(uint32_t nowMs, uint32_t firstCallMs) {
  const uint32_t elapsed = static_cast<uint32_t>(nowMs - firstCallMs);
  return elapsed >= kBootAsyncEventDoneMs ? 0 : kBootAsyncEventDoneMs - elapsed;
}

}  // namespace fry

#endif  // !ARDUINO || ARDUINO_ARCH_ESP8266
