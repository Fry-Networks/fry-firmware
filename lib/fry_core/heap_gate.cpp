#include "heap_gate.h"

#if defined(ARDUINO)
#include <Arduino.h>
#endif

namespace fry {

bool heapGatePass(uint32_t freeTotal, uint32_t maxBlock, uint32_t minFreeTotal, uint32_t minBlock) {
  return freeTotal >= minFreeTotal && maxBlock >= minBlock;
}

uint32_t queryMaxFreeBlock() {
#if defined(ARDUINO_ARCH_ESP8266)
  return ESP.getMaxFreeBlockSize();
#elif defined(ARDUINO)
  return ESP.getMaxAllocHeap();
#else
  return UINT32_MAX;
#endif
}

}  // namespace fry
