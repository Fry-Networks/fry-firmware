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


uint32_t otaMinContiguousBlock(bool isHttps, bool bearsslSingleBuffer, uint32_t configuredBlock) {
  // Only BearSSL needs a second large CONTIGUOUS block at download time, and only over https.
  // Keying this off the URL scheme alone blocked every ESP32 update: the gate runs after the
  // HTTPS GET, so mbedtls already holds its buffers and the check measures the wrong moment.
  return (isHttps && bearsslSingleBuffer) ? configuredBlock : 0;
}

}  // namespace fry
