#include "heap_gate_wait.h"

#include <Arduino.h>

#include "heap_gate.h"

namespace fry {

bool waitForHeapGate(uint32_t minFreeTotal, uint32_t minBlock, int attempts, uint32_t delayMs) {
  for (int attempt = 1; attempt <= attempts; ++attempt) {
    uint32_t freeTotal = ESP.getFreeHeap();
    uint32_t maxBlock = queryMaxFreeBlock();
    if (heapGatePass(freeTotal, maxBlock, minFreeTotal, minBlock)) return true;
    if (attempt < attempts) delay(delayMs);
  }
  return false;
}

}  // namespace fry
