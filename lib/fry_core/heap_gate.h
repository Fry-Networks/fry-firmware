#pragma once
// Dual heap gate: total free heap AND largest contiguous block. See include/config.h /
// HEAP_GATE_OTA_BLOCK for why total-free alone is not sufficient (a fragmented heap can pass a
// total-free check and still fail to satisfy a single large allocation like the ESP8266
// non-MFLN BearSSL 16384-byte rx buffer).
//
// The decision itself is pure (no I/O, no delay) so it is natively unit-testable under
// `pio test -e native`; the platform-specific "largest free block" query lives alongside it as
// a thin wrapper so callers only ever import one header.
#include <cstdint>

namespace fry {

// True only when BOTH freeTotal >= minFreeTotal AND maxBlock >= minBlock.
bool heapGatePass(uint32_t freeTotal, uint32_t maxBlock, uint32_t minFreeTotal, uint32_t minBlock);

// Largest allocatable contiguous heap block, in bytes:
//   ESP8266      -> ESP.getMaxFreeBlockSize()
//   ESP32 family -> ESP.getMaxAllocHeap()
//   native/host  -> UINT32_MAX (never gates a host-side build or test)
uint32_t queryMaxFreeBlock();

}  // namespace fry
