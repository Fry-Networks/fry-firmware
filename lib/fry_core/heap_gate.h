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

// How much CONTIGUOUS heap an OTA download must find before streaming an image in.
//
// The large contiguous requirement is a property of ESP8266's BearSSL, not of TLS in general:
// that stack allocates a single 16384-byte rx buffer as one block (see HEAP_GATE_OTA_BLOCK in
// include/config.h for the field evidence). ESP32's mbedtls has already allocated its working
// buffers by the time the OTA gate runs, because the gate sits AFTER the HTTPS GET has returned
// headers -- so demanding another 36 KB contiguous there measures the wrong moment and refuses
// every ESP32 update. Measured on a T-Beam: 110,580 bytes contiguous when idle, gate still failed
// mid-session, so no ESP32 board could ever self-update.
//
// Returns 0 (no contiguous requirement) unless this really is the BearSSL single-buffer path.
uint32_t otaMinContiguousBlock(bool isHttps, bool bearsslSingleBuffer, uint32_t configuredBlock);

// Largest allocatable contiguous heap block, in bytes:
//   ESP8266      -> ESP.getMaxFreeBlockSize()
//   ESP32 family -> ESP.getMaxAllocHeap()
//   native/host  -> UINT32_MAX (never gates a host-side build or test)
uint32_t queryMaxFreeBlock();

}  // namespace fry
