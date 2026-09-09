#pragma once
// Arduino-side wrapper around lib/fry_core/heap_gate.h's pure dual gate: polls
// ESP.getFreeHeap() + fry::queryMaxFreeBlock() with a short bounded retry so a transient
// fragmentation dip (e.g. a TCP buffer momentarily pinning a chunk of heap) degrades into a
// brief stall-and-retry instead of an immediate, unrecoverable OTA/TLS failure. Shared by both
// gate sites (src/core/ota_client.cpp and src/esp8266/http_tls.cpp) since it is cross-platform —
// ESP.getFreeHeap() and fry::queryMaxFreeBlock() both resolve correctly on ESP8266 and ESP32.
#include <cstdint>

namespace fry {

// Polls up to `attempts` times (default 30 x 100 ms = up to 3 s), returning true as soon as the
// dual gate (heapGatePass) clears. Returns false if it never does within the budget.
bool waitForHeapGate(uint32_t minFreeTotal, uint32_t minBlock, int attempts = 30,
                      uint32_t delayMs = 100);

}  // namespace fry
