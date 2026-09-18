#pragma once
#include <stddef.h>
#include <stdint.h>

namespace fry {

// One telemetry observation. Plain values only — no Arduino types — so the body builder
// below links into `pio test -e native` alongside the rest of lib/fry_core.
struct TelemetrySample {
  uint32_t uptimeS;         // millis()/1000 at capture
  uint32_t heapFree;        // ESP.getFreeHeap()
  uint32_t heapMaxBlock;    // fry::queryMaxFreeBlock() — the largest CONTIGUOUS block, which is
                            // what the OTA/TLS gate actually decides on. Total free heap alone
                            // has already produced a board reporting plenty of room while
                            // refusing an update for want of a 36 KB block.
  uint32_t stackHighWater;  // bytes of stack still unused at the deepest point, 0 if unavailable
  int32_t rssi;             // dBm, 0 when not associated
  const char* chip;         // FRY_CHIP
  const char* firmware;     // FRY_FIRMWARE_VERSION
};

// Serialises the /measurements request body:
//
//   {"miner_code":"..","install_id":"..","measurement_type":"telemetry",
//    "timestamp":"..","value":{"uptime_s":..,"heap_free":..,"heap_max_block":..,
//    "stack_high_water":..,"rssi":..,"chip":"..","firmware":".."}}
//
// Returns the number of characters written (excluding the NUL), or 0 on failure — either the
// buffer was too small or an input carried a character that would need JSON escaping. Every
// field here is a server-side enum, a version string or a hex identifier, none of which may
// legitimately contain a quote or backslash, so rejecting those is preferable to emitting a
// body that silently truncates or corrupts at the server.
size_t buildTelemetryBody(const TelemetrySample& sample, const char* minerCode,
                          const char* installId, const char* isoTimestamp, char* out,
                          size_t outLen);

// True when `s` is non-null and contains no character requiring JSON string escaping.
bool isJsonSafeToken(const char* s);

}  // namespace fry
