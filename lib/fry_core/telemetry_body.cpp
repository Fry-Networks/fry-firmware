#include "telemetry_body.h"

#include <stdio.h>
#include <string.h>

namespace fry {

bool isJsonSafeToken(const char* s) {
  if (!s) return false;
  for (const char* p = s; *p; ++p) {
    unsigned char c = static_cast<unsigned char>(*p);
    if (c == '"' || c == '\\') return false;
    if (c < 0x20) return false;  // control characters must be \u-escaped in JSON
  }
  return true;
}

size_t buildTelemetryBody(const TelemetrySample& sample, const char* minerCode,
                          const char* installId, const char* isoTimestamp, char* out,
                          size_t outLen) {
  if (!out || outLen == 0) return 0;
  out[0] = '\0';

  if (!isJsonSafeToken(minerCode) || !isJsonSafeToken(installId) ||
      !isJsonSafeToken(isoTimestamp) || !isJsonSafeToken(sample.chip) ||
      !isJsonSafeToken(sample.firmware)) {
    return 0;
  }

  int n = snprintf(
      out, outLen,
      "{\"miner_code\":\"%s\",\"install_id\":\"%s\",\"measurement_type\":\"telemetry\","
      "\"timestamp\":\"%s\",\"value\":{"
      "\"uptime_s\":%lu,\"heap_free\":%lu,\"heap_max_block\":%lu,"
      "\"stack_high_water\":%lu,\"rssi\":%ld,\"chip\":\"%s\",\"firmware\":\"%s\"}}",
      minerCode, installId, isoTimestamp,
      static_cast<unsigned long>(sample.uptimeS), static_cast<unsigned long>(sample.heapFree),
      static_cast<unsigned long>(sample.heapMaxBlock),
      static_cast<unsigned long>(sample.stackHighWater), static_cast<long>(sample.rssi),
      sample.chip, sample.firmware);

  // snprintf returns what it WOULD have written; a value >= outLen means it truncated, and a
  // truncated JSON body is worse than none at all.
  if (n < 0 || static_cast<size_t>(n) >= outLen) {
    out[0] = '\0';
    return 0;
  }
  return static_cast<size_t>(n);
}

}  // namespace fry
