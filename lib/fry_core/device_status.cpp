#include "device_status.h"

#include <cstdio>

#include "telemetry_body.h"

namespace fry {

uint8_t statusLegacyErr(const DeviceStatus& s) {
  return s.state == ProvState::Error ? legacyProvErr(s.err) : 0;
}

uint8_t statusDetailErr(const DeviceStatus& s) {
  return s.state == ProvState::Error ? static_cast<uint8_t>(s.err) : 0;
}

size_t buildStatusJson(const DeviceStatus& s, char* out, size_t outCap) {
  if (!out || outCap == 0) return 0;
  out[0] = 0;
  if (!isJsonSafeToken(s.fw) || !isJsonSafeToken(s.ota)) return 0;
  char buf[kStatusJsonMax + 1];
  const int n = snprintf(
      buf, sizeof(buf),
      "{\"v\":1,\"proto\":2,\"caps\":[\"key_write\",\"error_reset\",\"errs_v2\"],\"s\":%u,\"e\":%u,"
      "\"d\":%u,\"k\":%u,\"kc\":%u,\"reg\":%d,\"hb\":%ld,\"fw\":\"%s\",\"ota\":\"%s\"}",
      static_cast<unsigned>(s.state), static_cast<unsigned>(statusLegacyErr(s)),
      static_cast<unsigned>(statusDetailErr(s)), s.keySet ? 1u : 0u, s.keyConfirmed ? 1u : 0u,
      s.regHttp, static_cast<long>(s.hbAgeS), s.fw, s.ota);
  if (n <= 0 || static_cast<size_t>(n) > kStatusJsonMax || static_cast<size_t>(n) >= outCap) {
    return 0;
  }
  for (int i = 0; i <= n; i++) out[i] = buf[i];
  return static_cast<size_t>(n);
}

}  // namespace fry
