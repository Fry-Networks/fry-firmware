// RFC3339 UTC timestamp ("2023-11-14T22:13:20Z") from epoch seconds, with integer arithmetic only.
//
// Replaces strftime("%Y-%m-%dT%H:%M:%SZ") in src/core/telemetry.cpp. On the ESP8266 strftime was the only reference to libc's
// timelocal.o and strftime.o: ~640 B of DRAM .rodata, i.e. 640 B less heap for the OTA image download's TLS session
// (test/test_esp8266_iso8601 pins the output against the C library). Pure C++11, no Arduino include.
#ifndef FRY_ISO8601_UTC_H
#define FRY_ISO8601_UTC_H

#include <stddef.h>
#include <stdint.h>

namespace fry {

// Writes "YYYY-MM-DDTHH:MM:SSZ" and a NUL. Returns the length (20), or 0 when the buffer holds fewer than 21 bytes, is null,
// or secs is negative or past year 9999 (the format would not be 4-digit). Civil-from-days after H. Hinnant (proleptic Gregorian).
inline size_t formatIso8601Utc(int64_t secs, char* out, size_t outLen) {
  if (out == nullptr || outLen < 21 || secs < 0 || secs > 253402300799LL) return 0;
  const int64_t days = secs / 86400;
  const uint32_t rem = static_cast<uint32_t>(secs % 86400);
  const int64_t z = days + 719468;
  const int64_t era = z / 146097;  // z >= 0 here
  const uint32_t doe = static_cast<uint32_t>(z - era * 146097);
  const uint32_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  const uint32_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  const uint32_t mp = (5 * doy + 2) / 153;
  const uint32_t d = doy - (153 * mp + 2) / 5 + 1;
  const uint32_t m = mp < 10 ? mp + 3 : mp - 9;
  const uint32_t y = static_cast<uint32_t>(yoe + era * 400) + (m <= 2 ? 1 : 0);
  const uint32_t hh = rem / 3600, mi = (rem % 3600) / 60, ss = rem % 60;
  const uint32_t f[6] = {y, m, d, hh, mi, ss};
  // widths and separators of YYYY-MM-DDTHH:MM:SSZ
  static const char kSep[6] = {'-', '-', 'T', ':', ':', 'Z'};
  static const uint8_t kWidth[6] = {4, 2, 2, 2, 2, 2};
  size_t n = 0;
  for (int i = 0; i < 6; i++) {
    uint32_t v = f[i];
    for (int k = kWidth[i] - 1; k >= 0; k--) {
      out[n + static_cast<size_t>(k)] = static_cast<char>('0' + v % 10);
      v /= 10;
    }
    n += kWidth[i];
    out[n++] = kSep[i];
  }
  out[n] = '\0';
  return n;
}

}  // namespace fry

#endif  // FRY_ISO8601_UTC_H
