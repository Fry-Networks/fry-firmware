#pragma once
// Key mapping and value codec shared by the Pico (one LittleFS file per key) and BK7231N (FlashDB blob per key) stores, which
// both present the Preferences interface fry_config.cpp uses on the ESP32 family. Header-only, no Arduino include.
//   flat key  = "<namespace>.<key>"   ("fry.minerKey", "fry_wifi.ssid")
// Namespace and key are limited like NVS (15 characters, [A-Za-z0-9_]) so any name that works on the ESP32 works here and the
// two cannot collide through the '.' separator.
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace fry {
namespace kv {

constexpr size_t kNameMax = 15;
constexpr size_t kFlatMax = 2 * kNameMax + 2;  // ns + '.' + key + NUL

inline bool validName(const char* s) {
  if (!s || !s[0]) return false;
  size_t n = 0;
  for (; s[n]; n++) {
    const char c = s[n];
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
    if (!ok) return false;
  }
  return n <= kNameMax;
}

inline bool flatKey(const char* ns, const char* key, char* out, size_t cap) {
  if (!validName(ns) || !validName(key) || !out) return false;
  const size_t need = strlen(ns) + 1 + strlen(key) + 1;
  if (cap < need) return false;
  snprintf(out, cap, "%s.%s", ns, key);
  return true;
}

inline bool inNamespace(const char* flat, const char* ns) {
  if (!flat || !ns) return false;
  const size_t n = strlen(ns);
  return strncmp(flat, ns, n) == 0 && flat[n] == '.' && flat[n + 1] != '\0';
}

inline const char* keyPart(const char* flat, const char* ns) { return inNamespace(flat, ns) ? flat + strlen(ns) + 1 : nullptr; }

// LittleFS file of a key: "/kv_<ns>.<key>".
inline bool fileName(const char* ns, const char* key, char* out, size_t cap) {
  char flat[kFlatMax];
  if (!flatKey(ns, key, flat, sizeof(flat))) return false;
  if (cap < strlen(flat) + 5) return false;
  snprintf(out, cap, "/kv_%s", flat);
  return true;
}

inline void encodeU32(uint32_t v, uint8_t out[4]) {
  out[0] = static_cast<uint8_t>(v);
  out[1] = static_cast<uint8_t>(v >> 8);
  out[2] = static_cast<uint8_t>(v >> 16);
  out[3] = static_cast<uint8_t>(v >> 24);
}

inline uint32_t decodeU32(const uint8_t* b, size_t len, uint32_t def) {
  if (!b || len != 4) return def;
  return static_cast<uint32_t>(b[0]) | (static_cast<uint32_t>(b[1]) << 8) | (static_cast<uint32_t>(b[2]) << 16) |
         (static_cast<uint32_t>(b[3]) << 24);
}

// The stored form of a string includes its NUL, as NVS stores it. Returns the blob length, 0 when it would not fit (a write is
// refused, never truncated).
inline size_t encodeString(const char* s, uint8_t* out, size_t cap) {
  if (!s || !out) return 0;
  const size_t n = strlen(s) + 1;
  if (n > cap) return 0;
  memcpy(out, s, n);
  return n;
}

// Copies at most cap-1 characters and always NUL-terminates. Returns the string length copied.
inline size_t decodeString(const uint8_t* blob, size_t len, char* out, size_t cap) {
  if (!out || cap == 0) return 0;
  out[0] = '\0';
  if (!blob || len == 0) return 0;
  size_t n = 0;
  while (n < len && n + 1 < cap && blob[n] != 0) {
    out[n] = static_cast<char>(blob[n]);
    n++;
  }
  out[n] = '\0';
  return n;
}

}  // namespace kv
}  // namespace fry
