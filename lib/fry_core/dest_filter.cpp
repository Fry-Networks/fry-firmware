#include "dest_filter.h"

#include <cstring>

namespace fry {

namespace {

DestCounters g_counters;

bool inRange(uint32_t ip, uint32_t net, int prefix) {
  const uint32_t mask = prefix == 0 ? 0 : 0xFFFFFFFFu << (32 - prefix);
  return (ip & mask) == (net & mask);
}

bool parseV4(const char* s, uint32_t* out) {
  uint32_t ip = 0;
  int octets = 0;
  const char* p = s;
  while (true) {
    if (*p < '0' || *p > '9') return false;
    uint32_t v = 0;
    int digits = 0;
    const bool leadingZero = (*p == '0' && p[1] >= '0' && p[1] <= '9');  // "012": octal to lwIP
    if (leadingZero) return false;
    while (*p >= '0' && *p <= '9') {
      v = v * 10 + static_cast<uint32_t>(*p - '0');
      if (++digits > 3 || v > 255) return false;
      ++p;
    }
    ip = (ip << 8) | v;
    ++octets;
    if (*p == 0) break;
    if (*p != '.' || octets == 4) return false;
    ++p;
  }
  if (octets != 4) return false;
  *out = ip;
  return true;
}

int hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Minimal IPv6 text parser: hex groups, one "::", optional trailing dotted quad.
bool parseV6(const char* s, uint8_t out[16]) {
  if (std::strchr(s, ':') == nullptr) return false;
  uint16_t groups[8] = {0};
  int n = 0;        // groups parsed before "::" (or in total)
  int tailN = 0;    // groups after "::"
  uint16_t tail[8] = {0};
  bool gap = false;
  const char* p = s;
  if (p[0] == ':') {
    if (p[1] != ':') return false;
    gap = true;
    p += 2;
    if (*p == 0) {
      std::memset(out, 0, 16);
      return true;
    }
  }
  while (*p) {
    if (std::strchr(p, '.') != nullptr && std::strchr(p, ':') == nullptr) {  // trailing dotted quad
      uint32_t v4;
      if (!parseV4(p, &v4)) return false;
      uint16_t hi = static_cast<uint16_t>(v4 >> 16), lo = static_cast<uint16_t>(v4 & 0xFFFF);
      uint16_t* dst = gap ? tail : groups;
      int& cnt = gap ? tailN : n;
      if (cnt + 2 > 8) return false;
      dst[cnt++] = hi;
      dst[cnt++] = lo;
      break;
    }
    int digits = 0;
    uint32_t v = 0;
    while (*p && *p != ':') {
      int h = hexVal(*p);
      if (h < 0 || ++digits > 4) return false;
      v = (v << 4) | static_cast<uint32_t>(h);
      ++p;
    }
    if (digits == 0) return false;
    uint16_t* dst = gap ? tail : groups;
    int& cnt = gap ? tailN : n;
    if (cnt >= 8) return false;
    dst[cnt++] = static_cast<uint16_t>(v);
    if (*p == ':') {
      ++p;
      if (*p == ':') {
        if (gap) return false;
        gap = true;
        ++p;
      } else if (*p == 0) {
        return false;
      }
    }
  }
  if (!gap && n != 8) return false;
  if (gap && n + tailN > 7) return false;
  uint16_t full[8] = {0};
  for (int i = 0; i < n; i++) full[i] = groups[i];
  for (int i = 0; i < tailN; i++) full[8 - tailN + i] = tail[i];
  for (int i = 0; i < 8; i++) {
    out[2 * i] = static_cast<uint8_t>(full[i] >> 8);
    out[2 * i + 1] = static_cast<uint8_t>(full[i] & 0xFF);
  }
  return true;
}

// A host made only of digits, hex letters, 'x' and dots that starts with a digit ("012.0.0.1",
// "0x0a.0.0.1", "10.1", "2130706433"): lwIP's resolver reads these as IPv4 in octal, hex or
// shortened forms, so they are never treated as a name.
bool looksNumeric(const char* s) {
  if (s[0] < '0' || s[0] > '9') return false;
  for (const char* p = s; *p; ++p) {
    const char c = *p;
    const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') ||
                    c == 'x' || c == 'X' || c == '.';
    if (!ok) return false;
  }
  return true;
}

uint32_t be32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | p[3];
}

}  // namespace

bool destParseV4(const char* host, uint32_t* ipHostOrder) {
  if (host == nullptr || host[0] == 0) return false;
  return parseV4(host, ipHostOrder);
}

bool destIsBlockedV4(uint32_t ip, const DestCtx& ctx) {
  if (inRange(ip, 0x00000000u, 8)) return true;        // 0.0.0.0/8
  if (inRange(ip, 0x7F000000u, 8)) return true;        // 127/8
  if (inRange(ip, 0x0A000000u, 8)) return true;        // 10/8
  if (inRange(ip, 0xAC100000u, 12)) return true;       // 172.16/12
  if (inRange(ip, 0xC0A80000u, 16)) return true;       // 192.168/16
  if (inRange(ip, 0xA9FE0000u, 16)) return true;       // 169.254/16
  if (inRange(ip, 0x64400000u, 10)) return true;       // 100.64/10
  if (inRange(ip, 0xE0000000u, 4)) return true;        // 224/4
  if (inRange(ip, 0xF0000000u, 4)) return true;        // 240/4, incl. 255.255.255.255
  if (ctx.gateway != 0 && ip == ctx.gateway) return true;
  if (ctx.selfIp != 0 && ctx.selfMask != 0 && (ip & ctx.selfMask) == (ctx.selfIp & ctx.selfMask)) {
    return true;
  }
  return false;
}

bool destIsBlockedV6(const uint8_t ip[16], const DestCtx& ctx) {
  static const uint8_t kMappedPrefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
  static const uint8_t kNat64Prefix[12] = {0x00, 0x64, 0xFF, 0x9B, 0, 0, 0, 0, 0, 0, 0, 0};
  if (std::memcmp(ip, kMappedPrefix, 12) == 0) return destIsBlockedV4(be32(ip + 12), ctx);
  if (std::memcmp(ip, kNat64Prefix, 12) == 0) return destIsBlockedV4(be32(ip + 12), ctx);  // 64:ff9b::/96
  if (ip[0] == 0x20 && ip[1] == 0x02) return destIsBlockedV4(be32(ip + 2), ctx);            // 2002::/16 (6to4)
  bool allZeroButLast = true;
  for (int i = 0; i < 15; i++) {
    if (ip[i] != 0) { allZeroButLast = false; break; }
  }
  if (allZeroButLast && ip[15] <= 1) return true;      // :: and ::1
  {
    static const uint8_t kZero12[12] = {0};
    if (std::memcmp(ip, kZero12, 12) == 0) return destIsBlockedV4(be32(ip + 12), ctx);  // ::/96 IPv4-compatible
  }
  if ((ip[0] & 0xFE) == 0xFC) return true;             // fc00::/7
  if (ip[0] == 0xFE && (ip[1] & 0xC0) == 0x80) return true;  // fe80::/10
  if (ip[0] == 0xFF) return true;                      // ff00::/8
  return false;
}

bool destIsBlockedV6(const uint8_t ip[16]) { return destIsBlockedV6(ip, DestCtx{}); }

bool destFilterV4(uint32_t ip, const DestCtx& ctx) {
  const bool allowed = !destIsBlockedV4(ip, ctx);
  (allowed ? g_counters.allowed : g_counters.blocked)++;
  return allowed;
}

bool destFilterV6(const uint8_t ip[16], const DestCtx& ctx) {
  const bool allowed = !destIsBlockedV6(ip, ctx);
  (allowed ? g_counters.allowed : g_counters.blocked)++;
  return allowed;
}

bool destFilterV6(const uint8_t ip[16]) { return destFilterV6(ip, DestCtx{}); }

bool destFilterText(const char* host, const DestCtx& ctx, bool* isLiteral) {
  if (isLiteral) *isLiteral = false;
  if (host == nullptr || host[0] == 0) return false;
  uint32_t v4;
  if (parseV4(host, &v4)) {
    if (isLiteral) *isLiteral = true;
    return destFilterV4(v4, ctx);
  }
  uint8_t v6[16];
  if (parseV6(host, v6)) {
    if (isLiteral) *isLiteral = true;
    return destFilterV6(v6, ctx);
  }
  // Anything numeric-looking or colon-bearing that did not parse canonically is a literal in a
  // form the resolver may still accept (octal, hex, short, zone-id): blocked, never a name.
  if (looksNumeric(host) || std::strchr(host, ':') != nullptr) {
    if (isLiteral) *isLiteral = true;
    g_counters.blocked++;
    return false;
  }
  return false;
}

DestCounters destCounters() { return g_counters; }
void destCountersReset() { g_counters = DestCounters{}; }

}  // namespace fry
