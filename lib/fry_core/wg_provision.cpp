#include "wg_provision.h"

#include <cstdio>
#include <cstring>

namespace fry {

namespace {

const char kB64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// -1 for any character outside the standard (non-URL-safe) base64 alphabet.
int b64Value(char c) {
  for (int i = 0; i < 64; i++) {
    if (kB64Alphabet[i] == c) return i;
  }
  return -1;
}

bool isDigit(char c) { return c >= '0' && c <= '9'; }

// Parses up to 3 ASCII digits into *out (0-255 range checked by the caller). Returns the number
// of digit characters consumed, or 0 if `s` doesn't start with a digit.
size_t parseOctetDigits(const char* s, uint32_t* out) {
  uint32_t v = 0;
  size_t n = 0;
  while (n < 3 && isDigit(s[n])) {
    v = v * 10 + static_cast<uint32_t>(s[n] - '0');
    n++;
  }
  if (n == 0) return 0;
  *out = v;
  return n;
}

}  // namespace

// ── Key encoding ─────────────────────────────────────────────────────────────────────────────

bool isWgKeyB64(const char* s) {
  if (s == nullptr) return false;
  size_t len = std::strlen(s);
  if (len != 44) return false;
  if (s[43] != '=') return false;
  for (int i = 0; i < 42; i++) {
    if (b64Value(s[i]) < 0) return false;
  }
  // The 43rd character (index 42) closes out a 2-byte tail group: only 16 real bits exist, so
  // its low 2 bits are always the padding zero bits and must be exactly 0 (value % 4 == 0).
  int last = b64Value(s[42]);
  if (last < 0 || (last % 4) != 0) return false;
  return true;
}

void clampX25519Private(uint8_t key[32]) {
  key[0] &= 248;
  key[31] &= 127;
  key[31] |= 64;
}

size_t encodeWgKeyB64(const uint8_t in[32], char* out, size_t outLen) {
  if (in == nullptr || out == nullptr || outLen < 45) return 0;
  size_t oi = 0;
  size_t i = 0;
  // 10 full 3-byte groups -> 40 characters.
  for (; i + 3 <= 32; i += 3) {
    uint32_t v = (static_cast<uint32_t>(in[i]) << 16) | (static_cast<uint32_t>(in[i + 1]) << 8) |
                 static_cast<uint32_t>(in[i + 2]);
    out[oi++] = kB64Alphabet[(v >> 18) & 0x3F];
    out[oi++] = kB64Alphabet[(v >> 12) & 0x3F];
    out[oi++] = kB64Alphabet[(v >> 6) & 0x3F];
    out[oi++] = kB64Alphabet[v & 0x3F];
  }
  // Final 2-byte tail -> 3 characters + 1 '=' pad.
  uint32_t v = (static_cast<uint32_t>(in[i]) << 16) | (static_cast<uint32_t>(in[i + 1]) << 8);
  out[oi++] = kB64Alphabet[(v >> 18) & 0x3F];
  out[oi++] = kB64Alphabet[(v >> 12) & 0x3F];
  out[oi++] = kB64Alphabet[(v >> 6) & 0x3F];  // low 2 bits always 0 here — the b2=0 padding
  out[oi++] = '=';
  out[oi] = 0;
  return oi + 1;
}

// ── Request body ─────────────────────────────────────────────────────────────────────────────

namespace {
bool jsonSafe(const char* s) {
  if (s == nullptr) return false;
  for (const char* c = s; *c; c++) {
    if (*c == '"' || *c == '\\' || static_cast<unsigned char>(*c) < 0x20) return false;
  }
  return true;
}
}  // namespace

size_t buildWgProvisionBody(const char* pubKeyB64, const char* firmwareVersion, const char* chip,
                            char* out, size_t outLen) {
  if (out == nullptr) return 0;
  if (pubKeyB64 == nullptr || std::strlen(pubKeyB64) != 44) return 0;
  if (!jsonSafe(pubKeyB64) || !jsonSafe(firmwareVersion) || !jsonSafe(chip)) return 0;

  int n = std::snprintf(out, outLen,
                        "{\"public_key\":\"%s\",\"firmware_version\":\"%s\",\"chip\":\"%s\"}",
                        pubKeyB64, firmwareVersion, chip);
  if (n < 0 || static_cast<size_t>(n) >= outLen) return 0;
  return static_cast<size_t>(n);
}

// ── IPv4 helpers ─────────────────────────────────────────────────────────────────────────────

bool parseIpv4Cidr(const char* s, uint32_t* ip, int* prefix) {
  if (s == nullptr || ip == nullptr || prefix == nullptr) return false;
  const char* p = s;
  uint32_t octets[4];
  for (int i = 0; i < 4; i++) {
    uint32_t v;
    size_t n = parseOctetDigits(p, &v);
    if (n == 0 || v > 255) return false;
    p += n;
    octets[i] = v;
    if (i < 3) {
      if (*p != '.') return false;
      p++;
    }
  }
  if (*p != '/') return false;
  p++;
  uint32_t pfx;
  size_t n = parseOctetDigits(p, &pfx);
  if (n == 0 || pfx > 32) return false;
  p += n;
  if (*p != 0) return false;  // no trailing junk

  *ip = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
  *prefix = static_cast<int>(pfx);
  return true;
}

uint32_t prefixToMask(int prefix) {
  if (prefix <= 0) return 0;
  if (prefix >= 32) return 0xFFFFFFFFu;
  return 0xFFFFFFFFu << (32 - prefix);
}

size_t formatIpv4(uint32_t ip, char* out, size_t outLen) {
  if (out == nullptr || outLen < 16) return 0;
  int n = std::snprintf(out, outLen, "%u.%u.%u.%u", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                        (ip >> 8) & 0xFF, ip & 0xFF);
  if (n < 0 || static_cast<size_t>(n) >= outLen) return 0;
  return static_cast<size_t>(n);
}

size_t formatIpv4Cidr(uint32_t ip, int prefix, char* out, size_t outLen) {
  if (out == nullptr || outLen < 19) return 0;
  int n = std::snprintf(out, outLen, "%u.%u.%u.%u/%d", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                        (ip >> 8) & 0xFF, ip & 0xFF, prefix);
  if (n < 0 || static_cast<size_t>(n) >= outLen) return 0;
  return static_cast<size_t>(n);
}

// ── Response validation ──────────────────────────────────────────────────────────────────────

namespace {
void setReject(WgProvisionConfig* cfg, const char* reason) {
  cfg->ok = false;
  std::strncpy(cfg->rejectReason, reason, sizeof(cfg->rejectReason) - 1);
}
}  // namespace

WgProvisionConfig validateWgProvision(const WgProvisionRaw& raw) {
  WgProvisionConfig cfg;

  if (!isWgKeyB64(raw.serverPub)) {
    setReject(&cfg, "bad_server_pubkey");
    return cfg;
  }
  if (raw.endpointHost == nullptr || std::strlen(raw.endpointHost) == 0 ||
      std::strlen(raw.endpointHost) >= sizeof(cfg.endpointHost)) {
    setReject(&cfg, "bad_endpoint_host");
    return cfg;
  }
  if (raw.endpointPort <= 0 || raw.endpointPort > 65535) {
    setReject(&cfg, "bad_port");
    return cfg;
  }
  uint32_t tmpIp;
  int tmpPrefix;
  if (raw.tunnelAddress == nullptr || !parseIpv4Cidr(raw.tunnelAddress, &tmpIp, &tmpPrefix) ||
      std::strlen(raw.tunnelAddress) >= sizeof(cfg.addressCidr)) {
    setReject(&cfg, "bad_tunnel_address");
    return cfg;
  }
  if (raw.allowedIpsCount <= 0) {
    setReject(&cfg, "allowed_ips_empty");
    return cfg;
  }
  if (raw.allowedIpsCount > kWgMaxAllowedIps) {
    setReject(&cfg, "allowed_ips_too_many");
    return cfg;
  }
  for (int i = 0; i < raw.allowedIpsCount; i++) {
    uint32_t aip;
    int apfx;
    const char* entry = raw.allowedIps[i];
    if (entry == nullptr || !parseIpv4Cidr(entry, &aip, &apfx) ||
        std::strlen(entry) >= sizeof(cfg.allowedIps[0])) {
      setReject(&cfg, "bad_allowed_ip");
      return cfg;
    }
  }
  if (raw.psk != nullptr) {
    if (std::strlen(raw.psk) == 0 || !isWgKeyB64(raw.psk)) {
      setReject(&cfg, "bad_psk");
      return cfg;
    }
  }
  if (raw.keepaliveProvided && raw.keepaliveValue <= 0) {
    setReject(&cfg, "zero_keepalive");
    return cfg;
  }

  cfg.ok = true;
  std::strncpy(cfg.serverPub, raw.serverPub, sizeof(cfg.serverPub) - 1);
  cfg.hasPsk = raw.psk != nullptr;
  if (cfg.hasPsk) std::strncpy(cfg.psk, raw.psk, sizeof(cfg.psk) - 1);
  std::strncpy(cfg.endpointHost, raw.endpointHost, sizeof(cfg.endpointHost) - 1);
  cfg.endpointPort = static_cast<uint16_t>(raw.endpointPort);
  std::strncpy(cfg.addressCidr, raw.tunnelAddress, sizeof(cfg.addressCidr) - 1);
  cfg.allowedIpsCount = raw.allowedIpsCount;
  for (int i = 0; i < raw.allowedIpsCount; i++) {
    std::strncpy(cfg.allowedIps[i], raw.allowedIps[i], sizeof(cfg.allowedIps[0]) - 1);
  }
  cfg.keepaliveS = raw.keepaliveProvided ? static_cast<uint32_t>(raw.keepaliveValue) : 25;
  return cfg;
}

// ── Route planning ───────────────────────────────────────────────────────────────────────────

namespace {

// True iff `addr` falls within the network described by (net, prefix). `net` must already be
// the network address at that prefix (low bits zero) - true for every value this function is
// called with below.
bool addrInBlock(uint32_t addr, uint32_t net, int prefix) {
  return (addr & prefixToMask(prefix)) == net;
}

// Narrows (net, prefix) — a candidate already known to be prefix>=8 — one bit at a time,
// always keeping the half that excludes whichever of staIp/staGw is currently inside it, until
// neither is inside (returns true, *outNet/*outPrefix updated) or the block has narrowed to a
// single /32 that IS one of them (returns false — the whole candidate must be dropped).
bool narrowAwayFromSta(uint32_t net, int prefix, uint32_t staIp, int staPrefix, uint32_t staGw,
                        uint32_t* outNet, int* outPrefix) {
  bool staActive = staPrefix > 0 && staIp != 0;
  bool gwActive = staPrefix > 0 && staGw != 0;
  uint32_t curNet = net;
  int p = prefix;
  for (;;) {
    // Checked BEFORE testing p against 32, so a candidate that is already a clean /32 (no STA
    // collision at all) is kept rather than falling through to the "can't narrow further" drop.
    bool staIn = staActive && addrInBlock(staIp, curNet, p);
    bool gwIn = gwActive && addrInBlock(staGw, curNet, p);
    if (!staIn && !gwIn) {
      *outNet = curNet;
      *outPrefix = p;
      return true;
    }
    if (p == 32) return false;  // still colliding and can't narrow further - drop the candidate

    uint32_t mask = prefixToMask(p);
    uint32_t childMask = prefixToMask(p + 1);
    uint32_t bit = mask & ~childMask;  // the single new distinguishing bit
    uint32_t lower = curNet;
    uint32_t upper = curNet | bit;
    if (staIn) {
      bool staInLower = addrInBlock(staIp, lower, p + 1);
      curNet = staInLower ? upper : lower;
    } else {  // gwIn must be true here
      bool gwInLower = addrInBlock(staGw, lower, p + 1);
      curNet = gwInLower ? upper : lower;
    }
    p += 1;
  }
}

}  // namespace

WgRoutePlan planWgRoutes(const char* addressCidr, const char* const* allowedIps, int allowedCount,
                          uint32_t staIp, int staPrefix, uint32_t staGw) {
  WgRoutePlan plan;
  uint32_t addrIp;
  int addrPrefix;
  if (addressCidr == nullptr || !parseIpv4Cidr(addressCidr, &addrIp, &addrPrefix)) {
    std::strncpy(plan.rejectReason, "bad_address_cidr", sizeof(plan.rejectReason) - 1);
    return plan;
  }

  struct Kept {
    uint32_t net;
    int prefix;
  };
  Kept kept[kWgMaxPlannedRoutes];
  int keptCount = 0;

  for (int i = 0; i < allowedCount && keptCount < kWgMaxPlannedRoutes; i++) {
    if (allowedIps == nullptr || allowedIps[i] == nullptr) continue;
    uint32_t ip;
    int prefix;
    if (!parseIpv4Cidr(allowedIps[i], &ip, &prefix)) continue;  // defensive; already validated
    if (prefix < 8) continue;                                   // drop /0-/7

    uint32_t net = ip & prefixToMask(prefix);

    bool dup = false;
    for (int j = 0; j < keptCount; j++) {
      if (kept[j].net == net && kept[j].prefix == prefix) {
        dup = true;
        break;
      }
    }
    if (dup) continue;

    uint32_t narrowedNet;
    int narrowedPrefix;
    if (!narrowAwayFromSta(net, prefix, staIp, staPrefix, staGw, &narrowedNet, &narrowedPrefix)) {
      continue;  // this candidate IS the STA's own address; drop it, not the whole plan
    }

    kept[keptCount].net = narrowedNet;
    kept[keptCount].prefix = narrowedPrefix;
    keptCount++;
  }

  if (keptCount == 0) {
    // Nothing survived - default to the tunnel's own subnet, never narrowed against the STA
    // address (the tunnel's own subnet legitimately contains the device's own tunnel address).
    kept[0].net = addrIp & prefixToMask(addrPrefix);
    kept[0].prefix = addrPrefix;
    keptCount = 1;
  }

  plan.ok = true;
  plan.allowedCount = keptCount;
  for (int i = 0; i < keptCount; i++) {
    formatIpv4Cidr(kept[i].net, kept[i].prefix, plan.allowedCidr[i], sizeof(plan.allowedCidr[i]));
  }
  return plan;
}

// ── HTTP outcome classification + retry schedule ────────────────────────────────────────────

WgFetchOutcome classifyWgFetch(bool hasToken, bool heapOk, bool clockOk, int32_t httpStatus) {
  if (!hasToken) return WgFetchOutcome::NoToken;
  if (!heapOk) return WgFetchOutcome::NoHeap;
  if (!clockOk) return WgFetchOutcome::NoClock;
  if (httpStatus >= 200 && httpStatus < 300) return WgFetchOutcome::Ok;
  if (httpStatus == 401) return WgFetchOutcome::Unauthorized401;
  if (httpStatus == 403) return WgFetchOutcome::Forbidden403;
  if (httpStatus == 409) return WgFetchOutcome::Conflict409;
  if (httpStatus == 429) return WgFetchOutcome::RateLimited429;
  if (httpStatus >= 400 && httpStatus < 500) return WgFetchOutcome::OtherClientError4xx;
  if (httpStatus >= 500) return WgFetchOutcome::ServerError5xx;
  return WgFetchOutcome::TransientError;  // <=0: transport error, or anything else unrecognised
}

WgRetrySchedule wgRetryDelayMs(WgFetchOutcome outcome, uint32_t attemptNumber,
                                uint32_t retryAfterHeaderS) {
  WgRetrySchedule sched;
  switch (outcome) {
    case WgFetchOutcome::NoToken:
    case WgFetchOutcome::NoHeap:
      sched.delayMs = 60000;
      break;
    case WgFetchOutcome::NoClock:
      sched.delayMs = 300000;
      break;
    case WgFetchOutcome::Unauthorized401:
      sched.delayMs = 900000;
      break;
    case WgFetchOutcome::Forbidden403:
      sched.delayMs = 21600000;
      break;
    case WgFetchOutcome::Conflict409:
    case WgFetchOutcome::RateLimited429: {
      if (retryAfterHeaderS > 0) {
        uint64_t ms = static_cast<uint64_t>(retryAfterHeaderS) * 1000ULL;
        if (ms < 60000ULL) ms = 60000ULL;
        if (ms > 86400000ULL) ms = 86400000ULL;
        sched.delayMs = static_cast<uint32_t>(ms);
      } else {
        sched.delayMs = 3600000;
      }
      break;
    }
    case WgFetchOutcome::OtherClientError4xx:
      sched.delayMs = 21600000;
      break;
    case WgFetchOutcome::TransientError:
    case WgFetchOutcome::ServerError5xx:
    case WgFetchOutcome::Ok:
    default: {
      // Wrap-safe: compute in uint64_t and clamp before narrowing back to uint32_t, so a huge
      // attemptNumber saturates at the cap instead of overflowing to a short delay.
      uint64_t base = 30000ULL;
      uint32_t shift = attemptNumber > 32 ? 32 : attemptNumber;  // 1ULL<<32 already exceeds the
                                                                  // cap, so anything past that is
                                                                  // pointless to compute exactly
      uint64_t ms = base << shift;
      if (ms > 1800000ULL || shift == 32) ms = 1800000ULL;
      sched.delayMs = static_cast<uint32_t>(ms);
      break;
    }
  }
  return sched;
}

}  // namespace fry
