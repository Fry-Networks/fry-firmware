#include "ota_rollout.h"

#include <cstring>

namespace fry {

namespace {

int hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

}  // namespace

uint32_t rolloutBucket(const uint8_t digest[32]) {
  const uint32_t first4 = (static_cast<uint32_t>(digest[0]) << 24) | (static_cast<uint32_t>(digest[1]) << 16) |
                          (static_cast<uint32_t>(digest[2]) << 8) | static_cast<uint32_t>(digest[3]);
  return first4 % 100u;
}

void rolloutPrefixHex(const uint8_t digest[32], char out[kRolloutPrefixHexLen + 1]) {
  static const char kHex[] = "0123456789abcdef";
  for (size_t i = 0; i < kRolloutPrefixHexLen / 2; i++) {
    out[2 * i] = kHex[digest[i] >> 4];
    out[2 * i + 1] = kHex[digest[i] & 0x0F];
  }
  out[kRolloutPrefixHexLen] = '\0';
}

bool isRolloutHexPrefix(const char* s) {
  if (!s) return false;
  size_t n = 0;
  while (s[n] != '\0') {
    if (hexVal(s[n]) < 0) return false;
    if (++n > kRolloutPrefixHexLen) return false;
  }
  return n == kRolloutPrefixHexLen;
}

bool rolloutPrefixMatches(const char* manifestEntry, const char devicePrefix[kRolloutPrefixHexLen + 1]) {
  if (!isRolloutHexPrefix(manifestEntry)) return false;
  for (size_t i = 0; i < kRolloutPrefixHexLen; i++) {
    if (hexVal(manifestEntry[i]) != hexVal(devicePrefix[i])) return false;
  }
  return true;
}

bool rolloutEligible(uint32_t lo, uint32_t hi, uint32_t bucket, bool inAllow) {
  return inAllow || (bucket >= lo && bucket <= hi);
}

}  // namespace fry
