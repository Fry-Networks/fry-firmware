#pragma once
// Staged-rollout gate for the OTA manifest. Pure C++, no Arduino/ArduinoJson dependency.
//
// A manifest MAY carry a top-level "rollout" object (parsed by ota_rollout_json.h):
//   {"bucket_lo": 0-99, "bucket_hi": 0-99, "allow": ["<16 hex>", ...]}
// A device's bucket is the first four bytes of SHA-256(miner key string), read big-endian, mod 100.
// "allow" holds the first 16 lowercase hex chars of that same digest; the manifest is PUBLIC, so it
// never carries a raw key. Eligible iff bucket_lo <= bucket <= bucket_hi OR the prefix is listed.
// Absent field: no gate (the 0.4.7 behaviour). Malformed field: ignored entirely, same as absent.
#include <cstddef>
#include <cstdint>

namespace fry {

const size_t kRolloutPrefixHexLen = 16;

// (digest[0]<<24 | digest[1]<<16 | digest[2]<<8 | digest[3]) % 100
uint32_t rolloutBucket(const uint8_t digest[32]);

// Lowercase hex of digest[0..7] into out (17 bytes with the NUL).
void rolloutPrefixHex(const uint8_t digest[32], char out[kRolloutPrefixHexLen + 1]);

// True iff `s` is exactly 16 hex digits (either case) and nothing else.
bool isRolloutHexPrefix(const char* s);

// Case-insensitive compare of a manifest allow entry against this device's lowercase prefix.
bool rolloutPrefixMatches(const char* manifestEntry, const char devicePrefix[kRolloutPrefixHexLen + 1]);

bool rolloutEligible(uint32_t lo, uint32_t hi, uint32_t bucket, bool inAllow);

}  // namespace fry
