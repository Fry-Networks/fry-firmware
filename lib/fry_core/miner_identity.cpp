#include "miner_identity.h"

#include <cstdio>
#include <cstring>

#include "sha256.h"

namespace fry {

namespace {

bool isHexUpper(char c) { return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'); }

const char* const kChipTags[] = {"ESP8266", "ESP32", "ESP32-S3", "ESP32-C3"};
const size_t kChipTagCount = sizeof(kChipTags) / sizeof(kChipTags[0]);

}  // namespace

void computeMinerKey(const uint8_t mac6[3], const uint8_t salt[16], char* outKey, size_t outKeyLen) {
  uint8_t msg[3 + 16];
  memcpy(msg, mac6, 3);
  memcpy(msg + 3, salt, 16);

  uint8_t digest[32];
  Sha256::hash(msg, sizeof(msg), digest);

  char hex[33];
  bytesToHexUpper(digest, 16, hex, sizeof(hex));  // truncate to first 16 bytes = 32 hex chars

  snprintf(outKey, outKeyLen, "IOT-%s", hex);
}

bool isValidMinerKey(const char* key) {
  if (!key) return false;
  if (strlen(key) != 36) return false;  // "IOT-" (4) + 32 hex chars
  if (strncmp(key, "IOT-", 4) != 0) return false;
  for (int i = 0; i < 32; i++) {
    if (!isHexUpper(key[4 + i])) return false;
  }
  return true;
}

void formatDeviceName(const char* chipTag, const uint8_t mac6[3], char* outName, size_t outNameLen) {
  snprintf(outName, outNameLen, "FRY-%s-%02X%02X%02X", chipTag, mac6[0], mac6[1], mac6[2]);
}

bool isValidDeviceName(const char* name) {
  if (!name) return false;
  if (strncmp(name, "FRY-", 4) != 0) return false;
  const char* rest = name + 4;

  for (size_t t = 0; t < kChipTagCount; t++) {
    const char* tag = kChipTags[t];
    size_t tagLen = strlen(tag);
    if (strncmp(rest, tag, tagLen) != 0) continue;
    if (rest[tagLen] != '-') continue;
    const char* mac = rest + tagLen + 1;
    size_t macLen = strlen(mac);
    if (macLen != 6) continue;
    bool allHex = true;
    for (int i = 0; i < 6; i++) {
      if (!isHexUpper(mac[i])) {
        allHex = false;
        break;
      }
    }
    if (allHex) return true;
  }
  return false;
}

}  // namespace fry
