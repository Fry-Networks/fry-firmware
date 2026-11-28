#include "config_snapshot.h"

#include <string.h>

namespace fry {
namespace cfg {

namespace {

const uint32_t kFnvOffset = 2166136261u;
const uint32_t kFnvPrime = 16777619u;

uint32_t fnvByte(uint32_t h, uint8_t b) { return (h ^ b) * kFnvPrime; }

// Bytes up to (not including) the NUL, bounded by `cap`, then a 0x00 separator so field boundaries count.
uint32_t fnvStr(uint32_t h, const char* s, size_t cap) {
  for (size_t i = 0; i < cap && s[i]; i++) h = fnvByte(h, (uint8_t)s[i]);
  return fnvByte(h, 0);
}

bool isAlnum(char c) { return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }

}  // namespace

uint32_t snapshotGeneration(const Snapshot& s) {
  uint32_t h = kFnvOffset;
  h = fnvStr(h, s.ssid, sizeof(s.ssid));
  h = fnvByte(h, s.hasPass ? 1 : 0);
  h = fnvByte(h, s.hasMinerKey ? 1 : 0);
  h = fnvStr(h, s.minerKeyLast4, sizeof(s.minerKeyLast4));
  h = fnvStr(h, s.wallet, sizeof(s.wallet));
  h = fnvByte(h, s.provDone ? 1 : 0);
  h = fnvByte(h, (uint8_t)s.displayMode);
  return h;
}

bool validMinerKey(const char* k) {
  if (!k) return false;
  if (strlen(k) != 36) return false;
  if (strncmp(k, "FEM-", 4) != 0) return false;
  for (int i = 4; i < 36; i++) {
    if (!isAlnum(k[i])) return false;
  }
  return true;
}

}  // namespace cfg
}  // namespace fry
