#include "mfln_cache.h"

#if !defined(ARDUINO) || defined(ARDUINO_ARCH_ESP8266)

namespace fry {

namespace {

// 64-bit FNV-1a over the ASCII-lower-cased host. 64 bits so that a collision between two hosts (which
// would hand a peer that does NOT honour MFLN the 512/512 buffers it cannot carry) is not a real risk.
uint64_t hostHash(const char* host) {
  uint64_t h = 1469598103934665603ULL;
  for (const char* c = host; *c; c++) {
    uint8_t b = static_cast<uint8_t>(*c);
    if (b >= 'A' && b <= 'Z') b = static_cast<uint8_t>(b + ('a' - 'A'));
    h = (h ^ b) * 1099511628211ULL;
  }
  return h == 0 ? 1 : h;  // 0 marks an empty slot
}

}  // namespace

// 217c2bb probed on every call. Now: once per host per boot, positive answers only.
bool mflnHonours(MflnCache& cache, const char* host, bool (*probe)(const char* host, void* ctx),
                 void* ctx) {
  if (host == nullptr || *host == '\0') return probe(host, ctx);
  const uint64_t h = hostHash(host);
  for (unsigned i = 0; i < kMflnCacheSlots; i++) {
    if (cache.hash[i] == h) return true;
  }
  const bool honours = probe(host, ctx);
  if (honours) {
    cache.hash[cache.next] = h;
    cache.next = static_cast<uint8_t>((cache.next + 1) % kMflnCacheSlots);
  }
  return honours;
}

}  // namespace fry

#endif  // !ARDUINO || ARDUINO_ARCH_ESP8266
