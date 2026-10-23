#pragma once
// Per-boot memory of which hosts honour MFLN, so the probe runs once per host instead of on every call.
//
// WiFiClientSecure::probeMaxFragmentLength() is not free: it opens a throwaway TLS session on BearSSL's
// DEFAULT 16384+16384 buffers (~32 KB of contiguous heap, src/esp8266/http_tls.cpp) and leaves a TIME_WAIT
// pcb behind (+1 per probe, measured), and 217c2bb ran it before EVERY call to an MFLN-capable peer
// (hardwareapi: registration, lease renewal, PoC, heartbeat). A host that honours MFLN keeps honouring it
// for the life of the process, so one positive answer is enough.
//
// Only POSITIVE answers are kept. probeMaxFragmentLength() returns false both for "the peer refused" and
// for "I could not connect" and the caller cannot tell them apart; remembering a transient failure would
// pin a healthy MFLN host to the big 16384/512 buffers (which only fit when the heap is intact) until the
// next reboot. A negative answer is simply asked again, exactly as before.
//
// ESP8266 and host only: ESP32 has no MFLN buffer-size decision, so the translation unit is empty there.
#if !defined(ARDUINO) || defined(ARDUINO_ARCH_ESP8266)

#include <cstdint>

namespace fry {

constexpr unsigned kMflnCacheSlots = 4;

struct MflnCache {
  uint64_t hash[kMflnCacheSlots];  // 64-bit FNV-1a of the lower-cased host; 0 = empty slot
  uint8_t next;                    // slot the next remembered host overwrites (oldest first)
};

// Returns whether `host` honours MFLN 512. Runs `probe(host, ctx)` at most once per host per boot: a
// positive result is remembered and answers every later call; a negative one is not (see above).
// A null or empty host is never remembered.
bool mflnHonours(MflnCache& cache, const char* host, bool (*probe)(const char* host, void* ctx),
                 void* ctx);

}  // namespace fry

#endif  // !ARDUINO || ARDUINO_ARCH_ESP8266
