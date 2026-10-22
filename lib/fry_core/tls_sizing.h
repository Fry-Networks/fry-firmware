#pragma once
// ESP8266 TLS buffer sizing, decided from ONE heap sample.
//
// src/esp8266/http_tls.cpp used to take its verdict from a gate sample and then pick the BearSSL
// buffers by a second rule, and a non-affordable verdict dropped EVERY peer to 512/512. That is
// right for a peer that honours MFLN (hardwareapi) and fatal for one that does not (GitHub, the
// OTA manifest and image host): 512/512 against a 16 KB-record server made BearSSL spin until the
// soft watchdog bit (0.3.3 bench: 2x Soft WDT (Exception 4) + 1x HTTP -5 in 3 scheduled checks).
// Deciding the verdict AND the sizing from the same sample, in one pure function, makes "a check
// never proceeds into a handshake it cannot afford" a property that is tested, not a convention.
//
// ESP8266 and host only: ESP32's mbedtls has no buffer-size decision to make, and the translation
// unit is empty there so the ESP32/C3 images are untouched.
#if !defined(ARDUINO) || defined(ARDUINO_ARCH_ESP8266)

#include <cstdint>

namespace fry {

struct HeapSample {
  uint32_t freeTotal;  // ESP.getFreeHeap()
  uint32_t maxBlock;   // ESP.getMaxFreeBlockSize()
};

enum class TlsSizing : uint8_t {
  Refuse,      // do not open the session: it cannot be afforded and 512/512 cannot carry this peer
  Small,       // 512/512 (only for a peer that may honour MFLN)
  Big,         // 16384/512, no probe (peer known not to honour MFLN, heap affordable)
  ProbeFirst,  // probe MFLN: honoured -> 512/512, refused -> 16384/512 (heap affordable)
};

struct TlsPlan {
  TlsSizing sizing;
  bool affordable;  // heapGatePass() on the SAME sample the sizing came from
};

// peerMightHonourMfln is false for a host known to refuse MFLN (GitHub): such a peer is either
// given the big buffers or not connected to at all, never 512/512.
TlsPlan planTls(const HeapSample& sample, uint32_t minFreeTotal, uint32_t minBlock,
                bool peerMightHonourMfln);

}  // namespace fry

#endif  // !ARDUINO || ARDUINO_ARCH_ESP8266
