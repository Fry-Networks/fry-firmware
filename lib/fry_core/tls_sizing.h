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
  Medium,      // 8192/512, no probe (peer does not honour MFLN but every record of THIS request is small)
};

// BearSSL buffer sizes (payload bytes; WiFiClientSecure::setBufferSizes adds its own 325 B / 85 B of record overhead).
// A 512 B send buffer is what makes BearSSL ask for MFLN 512 in every ClientHello, whatever the receive size is.
constexpr uint16_t kTlsBigRxBytes = 16384;
// OTA manifest (a ~2 KB JSON behind github.com -> github.com -> release-assets.githubusercontent.com). Host probe
// 2026-10-22: github.com honours MFLN 512 (its 2730 B Certificate arrives as 512 B records); release-assets does not
// and sends one 4146 B Certificate record, the largest record of the exchange. 8192 is 1.98x that. A bigger record fails
// cleanly (BR_ERR_TOO_LARGE), it cannot overrun the buffer. The image DOWNLOAD streams 16 KB records: Big only.
constexpr uint16_t kTlsMediumRxBytes = 8192;
constexpr uint16_t kTlsTxBytes = 512;

struct TlsPlan {
  TlsSizing sizing;
  bool affordable;  // heapGatePass() on the SAME sample the sizing came from
};

// peerMightHonourMfln is false for a host that may send records the 512 B receive buffer cannot hold (GitHub's
// release-assets host): such a peer is either given a big enough buffer or not connected to at all, never 512/512.
// smallReply: the caller knows every record of this request is small (the OTA manifest). A peer that does not honour
// MFLN then gets Medium instead of Big; every other combination is unchanged (the default keeps old callers and tests).
TlsPlan planTls(const HeapSample& sample, uint32_t minFreeTotal, uint32_t minBlock,
                bool peerMightHonourMfln, bool smallReply = false);

}  // namespace fry

#endif  // !ARDUINO || ARDUINO_ARCH_ESP8266
