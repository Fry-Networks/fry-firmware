#pragma once
// Portable SHA-256 (FIPS 180-4), zero Arduino includes, zero external dependencies.
// Used for the miner-key derivation (PROTOCOL.md section 4), which must be byte-identical
// across ESP8266/ESP32/ESP32-S3/ESP32-C3 — a self-contained implementation avoids relying on
// divergent per-chip TLS crypto libraries (mbedtls on ESP32, BearSSL on ESP8266) for a value
// that must never change once generated.
#include <cstddef>
#include <cstdint>

namespace fry {

class Sha256 {
 public:
  Sha256();
  void update(const uint8_t* data, size_t len);
  void finish(uint8_t out[32]);

  // One-shot convenience.
  static void hash(const uint8_t* data, size_t len, uint8_t out[32]);

 private:
  void transform(const uint8_t block[64]);

  uint32_t _state[8];
  uint8_t _buffer[64];
  size_t _bufferLen;
  uint64_t _bitLen;
};

// Hex-encodes `len` bytes as uppercase hex into `out` (must be at least 2*len+1 bytes).
void bytesToHexUpper(const uint8_t* data, size_t len, char* out, size_t outLen);

}  // namespace fry
