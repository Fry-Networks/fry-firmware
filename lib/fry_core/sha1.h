#pragma once
// Portable SHA-1 (FIPS 180-4), zero Arduino includes. Used ONLY for the RFC 6455
// Sec-WebSocket-Accept check of the ESP8266 relay link (ws_frame.h) - never for anything that
// needs collision resistance. Self-contained for the same reason as sha256.h: it must link into
// the native test build.
#include <cstddef>
#include <cstdint>

namespace fry {

class Sha1 {
 public:
  Sha1();
  void update(const uint8_t* data, size_t len);
  void finish(uint8_t out[20]);

  static void hash(const uint8_t* data, size_t len, uint8_t out[20]);

 private:
  void transform(const uint8_t block[64]);

  uint32_t _state[5];
  uint8_t _buffer[64];
  size_t _bufferLen;
  uint64_t _bitLen;
};

}  // namespace fry
