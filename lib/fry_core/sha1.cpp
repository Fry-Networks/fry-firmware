#include "sha1.h"

#include <cstring>

namespace fry {

namespace {

inline uint32_t rol(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

}  // namespace

Sha1::Sha1() : _state{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0},
               _buffer{0}, _bufferLen(0), _bitLen(0) {}

void Sha1::transform(const uint8_t block[64]) {
  uint32_t w[80];
  for (int i = 0; i < 16; i++) {
    w[i] = (static_cast<uint32_t>(block[4 * i]) << 24) |
           (static_cast<uint32_t>(block[4 * i + 1]) << 16) |
           (static_cast<uint32_t>(block[4 * i + 2]) << 8) | static_cast<uint32_t>(block[4 * i + 3]);
  }
  for (int i = 16; i < 80; i++) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

  uint32_t a = _state[0], b = _state[1], c = _state[2], d = _state[3], e = _state[4];
  for (int i = 0; i < 80; i++) {
    uint32_t f, k;
    if (i < 20) {
      f = (b & c) | (~b & d);
      k = 0x5A827999;
    } else if (i < 40) {
      f = b ^ c ^ d;
      k = 0x6ED9EBA1;
    } else if (i < 60) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8F1BBCDC;
    } else {
      f = b ^ c ^ d;
      k = 0xCA62C1D6;
    }
    uint32_t t = rol(a, 5) + f + e + k + w[i];
    e = d;
    d = c;
    c = rol(b, 30);
    b = a;
    a = t;
  }
  _state[0] += a;
  _state[1] += b;
  _state[2] += c;
  _state[3] += d;
  _state[4] += e;
}

void Sha1::update(const uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    _buffer[_bufferLen++] = data[i];
    if (_bufferLen == 64) {
      transform(_buffer);
      _bitLen += 512;
      _bufferLen = 0;
    }
  }
}

void Sha1::finish(uint8_t out[20]) {
  _bitLen += static_cast<uint64_t>(_bufferLen) * 8;
  _buffer[_bufferLen++] = 0x80;
  if (_bufferLen > 56) {
    while (_bufferLen < 64) _buffer[_bufferLen++] = 0;
    transform(_buffer);
    _bufferLen = 0;
  }
  while (_bufferLen < 56) _buffer[_bufferLen++] = 0;
  for (int i = 7; i >= 0; i--) _buffer[_bufferLen++] = static_cast<uint8_t>(_bitLen >> (8 * i));
  transform(_buffer);
  for (int i = 0; i < 5; i++) {
    out[4 * i] = static_cast<uint8_t>(_state[i] >> 24);
    out[4 * i + 1] = static_cast<uint8_t>(_state[i] >> 16);
    out[4 * i + 2] = static_cast<uint8_t>(_state[i] >> 8);
    out[4 * i + 3] = static_cast<uint8_t>(_state[i]);
  }
}

void Sha1::hash(const uint8_t* data, size_t len, uint8_t out[20]) {
  Sha1 s;
  s.update(data, len);
  s.finish(out);
}

}  // namespace fry
