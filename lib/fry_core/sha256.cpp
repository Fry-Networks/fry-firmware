#include "sha256.h"

#include <cstdio>
#include <cstring>

namespace fry {

namespace {

inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
inline uint32_t ep0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
inline uint32_t ep1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
inline uint32_t sig0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
inline uint32_t sig1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

const uint32_t kK[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

}  // namespace

Sha256::Sha256() : _bufferLen(0), _bitLen(0) {
  _state[0] = 0x6a09e667;
  _state[1] = 0xbb67ae85;
  _state[2] = 0x3c6ef372;
  _state[3] = 0xa54ff53a;
  _state[4] = 0x510e527f;
  _state[5] = 0x9b05688c;
  _state[6] = 0x1f83d9ab;
  _state[7] = 0x5be0cd19;
  memset(_buffer, 0, sizeof(_buffer));
}

void Sha256::transform(const uint8_t block[64]) {
  uint32_t m[64];
  for (int i = 0, j = 0; i < 16; i++, j += 4) {
    m[i] = (static_cast<uint32_t>(block[j]) << 24) | (static_cast<uint32_t>(block[j + 1]) << 16) |
           (static_cast<uint32_t>(block[j + 2]) << 8) | static_cast<uint32_t>(block[j + 3]);
  }
  for (int i = 16; i < 64; i++) {
    m[i] = sig1(m[i - 2]) + m[i - 7] + sig0(m[i - 15]) + m[i - 16];
  }

  uint32_t a = _state[0], b = _state[1], c = _state[2], d = _state[3];
  uint32_t e = _state[4], f = _state[5], g = _state[6], h = _state[7];

  for (int i = 0; i < 64; i++) {
    uint32_t t1 = h + ep1(e) + ch(e, f, g) + kK[i] + m[i];
    uint32_t t2 = ep0(a) + maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  _state[0] += a;
  _state[1] += b;
  _state[2] += c;
  _state[3] += d;
  _state[4] += e;
  _state[5] += f;
  _state[6] += g;
  _state[7] += h;
}

void Sha256::update(const uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    _buffer[_bufferLen++] = data[i];
    if (_bufferLen == 64) {
      transform(_buffer);
      _bitLen += 512;
      _bufferLen = 0;
    }
  }
}

void Sha256::finish(uint8_t out[32]) {
  size_t i = _bufferLen;

  if (_bufferLen < 56) {
    _buffer[i++] = 0x80;
    while (i < 56) _buffer[i++] = 0x00;
  } else {
    _buffer[i++] = 0x80;
    while (i < 64) _buffer[i++] = 0x00;
    transform(_buffer);
    memset(_buffer, 0, 56);
  }

  _bitLen += static_cast<uint64_t>(_bufferLen) * 8;
  for (int j = 0; j < 8; j++) {
    _buffer[63 - j] = static_cast<uint8_t>(_bitLen >> (8 * j));
  }
  transform(_buffer);

  for (i = 0; i < 4; i++) {
    for (int s = 0; s < 8; s++) {
      out[i + s * 4] = static_cast<uint8_t>((_state[s] >> (24 - i * 8)) & 0xff);
    }
  }
}

void Sha256::hash(const uint8_t* data, size_t len, uint8_t out[32]) {
  Sha256 sha;
  sha.update(data, len);
  sha.finish(out);
}

void bytesToHexUpper(const uint8_t* data, size_t len, char* out, size_t outLen) {
  static const char kHex[] = "0123456789ABCDEF";
  size_t need = len * 2 + 1;
  if (outLen < need) {
    if (outLen > 0) out[0] = 0;
    return;
  }
  for (size_t i = 0; i < len; i++) {
    out[i * 2] = kHex[(data[i] >> 4) & 0x0f];
    out[i * 2 + 1] = kHex[data[i] & 0x0f];
  }
  out[len * 2] = 0;
}

}  // namespace fry
