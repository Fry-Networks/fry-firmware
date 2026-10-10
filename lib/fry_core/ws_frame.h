#pragma once
// Minimal RFC 6455 WebSocket framing for the ESP8266 relay link (src/esp8266/relay_link.cpp),
// zero Arduino includes so it is unit tested under `pio test -e native`.
//
// Deliberately small: the link only ever carries single-frame (FIN=1) messages whose payload is
// at most kWsMaxPayload bytes, because the TLS session under it runs on 512/512 MFLN buffers and
// the chip cannot afford to reassemble anything bigger. Fragmented, masked-by-server, RSV-flagged
// or oversized frames are refused, and the caller closes the link.
#include <cstddef>
#include <cstdint>

namespace fry {

constexpr size_t kWsMaxPayload = 512;
// 2 (base) + 2 (16-bit length) + 4 (mask) - a client frame of <= kWsMaxPayload never needs more.
constexpr size_t kWsMaxClientHeader = 8;

enum WsOpcode : uint8_t {
  kWsContinuation = 0x0,
  kWsText = 0x1,
  kWsBinary = 0x2,
  kWsClose = 0x8,
  kWsPing = 0x9,
  kWsPong = 0xA,
};

enum class WsParse : uint8_t {
  Ok = 0,
  NeedMoreData = 1,
  TooBig = 2,     // payload longer than the caller's limit
  Malformed = 3,  // RSV bits, masked server frame, fragmentation, bad control frame, 64-bit length
};

struct WsFrameHeader {
  uint8_t opcode = 0;
  size_t payloadLen = 0;
  size_t headerLen = 0;
};

// Encodes one FIN=1, masked client frame (RFC 6455 section 5.3: every client frame is masked).
// Returns the number of bytes written to `out`, or 0 when `len` > kWsMaxPayload, a control frame
// payload is > 125, or `outCap` is too small.
size_t wsEncodeClientFrame(uint8_t opcode, const uint8_t* payload, size_t len,
                           const uint8_t mask[4], uint8_t* out, size_t outCap);

// Parses the header of one server frame at the start of `data`. On Ok, the payload is
// data[headerLen .. headerLen+payloadLen) once that many bytes have arrived.
WsParse wsParseServerHeader(const uint8_t* data, size_t len, size_t maxPayload, WsFrameHeader& out);

// Standard base64 (with '=' padding). Returns chars written excluding the NUL, or 0 if `outCap`
// cannot hold the result plus its NUL.
size_t base64Encode(const uint8_t* in, size_t len, char* out, size_t outCap);

// Sec-WebSocket-Accept for a client key: base64(SHA1(key + RFC 6455 GUID)). `out` gets 28 chars
// plus NUL. Returns false only if `out` is too small.
bool wsAcceptFor(const char* clientKeyB64, char* out, size_t outCap);

// The server's answer to the upgrade request, fed one header line at a time (CR/LF stripped;
// `rawLen` = bytes the line took on the wire). Bounded: more than kMaxBytes or kMaxLines is
// TooLong, so a hostile or broken peer cannot keep the board reading. The caller also bounds
// the wall-clock time (relay_link.cpp: 10 s).
class WsUpgradeResponse {
 public:
  static constexpr size_t kMaxBytes = 2048;
  static constexpr size_t kMaxLines = 32;
  enum class Result : uint8_t {
    NeedMore,   // keep feeding lines
    Ok,         // 101 with the expected Sec-WebSocket-Accept
    Refused,    // any other status (status() says which)
    Malformed,  // no HTTP/1.1 status line, or 101 without a matching Accept
    TooLong,
  };

  explicit WsUpgradeResponse(const char* expectedAccept);
  Result feedLine(const char* line, size_t rawLen);
  int status() const { return _status; }

 private:
  const char* _expectedAccept;
  int _status = -1;
  bool _acceptOk = false;
  size_t _bytes = 0;
  size_t _lines = 0;
};

}  // namespace fry
