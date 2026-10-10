#include "ws_frame.h"

#include <cstdlib>
#include <cstring>
#include <strings.h>

#include "sha1.h"

namespace fry {

namespace {

bool isControl(uint8_t opcode) { return (opcode & 0x8) != 0; }

bool isKnownOpcode(uint8_t opcode) {
  return opcode == kWsContinuation || opcode == kWsText || opcode == kWsBinary ||
         opcode == kWsClose || opcode == kWsPing || opcode == kWsPong;
}

const char kGuid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";  // RFC 6455 section 1.3

}  // namespace

size_t wsEncodeClientFrame(uint8_t opcode, const uint8_t* payload, size_t len,
                           const uint8_t mask[4], uint8_t* out, size_t outCap) {
  if (len > kWsMaxPayload) return 0;
  if (isControl(opcode) && len > 125) return 0;
  const size_t header = (len < 126) ? 6 : 8;
  if (outCap < header + len) return 0;

  out[0] = static_cast<uint8_t>(0x80 | (opcode & 0x0F));
  if (len < 126) {
    out[1] = static_cast<uint8_t>(0x80 | len);
  } else {
    out[1] = 0x80 | 126;
    out[2] = static_cast<uint8_t>(len >> 8);
    out[3] = static_cast<uint8_t>(len & 0xFF);
  }
  memcpy(out + header - 4, mask, 4);
  for (size_t i = 0; i < len; i++) out[header + i] = payload[i] ^ mask[i % 4];
  return header + len;
}

WsParse wsParseServerHeader(const uint8_t* data, size_t len, size_t maxPayload, WsFrameHeader& out) {
  if (len < 2) return WsParse::NeedMoreData;
  const bool fin = (data[0] & 0x80) != 0;
  const uint8_t rsv = data[0] & 0x70;
  const uint8_t opcode = data[0] & 0x0F;
  const bool masked = (data[1] & 0x80) != 0;
  const uint8_t len7 = data[1] & 0x7F;

  // The link never fragments, never negotiates extensions, and a server never masks.
  if (rsv || masked || !fin || opcode == kWsContinuation || !isKnownOpcode(opcode)) {
    return WsParse::Malformed;
  }
  if (isControl(opcode) && len7 > 125) return WsParse::Malformed;
  if (len7 == 127) return WsParse::Malformed;  // 64-bit lengths are far beyond kWsMaxPayload

  size_t payloadLen = len7;
  size_t headerLen = 2;
  if (len7 == 126) {
    if (len < 4) return WsParse::NeedMoreData;
    payloadLen = (static_cast<size_t>(data[2]) << 8) | data[3];
    headerLen = 4;
  }
  if (payloadLen > maxPayload) return WsParse::TooBig;

  out.opcode = opcode;
  out.payloadLen = payloadLen;
  out.headerLen = headerLen;
  return WsParse::Ok;
}

size_t base64Encode(const uint8_t* in, size_t len, char* out, size_t outCap) {
  static const char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const size_t need = 4 * ((len + 2) / 3);
  if (outCap < need + 1) return 0;
  size_t o = 0;
  for (size_t i = 0; i < len; i += 3) {
    const uint32_t b0 = in[i];
    const uint32_t b1 = (i + 1 < len) ? in[i + 1] : 0;
    const uint32_t b2 = (i + 2 < len) ? in[i + 2] : 0;
    const uint32_t v = (b0 << 16) | (b1 << 8) | b2;
    out[o++] = kAlphabet[(v >> 18) & 63];
    out[o++] = kAlphabet[(v >> 12) & 63];
    out[o++] = (i + 1 < len) ? kAlphabet[(v >> 6) & 63] : '=';
    out[o++] = (i + 2 < len) ? kAlphabet[v & 63] : '=';
  }
  out[o] = 0;
  return o;
}

bool wsAcceptFor(const char* clientKeyB64, char* out, size_t outCap) {
  if (outCap < 29) return false;
  Sha1 sha;
  sha.update(reinterpret_cast<const uint8_t*>(clientKeyB64), strlen(clientKeyB64));
  sha.update(reinterpret_cast<const uint8_t*>(kGuid), sizeof(kGuid) - 1);
  uint8_t digest[20];
  sha.finish(digest);
  return base64Encode(digest, sizeof(digest), out, outCap) == 28;
}

WsUpgradeResponse::WsUpgradeResponse(const char* expectedAccept)
    : _expectedAccept(expectedAccept) {}

WsUpgradeResponse::Result WsUpgradeResponse::feedLine(const char* line, size_t rawLen) {
  _bytes += rawLen;
  _lines++;
  if (_bytes > kMaxBytes || _lines > kMaxLines) return Result::TooLong;

  if (_status < 0) {
    if (strncmp(line, "HTTP/1.1 ", 9) != 0) return Result::Malformed;
    _status = atoi(line + 9);
    return Result::NeedMore;
  }
  if (line[0] == 0) {  // end of headers
    if (_status != 101) return Result::Refused;
    return _acceptOk ? Result::Ok : Result::Malformed;
  }
  if (strncasecmp(line, "Sec-WebSocket-Accept:", 21) == 0) {
    const char* v = line + 21;
    while (*v == ' ' || *v == '\t') v++;
    _acceptOk = _expectedAccept && strcmp(v, _expectedAccept) == 0;
  }
  return Result::NeedMore;
}

}  // namespace fry
