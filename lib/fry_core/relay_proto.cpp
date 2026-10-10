#include "relay_proto.h"

#include <cctype>
#include <cstdio>
#include <cstring>

namespace fry {

const char* const kRelayDestSuffix = ".frynetworks.com";

namespace {

// The only ports the server's probe may ask for: 7 (echo) and 443.
const uint16_t kAllowedPorts[] = {7, 443};

bool endsWithNoCase(const char* s, const char* suffix) {
  const size_t n = strlen(s), m = strlen(suffix);
  if (n < m) return false;
  for (size_t i = 0; i < m; i++) {
    if (tolower(static_cast<unsigned char>(s[n - m + i])) !=
        tolower(static_cast<unsigned char>(suffix[i]))) {
      return false;
    }
  }
  return true;
}

bool isHostnameChar(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
         c == '.';
}

size_t writeReply(uint8_t rep, uint8_t* reply, size_t replyCap) {
  // Same fixed reply as the LAN relay (src/esp8266/vpn_socks5.cpp): BND.ADDR 0.0.0.0:0.
  if (replyCap < 10) return 0;
  const uint8_t r[10] = {0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
  memcpy(reply, r, sizeof(r));
  return sizeof(r);
}

}  // namespace

bool relayDestAllowed(Socks5AddrType atyp, const char* host, uint16_t port) {
  if (atyp != Socks5AddrType::Domain || !host) return false;
  bool portOk = false;
  for (uint16_t p : kAllowedPorts) portOk = portOk || (p == port);
  if (!portOk) return false;

  const size_t n = strlen(host);
  const size_t m = strlen(kRelayDestSuffix);
  if (n <= m) return false;  // needs at least one label in front of the suffix
  for (size_t i = 0; i < n; i++) {
    if (!isHostnameChar(host[i])) return false;
  }
  if (host[0] == '.' || host[n - m - 1] == '.') return false;  // no empty label before suffix
  return endsWithNoCase(host, kRelayDestSuffix);
}

bool relayIpAllowed(uint8_t a, uint8_t b, uint8_t c, uint8_t) {
  if (a == 0 || a == 10 || a == 127) return false;
  if (a == 100 && (b & 0xC0) == 64) return false;   // 100.64.0.0/10 (CGNAT)
  if (a == 169 && b == 254) return false;           // link-local
  if (a == 172 && (b & 0xF0) == 16) return false;   // 172.16.0.0/12
  if (a == 192 && b == 168) return false;
  if (a == 192 && b == 0 && (c == 0 || c == 2)) return false;    // IETF 192.0.0/24, TEST-NET-1
  if (a == 198 && (b & 0xFE) == 18) return false;                // 198.18.0.0/15 benchmarking
  if (a == 198 && b == 51 && c == 100) return false;             // TEST-NET-2
  if (a == 203 && b == 0 && c == 113) return false;              // TEST-NET-3
  if (a >= 224) return false;                       // multicast, reserved, broadcast
  return true;
}

void RelaySocksSession::reset() {
  _state = State::Greeting;
  _bufLen = 0;
  _req = Socks5ConnectRequest();
}

RelaySocksSession::Action RelaySocksSession::feed(const uint8_t* data, size_t len, uint8_t* reply,
                                                  size_t replyCap, size_t& replyLen,
                                                  bool& forward) {
  replyLen = 0;
  forward = false;

  if (_state == State::Relaying) {
    forward = true;
    return Action::None;
  }
  if (_state != State::Greeting && _state != State::AwaitingConnect) {
    // Connecting (no reply sent yet) or Closed: the server spoke out of turn.
    _state = State::Closed;
    return Action::Close;
  }

  // Bounded: anything that would not fit can only be a malformed request.
  if (len > sizeof(_buf) - _bufLen) {
    _state = State::Closed;
    return Action::Close;
  }
  memcpy(_buf + _bufLen, data, len);
  _bufLen += len;

  if (_state == State::Greeting) {
    Socks5Greeting greeting;
    size_t consumed = 0;
    Socks5Result r = parseGreeting(_buf, _bufLen, greeting, consumed);
    if (r == Socks5Result::NeedMoreData) return Action::None;
    if (replyCap < 2) {
      _state = State::Closed;
      return Action::Close;
    }
    reply[0] = 0x05;
    reply[1] = (r == Socks5Result::Ok) ? 0x00 : 0xFF;
    replyLen = 2;
    if (r != Socks5Result::Ok) {
      _state = State::Closed;
      return Action::Close;
    }
    memmove(_buf, _buf + consumed, _bufLen - consumed);
    _bufLen -= consumed;
    _state = State::AwaitingConnect;
    if (_bufLen == 0) return Action::None;
  }

  // AwaitingConnect. Any method reply from above stays at reply[0..1].
  Socks5ConnectRequest req;
  size_t consumed = 0;
  Socks5Result r = parseConnectRequest(_buf, _bufLen, req, consumed);
  if (r == Socks5Result::NeedMoreData) return Action::None;

  uint8_t rep = kSocksRepOk;
  if (r != Socks5Result::Ok || consumed != _bufLen) {
    rep = kSocksRepFailure;  // malformed, unsupported, or bytes before our reply
  } else if (!relayDestAllowed(req.addrType, req.host, req.port)) {
    rep = kSocksRepNotAllowed;
  }
  if (rep != kSocksRepOk) {
    replyLen += writeReply(rep, reply + replyLen, replyCap - replyLen);
    _state = State::Closed;
    return Action::Close;
  }

  _req = req;
  _bufLen = 0;
  _state = State::Connecting;
  return Action::Connect;
}

size_t RelaySocksSession::onConnectResult(uint8_t rep, uint8_t* reply, size_t replyCap) {
  if (_state != State::Connecting) return 0;
  _state = (rep == kSocksRepOk) ? State::Relaying : State::Closed;
  return writeReply(rep, reply, replyCap);
}

size_t relayBuildHello(char* out, size_t outCap, const char* version, const char* env,
                       const char* boardId, uint32_t flashReal, uint32_t flashHeader,
                       uint32_t flashId, uint32_t heapFree, uint32_t heapBlock) {
  int n = snprintf(out, outCap,
                   "{\"v\":\"%s\",\"env\":\"%s\",\"board_id\":\"%s\",\"flash_real\":%lu,"
                   "\"flash_hdr\":%lu,\"flash_id\":\"%06lx\",\"heap\":%lu,\"blk\":%lu}",
                   version, env, boardId, static_cast<unsigned long>(flashReal),
                   static_cast<unsigned long>(flashHeader),
                   static_cast<unsigned long>(flashId & 0xFFFFFF),
                   static_cast<unsigned long>(heapFree), static_cast<unsigned long>(heapBlock));
  if (n < 0 || static_cast<size_t>(n) >= outCap) {
    if (outCap) out[0] = 0;
    return 0;
  }
  return static_cast<size_t>(n);
}

}  // namespace fry
