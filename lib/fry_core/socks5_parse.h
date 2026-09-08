#pragma once
// Pure C++ SOCKS5 greeting / CONNECT-request parser (RFC 1928), zero Arduino includes.
// Used by src/esp8266/vpn_socks5.cpp (T6) against bytes read off the client socket, and unit
// tested standalone under `pio test -e native`. This server only ever offers/accepts NO AUTH
// (0x00) and only ever accepts the CONNECT command against IPv4 or domain-name targets —
// BIND, UDP ASSOCIATE and IPv6 are out of scope for the single-client relay.
#include <cstddef>
#include <cstdint>

namespace fry {

enum class Socks5Result : uint8_t {
  Ok = 0,
  NeedMoreData = 1,
  UnsupportedMethod = 2,
  UnsupportedCommand = 3,
  UnsupportedAddrType = 4,
  Malformed = 5,
};

enum class Socks5AddrType : uint8_t {
  IPv4 = 1,
  Domain = 3,
  IPv6 = 4,
};

struct Socks5Greeting {
  uint8_t version = 0;
  uint8_t nmethods = 0;
  bool noAuthOffered = false;
};

// Parses the initial client greeting: VER | NMETHODS | METHODS[NMETHODS].
// On NeedMoreData, `consumed` is untouched and the caller should read more bytes and retry.
// On any other result, `consumed` is the number of bytes belonging to this message so the
// caller can advance its buffer even when rejecting the connection.
Socks5Result parseGreeting(const uint8_t* data, size_t len, Socks5Greeting& out, size_t& consumed);

struct Socks5ConnectRequest {
  uint8_t version = 0;
  uint8_t command = 0;  // 0x01 = CONNECT
  Socks5AddrType addrType = Socks5AddrType::IPv4;
  char host[256] = {0};  // dotted-decimal IPv4 or NUL-terminated domain name
  uint16_t port = 0;
};

// Parses the CONNECT request: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT.
Socks5Result parseConnectRequest(const uint8_t* data, size_t len, Socks5ConnectRequest& out,
                                  size_t& consumed);

}  // namespace fry
