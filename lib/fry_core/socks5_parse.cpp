#include "socks5_parse.h"

#include <cstdio>

namespace fry {

Socks5Result parseGreeting(const uint8_t* data, size_t len, Socks5Greeting& out, size_t& consumed) {
  if (len < 2) return Socks5Result::NeedMoreData;
  const uint8_t version = data[0];
  const uint8_t nmethods = data[1];
  if (len < static_cast<size_t>(2 + nmethods)) return Socks5Result::NeedMoreData;
  if (version != 0x05) return Socks5Result::Malformed;

  bool noAuth = false;
  for (uint8_t i = 0; i < nmethods; i++) {
    if (data[2 + i] == 0x00) {
      noAuth = true;
      break;
    }
  }

  out.version = version;
  out.nmethods = nmethods;
  out.noAuthOffered = noAuth;
  consumed = 2 + nmethods;
  return noAuth ? Socks5Result::Ok : Socks5Result::UnsupportedMethod;
}

Socks5Result parseConnectRequest(const uint8_t* data, size_t len, Socks5ConnectRequest& out,
                                  size_t& consumed) {
  if (len < 4) return Socks5Result::NeedMoreData;
  const uint8_t version = data[0];
  const uint8_t command = data[1];
  // data[2] is RSV, always 0x00 — not validated (harmless if a client sends garbage there).
  const uint8_t atyp = data[3];

  if (version != 0x05) return Socks5Result::Malformed;
  if (command != 0x01) return Socks5Result::UnsupportedCommand;

  if (atyp == static_cast<uint8_t>(Socks5AddrType::IPv4)) {
    const size_t need = 4 + 4 + 2;
    if (len < need) return Socks5Result::NeedMoreData;
    snprintf(out.host, sizeof(out.host), "%u.%u.%u.%u", data[4], data[5], data[6], data[7]);
    out.port = static_cast<uint16_t>((data[8] << 8) | data[9]);
    out.version = version;
    out.command = command;
    out.addrType = Socks5AddrType::IPv4;
    consumed = need;
    return Socks5Result::Ok;
  }

  if (atyp == static_cast<uint8_t>(Socks5AddrType::Domain)) {
    if (len < 5) return Socks5Result::NeedMoreData;
    const uint8_t dlen = data[4];
    const size_t need = 4 + 1 + dlen + 2;
    if (len < need) return Socks5Result::NeedMoreData;
    if (dlen >= sizeof(out.host)) return Socks5Result::Malformed;
    for (uint8_t i = 0; i < dlen; i++) out.host[i] = static_cast<char>(data[5 + i]);
    out.host[dlen] = 0;
    out.port = static_cast<uint16_t>((data[5 + dlen] << 8) | data[6 + dlen]);
    out.version = version;
    out.command = command;
    out.addrType = Socks5AddrType::Domain;
    consumed = need;
    return Socks5Result::Ok;
  }

  // IPv6 (0x04) or anything else — this relay does not support it.
  return Socks5Result::UnsupportedAddrType;
}

}  // namespace fry
