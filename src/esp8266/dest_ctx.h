#pragma once
// The board's own addressing for lib/fry_core/dest_filter.h, shared by the LAN SOCKS5 relay
// (vpn_socks5.cpp) and the outbound relay link (relay_link.cpp).
#include <ESP8266WiFi.h>

#include "dest_filter.h"

namespace fry_dest {

inline uint32_t hostOrder(const IPAddress& ip) {
  return (static_cast<uint32_t>(ip[0]) << 24) | (static_cast<uint32_t>(ip[1]) << 16) |
         (static_cast<uint32_t>(ip[2]) << 8) | static_cast<uint32_t>(ip[3]);
}

inline fry::DestCtx ctx() {
  fry::DestCtx c;
  c.selfIp = hostOrder(WiFi.localIP());
  c.selfMask = hostOrder(WiFi.subnetMask());
  c.gateway = hostOrder(WiFi.gatewayIP());
  return c;
}

}  // namespace fry_dest
