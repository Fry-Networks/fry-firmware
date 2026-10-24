#pragma once
// Peer-source guard for the ESP32 SOCKS5 relay (src/esp32/vpn_wireguard.cpp).
//
// The relay used to listen on INADDR_ANY, so any host on the device's uplink could use it as an
// open proxy, and a tunnel it was bound to was only a convention. It now binds to the device's own
// WireGuard address and drops every peer accepted from outside that address's subnet before the
// slot is even allocated. Both halves of that decision live here so they run under
// `pio test -e native`: no Arduino, no lwIP, no clock.
//
// Address convention: both `ip` values are HOST order with bit 31 the first dotted octet, which is
// exactly what fry::parseIpv4Cidr() returns. The shim converts (ntohl at accept, htonl on bind).
#include <cstdint>

#include "wg_provision.h"

namespace fry_relay {

// A tunnel prefix wider than /8 is not a tunnel: every address on the uplink would match, so the
// source guard would silently pass everything. planWgRoutes() already refuses to plan routes
// wider than /8 (wg_provision.cpp), so the same floor applies here.
constexpr int kMinTunnelPrefix = 8;

// A /32 tunnel address is this device alone: no peer can be inside its subnet, so the relay would
// bind a port and then drop every tunnel peer that reached it. That is worse than not running (an
// open port that can never serve), so a /32 disables the relay with one log line instead. A /31 is
// the smallest prefix that can hold a peer next to the device.
constexpr int kMaxTunnelPrefix = 31;

// Whether a provisioned tunnel prefix leaves room for at least one peer, i.e. whether the relay can
// admit anyone at all. Both ends fail closed: no listener rather than an unguarded one.
inline bool tunnelPrefixUsable(int prefix) {
  return prefix >= kMinTunnelPrefix && prefix <= kMaxTunnelPrefix;
}

// True when `ip` shares the subnet of `deviceIp`/`prefix`, i.e. the address a tunnel peer must have
// to reach this device's relay. The device's own address counts as inside.
inline bool ipInSubnet(uint32_t ip, uint32_t deviceIp, int prefix) {
  const uint32_t mask = fry::prefixToMask(prefix);
  return (ip & mask) == (deviceIp & mask);
}

// Saturating increment for the drop counter: a bench counter that wraps would read as "no drops"
// right after the run that mattered. Stops at UINT32_MAX.
inline void bumpSaturating(uint32_t& counter) {
  if (counter != 0xFFFFFFFFu) counter++;
}

}  // namespace fry_relay
