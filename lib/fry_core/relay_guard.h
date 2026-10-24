#pragma once
// Peer-source guard for the ESP32 SOCKS5 relay (src/esp32/vpn_wireguard.cpp).
//
// The relay used to listen on INADDR_ANY, so any host on the device's uplink could use it as an
// open proxy. It now binds to the device's own WireGuard address and admits exactly two kinds of
// source, dropping everything else before a slot or a buffer is spent on it:
//   (a) an address inside the device's own tunnel subnet, when the provisioned prefix leaves room
//       for a peer beside the device (/8../31);
//   (b) the WireGuard SERVER's own tunnel address, a /32 taken from the provisioned allowed-ips.
// (b) is what makes the relay reachable on the fleet: WG1/hardwareapi provision every device with a
// bare /32 (e.g. 10.77.0.2/32) and the server with its own /32 (e.g. 10.77.0.1/32), so the device's
// subnet contains no peer at all and the server is the legitimate client. A /32 device with no
// server address would admit nobody, and the relay then does not listen at all rather than bind a
// port it can never serve.
//
// Everything here is pure C++ (no Arduino, no lwIP, no clock) so it runs under `pio test -e native`.
// Address convention: host order with bit 31 the first dotted octet, exactly what
// fry::parseIpv4Cidr() returns. The shim converts (ntohl at accept, htonl on bind).
#include <cstdint>

#include "wg_provision.h"

namespace fry_relay {

// A tunnel prefix wider than /8 is not a tunnel: every address on the uplink would match, so the
// source guard would silently pass everything. planWgRoutes() already refuses to plan routes
// wider than /8 (wg_provision.cpp), so the same floor applies here.
constexpr int kMinTunnelPrefix = 8;

// /31 is the narrowest prefix that still holds a peer next to the device; a /32 is the device
// alone (see (b) above for how such a device is still reachable).
constexpr int kMaxSubnetPrefix = 31;

// True when `ip` shares the subnet of `deviceIp`/`prefix`, i.e. an address a tunnel peer must have
// to reach this device's relay. The device's own address counts as inside.
inline bool ipInSubnet(uint32_t ip, uint32_t deviceIp, int prefix) {
  const uint32_t mask = fry::prefixToMask(prefix);
  return (ip & mask) == (deviceIp & mask);
}

// A prefix that leaves room for at least one peer beside the device.
inline bool prefixAdmitsPeers(int prefix) {
  return prefix >= kMinTunnelPrefix && prefix <= kMaxSubnetPrefix;
}

struct GuardConfig {
  uint32_t deviceIp = 0;  // host order, bit 31 = first octet
  int prefix = 32;        // as provisioned
  uint32_t serverIp = 0;  // the WG server's own tunnel address, 0 = unknown
};

// The relay runs when the guard can name at least one legitimate client. Nothing is admitted by
// default: with neither a usable prefix nor a server address there is no client to serve.
inline bool relayEnabled(const GuardConfig& g) {
  return prefixAdmitsPeers(g.prefix) || g.serverIp != 0;
}

// The one decision the accept path makes. Fails closed: anything that is neither the server's own
// tunnel address nor inside the device's tunnel subnet is refused.
inline bool peerAdmitted(uint32_t src, const GuardConfig& g) {
  if (g.serverIp != 0 && src == g.serverIp) return true;
  return prefixAdmitsPeers(g.prefix) && ipInSubnet(src, g.deviceIp, g.prefix);
}

// Picks the WireGuard server's own tunnel address out of the persisted `wgAllowed` CSV (the planned
// allowed-ips list: ';'-separated "a.b.c.d/nn" entries): the first /32 that is not this device's
// own tunnel address. A /32 is the only shape that names a single tunnel endpoint; the wider
// entries are routes, not peers, and planWgRoutes() falls back to the device's own /32 when nothing
// else survives, which is why the device's address must be skipped here.
// Returns 0 when there is none, in which case the relay needs a usable prefix.
inline uint32_t pickServerTunnelAddress(const char* csv, uint32_t deviceIp) {
  if (csv == nullptr) return 0;
  const char* p = csv;
  while (*p != 0) {
    const char* end = p;
    while (*end != 0 && *end != ';') end++;
    const size_t len = static_cast<size_t>(end - p);
    char entry[20];  // formatIpv4Cidr writes at most 18 characters + NUL
    if (len > 0 && len < sizeof(entry)) {
      for (size_t i = 0; i < len; i++) entry[i] = p[i];
      entry[len] = 0;
      uint32_t ip = 0;
      int prefix = 0;
      if (fry::parseIpv4Cidr(entry, &ip, &prefix) && prefix == 32 && ip != deviceIp) return ip;
    }
    if (*end == 0) break;
    p = end + 1;
  }
  return 0;
}

// Saturating increment for the drop counter: a bench counter that wraps would read as "no drops"
// right after the run that mattered. Stops at UINT32_MAX.
inline void bumpSaturating(uint32_t& counter) {
  if (counter != 0xFFFFFFFFu) counter++;
}

}  // namespace fry_relay
