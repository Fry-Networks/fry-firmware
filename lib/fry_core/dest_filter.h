#pragma once
// Relay destination filter: the one shared check applied AFTER DNS resolution and BEFORE every
// outbound connect of the WireGuard-side SOCKS5 relay (src/esp32/vpn_wireguard.cpp), the ESP8266
//
// Blocked: 0.0.0.0/8, 127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10, 224/4, 240/4
// (which includes 255.255.255.255), ::, ::1, fc00::/7, fe80::/10, ff00::/8, and the board's own
// subnet and gateway (DestCtx). An IPv4-mapped IPv6 address (::ffff:a.b.c.d) follows the IPv4 rules.
#include <cstddef>
#include <cstdint>

namespace fry {

// All host-order (bit 31 = first octet). A zero field means "unknown": nothing extra is blocked
// for it.
struct DestCtx {
  uint32_t selfIp = 0;
  uint32_t selfMask = 0;
  uint32_t gateway = 0;
};

struct DestCounters {
  uint32_t allowed = 0;
  uint32_t blocked = 0;
};

// Pure predicates (no counting). The V6 overload with a ctx also applies the v4 rules (and the
// board's own LAN) to an embedded IPv4: ::ffff:a.b.c.d, 64:ff9b::/96 (NAT64) and 2002::/16 (6to4).
bool destIsBlockedV4(uint32_t ipHostOrder, const DestCtx& ctx);
bool destIsBlockedV6(const uint8_t ip[16]);
bool destIsBlockedV6(const uint8_t ip[16], const DestCtx& ctx);

// Strict canonical dotted quad only (4 decimal octets 0-255, no leading zeros). Relays use it to
// get the exact IP they checked and must connect to THAT IP, never to the host string.
bool destParseV4(const char* host, uint32_t* ipHostOrder);

// Predicates plus counting: return true when the destination is ALLOWED.
bool destFilterV4(uint32_t ipHostOrder, const DestCtx& ctx);
bool destFilterV6(const uint8_t ip[16]);
bool destFilterV6(const uint8_t ip[16], const DestCtx& ctx);

// For a SOCKS5 request host. *isLiteral is true for an IP literal (canonical dotted quad or IPv6
// text) AND for any non-canonical numeric form (leading zeros, octal/hex, fewer than 4 parts, a
// single decimal number, a bad IPv6): those are returned as not allowed (counted blocked).
// *isLiteral is false for a real name: the caller must resolve it and use destFilterV4/V6 on the
// result (nothing is counted here).
bool destFilterText(const char* host, const DestCtx& ctx, bool* isLiteral);

DestCounters destCounters();
void destCountersReset();

}  // namespace fry
