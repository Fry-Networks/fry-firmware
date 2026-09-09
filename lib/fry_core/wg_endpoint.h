#pragma once
// Pure "host:port" splitter for the WireGuard endpoint, zero Arduino includes.
//
// PROTOCOL.md section 7 sends set_wg with `"endpoint":"host:port"`, but esp_wireguard hands
// wireguard_config_t::endpoint straight to lwIP's dns_gethostbyname(), which cannot parse a
// trailing ":port". A composite string therefore never matches an IP literal and falls back to
// an asynchronous hostname lookup that can never resolve, so esp_wireguard_connect() returns
// ESP_ERR_RETRY (0x201) forever. Splitting host from port before storage is what makes an IP
// literal resolve synchronously.
//
// Unit tested standalone under `pio test -e native`.
#include <cstddef>
#include <cstdint>

namespace fry {

// Longest host we accept. Comfortably covers an IPv4 literal, a bracketed IPv6 literal and a
// fully qualified domain name (RFC 1035 caps a name at 253 characters).
constexpr size_t kWgHostCap = 254;

struct WgEndpoint {
  bool ok = false;        // input was well formed
  bool hasPort = false;   // input carried an explicit :port
  uint16_t port = 0;      // meaningful only when hasPort
  char host[kWgHostCap] = {};
};

// Splits "host", "host:port", "[v6]" or "[v6]:port". A bare IPv6 literal with no brackets is
// ambiguous (every separator is a colon), so it is returned whole with hasPort false rather
// than guessed at. Returns ok=false for empty input, an over-long host, or a non-numeric or
// out-of-range port.
WgEndpoint parseWgEndpoint(const char* in);

}  // namespace fry
