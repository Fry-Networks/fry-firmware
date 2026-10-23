#pragma once
// Chip-agnostic VPN endpoint interface. ESP32/S3/C3 run WireGuard (src/esp32/vpn_wireguard.cpp);
// ESP8266 runs a single-client SOCKS5 relay (src/esp8266/vpn_socks5.cpp) since it has no spare
// heap/CPU for a WireGuard handshake. Both feed the PROTOCOL.md section 9 [health] line's
// vpn=<up|down> and relayed=<bytes> fields through the same two accessors.
#include <Arduino.h>

namespace fry_vpn {

// Starts the endpoint using whatever config fry_config has persisted (fry_vpn namespace).
void init();

// Call every loop() — pumps the relay / checks handshake state. Never blocks for long.
void tick();

bool isUp();
uint32_t relayedBytes();

// Relay connect-latency summary for the installation heartbeat
// (lib/fry_core/heartbeat_fields.h addRelayLatencyFields). Implemented - and called - only by the
// ESP32 endpoint (src/esp32/vpn_wireguard.cpp), from lib/fry_core/relay_latency.h's ring of the
// last kLatencySamples successful upstream connects. The ESP8266 endpoint has no such ring and
// nothing on that chip calls this, so its object file stays exactly as it was; the ESP8266's
// heartbeat never carries the three keys.
struct RelayLatency {
  uint32_t p50Ms;
  uint32_t p95Ms;
  uint32_t samples;
};
RelayLatency relayLatency();

}  // namespace fry_vpn
