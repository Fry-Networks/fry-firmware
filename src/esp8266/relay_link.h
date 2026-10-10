#pragma once
// ESP8266 relay link (IV5 G-3/B5): one outbound WebSocket to hardwareapi over which the server
// sends SOCKS5 CONNECT probes to a Fry-owned echo endpoint, so the server can observe this
// board's relay. Protocol and destination policy: lib/fry_core/relay_proto.h. The LAN :1080
// relay (vpn_socks5.cpp) is separate and unchanged.
namespace fry_relay {

// Arms the link; the first connect happens on a later tick() once Wi-Fi is up.
void begin();

// Call every loop(). Does at most one frame and one upstream read per call.
void tick();

// Drops the link and holds it down until resume() - the OTA check calls this to give the
// GitHub TLS path its 36 KB block (include/config.h HEAP_GATE_OTA_BLOCK).
void pause();
void resume();

}  // namespace fry_relay
