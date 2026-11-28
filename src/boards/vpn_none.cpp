// Built only by the Pico / BK7231N envs (platformio.boards.ini defines FRY_BOARDS_PORT); the ESP envs compile all of src/.
#if defined(FRY_BOARDS_PORT)
// src/core/vpn_relay.h for the boards that do not run a relay endpoint. The SOCKS5 relay (ESP8266) and WireGuard (ESP32 family)
// are the ESP-side products of the relay; these boards register, heartbeat, lease, report PoC and update, and report the relay
// honestly as down (the [health] line prints vpn=down relayed=0).
#include "../core/vpn_relay.h"

namespace fry_vpn {

void init() {}
void tick() {}
bool isUp() { return false; }
uint32_t relayedBytes() { return 0; }
RelayLatency relayLatency() { return RelayLatency{0, 0, 0}; }

}  // namespace fry_vpn

#include "../core/trigger_hooks.h"

// Strong override of the weak "VPN module not built yet" stub in trigger_stubs.cpp: nothing to start, and nothing to announce.
extern "C" void fry_trigger_start_vpn() { fry_vpn::init(); }
#endif  // FRY_BOARDS_PORT
