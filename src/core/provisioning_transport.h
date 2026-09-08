#pragma once
// Chip-agnostic provisioning transport interface. Exactly one implementation is compiled per
// chip family (build_src_filter in platformio.ini excludes the other chip's src/ subtree):
// src/esp32/ble_provisioning.cpp (NimBLE GATT, PROTOCOL.md section 1) or
// src/esp8266/wifi_provisioning.cpp (SoftAP + captive HTTP, PROTOCOL.md section 3).
// Both drive the SAME fry::ProvisioningFsm (lib/fry_core) and expose the SAME status/error
// codes (PROTOCOL.md section 2) through whichever surface the chip supports.
#include <Arduino.h>

#include "provisioning_fsm.h"

namespace fry_provisioning {

// Starts advertising (BLE) or the softAP + DNS + HTTP server (WiFi), using the already-computed
// device name and miner key. If fry_config already has WiFi + wallet persisted from a prior
// session, this still initializes the transport (harmless) but the caller should skip straight
// to connecting.
void init(const char* deviceName, const char* minerKey);

// Pumps chip-specific I/O (DNS catch-all, HTTP handleClient; NimBLE runs its own background
// task and needs no polling here, but the call is safe/cheap either way). Call every loop().
void loop();

fry::ProvState state();
fry::ProvErr lastError();

// True exactly while state() == Connecting (PROTOCOL.md state 2) — the boot sequence's cue to
// read the newly-persisted WiFi credentials from fry_config and attempt the join.
bool readyToConnect();

// Feedback events from the WiFi join / hardwareapi registration, forwarded into the FSM so the
// status characteristic / GET /status reflects the real outcome.
void notifyWifiUp();
void notifyWifiAuthFail();
void notifyWifiNoIp();
void notifyApiOk();
void notifyApiFail();

// Tears down the transport once no longer needed (ESP8266: AP_TEARDOWN_MS after Connected, per
// PROTOCOL.md section 3; ESP32 BLE has no mandated teardown and this is a no-op there).
void tick();

}  // namespace fry_provisioning
