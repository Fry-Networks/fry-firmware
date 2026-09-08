#pragma once
// Chip-agnostic WiFi station connect/maintain interface. ESP8266 needs several
// hardware-specific workarounds (forced 802.11g PHY, softAP teardown before STA, scan-then-
// match-by-BSSID) that ESP32's WiFi stack does not; each chip has its own implementation under
// src/esp32/wifi_connect.cpp and src/esp8266/wifi_connect.cpp behind this shared interface.
#include <Arduino.h>

#include "provisioning_fsm.h"

namespace fry_wifi {

// Blocks up to timeoutMs attempting to join ssid/pass. Returns true on success; on failure,
// *errOut is set to WifiAuth, NoIp, or WifiAuth as a fallback for an undiagnosed failure.
bool connect(const char* ssid, const char* pass, uint32_t timeoutMs, fry::ProvErr* errOut);

bool isConnected();
String localIp();
int8_t rssi();

// Reconnect watchdog — call every loop() once connect() has succeeded at least once.
void maintain();

}  // namespace fry_wifi
