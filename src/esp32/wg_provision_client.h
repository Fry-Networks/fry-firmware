#pragma once
// Server-driven WireGuard provisioning fetch, ESP32-family only (WireGuard itself is not built
// for ESP8266 — see platformio.ini's build_src_filter). Mirrors the shape of
// src/core/hardwareapi_client.cpp (same beginHttpsUrl/ArduinoJson/backoff conventions), with one
// deliberate divergence: the Authorization header here NEVER falls back to a compiled bootstrap
// token — only fry_config::getDeviceToken() is used, so a board can mint a WireGuard peer only
// once it has actually registered.
#include <Arduino.h>

namespace fry_wg_provision {

// Drives the fetch-and-provision attempt on its own backoff schedule
// (lib/fry_core/wg_provision.h's classifyWgFetch/wgRetryDelayMs). A no-op once
// fry_config::hasVpnConfig() is already true — this never re-provisions an existing config.
// Call every loop() once WiFi is connected; src/esp32/vpn_wireguard.cpp's tick() does this.
void tick();

}  // namespace fry_wg_provision
