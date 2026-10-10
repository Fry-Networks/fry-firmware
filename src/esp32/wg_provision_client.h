#pragma once
// Server-driven WireGuard provisioning fetch, ESP32-family only (WireGuard itself is not built
// for ESP8266 — see platformio.ini's build_src_filter). Mirrors the shape of
// src/core/hardwareapi_client.cpp (same beginHttpsUrl/ArduinoJson/backoff conventions), with one
// deliberate divergence: the Authorization header here NEVER falls back to a compiled bootstrap
// token — only fry_config::getDeviceToken() is used, so a board can mint a WireGuard peer only
// once it has actually registered.
#include <Arduino.h>

#include "wg_recover.h"

namespace fry_wg_provision {

// Drives the fetch-and-provision attempt on its own backoff schedule
// (lib/fry_core/wg_provision.h's classifyWgFetch/wgRetryDelayMs). A no-op once
// fry_config::hasVpnConfig() is already true — this never re-provisions an existing config.
// Call every loop() once WiFi is connected; src/esp32/vpn_wireguard.cpp's tick() does this.
void tick();

// True while a deferred attempt's backoff (401/403/429/5xx/...) is still running. The dead-tunnel
// recovery (src/esp32/vpn_wireguard.cpp) never clears the config inside one.
bool backoffActive();

// Stage B of the dead-tunnel recovery (lib/fry_core/wg_recover.h): arm ONE rotation attempt that
// the next tick() performs even though hasVpnConfig() is true. It POSTs a NEW keypair (same
// install_id) and replaces the cached config only after a validated 2xx; on any failure the
// existing config is untouched. rotationState() is Pending until tick() has finished the attempt,
// then Committed or Failed. A failure leaves the normal backoff (backoffActive) in place.
void requestRotation();
fry::WgRotationState rotationState();

}  // namespace fry_wg_provision
