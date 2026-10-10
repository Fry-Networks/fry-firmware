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

// T3 re-provision (stage B of the dead-tunnel recovery, and the T7 post-OTA refresh): arm ONE
// attempt that the next tick() performs even though hasVpnConfig() is true. It POSTs the SAME
// install_id and the SAME WG keypair (never a new one; a board without a keypair fails the attempt)
// and does NOT touch the cached config: a validated 2xx is held in RAM as a PendingConfig.
// rotationState() is Pending until tick() has finished the attempt, then Committed (a pending
// config is ready for takePending) or Failed. A failure leaves the T5 backoff (backoffActive).
void requestRotation();
fry::WgRotationState rotationState();

// A refreshed config awaiting its first handshake. RAM-only: a reset drops it and the old config
// is used, which is the point (persist only after a handshake).
struct PendingConfig {
  char serverPub[45] = {};
  bool hasPsk = false;
  char psk[45] = {};
  char endpointHost[64] = {};
  uint16_t endpointPort = 0;
  char addressCidr[20] = {};
  char allowedCsv[80] = {};
  uint32_t keepaliveS = 25;
};
bool takePending(PendingConfig& out);  // true once per Committed attempt
// Called after the pending config handshook: writes it to fry_vpn (same keypair, nothing minted).
void commitPending(const PendingConfig& cfg);
// Called when the pending config did not handshake in time: schedules a T5 backoff.
void noteTrialFailed();

}  // namespace fry_wg_provision
