#pragma once
// hardwareapi client per PROTOCOL.md section 5. Chip-agnostic — relies on the http_tls.h
// per-chip TLS helper, fry_config for the persisted device token, and fry_wifi for RSSI.
#include <Arduino.h>

namespace fry_hwapi {

// POST /installations/{miner_key}/installations/{install_id}. Retries on transport errors and
// 5xx only (never 4xx), 2/4/8s backoff, up to 3 retries. Persists the returned device_token.
bool registerInstallation();

// POST/PATCH /installations/{miner_key}/leases/{install_id} {"lease_seconds":LEASE_SECONDS}.
bool renewLease();

// PUT /PoC/{miner_key}/hardware {"document":{...}}. Requires NTP to already be synced.
// Returns the raw HTTP status code (<=0 for a transport error) so callers can log it verbatim.
int putPoc();

// GET /versions/IOTVPN?platform=<os>. Returns the raw JSON body in outJson on 2xx.
bool getVersions(String& outJson);

// Blocks (bounded) until NTP time looks plausible. Call once before the first PoC.
bool ensureNtpSynced(uint32_t timeoutMs = 15000);

// Drives the INSTALL_HEARTBEAT_MS / POC_INTERVAL_MS cadence. Call every loop() once WiFi is
// connected. This is also installed as the strong override of fry_trigger_register_now(),
// fry_trigger_poc_now() and fry_trigger_report_loop_tick() (see trigger_hooks.h).
void tick();

}  // namespace fry_hwapi
