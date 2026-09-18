#pragma once

// Periodic device telemetry -> POST /measurements/<minerKey>.
//
// Until 2026-09-18 this firmware had no /measurements client at all, which is why the server
// side had never persisted a single evidenceType='telemetry' row: there was no producer, not a
// broken consumer.
//
// Auth is the PER-DEVICE token the registration response already persists
// (fry_config::setDeviceToken, NVS "fry"/"deviceToken"). The header is built inline rather than
// through hardwareapi_client's addAuthHeader(), which is file-local and unreachable from here --
// and deliberately so: addAuthHeader() falls back to the build-time FRY_API_TOKEN, and telemetry
// must never spend the bootstrap credential. No token means no POST. Nothing secret is compiled
// into the binary.
//
// Conditions that skip a cycle silently rather than failing:
//   * no device token yet — the board has not completed a registration, so there is nothing to
//     authenticate with and a POST would only earn a 401;
//   * empty install id or miner key — nothing the server could attribute the sample to;
//   * insufficient heap — total free is gated on every chip. The CONTIGUOUS-block half is
//     BearSSL-only (ESP8266 https), matching fry::otaMinContiguousBlock: a TLS handshake there
//     needs ~34-37 KB in ONE block and the OTA path needs the same memory, so telemetry yields
//     rather than being the allocation that starves an update. Applying that block requirement
//     on ESP32 would gate out every cycle forever (see heap_gate.h);
//   * clock not NTP-synced — a 1970 timestamp would silently mis-date the sample.
namespace fry_telemetry {

// Drives TELEMETRY_INTERVAL_MS internally; safe to call every loop. No-op until due.
void tick();

}  // namespace fry_telemetry
