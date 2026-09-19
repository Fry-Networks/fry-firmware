#pragma once

// Periodic device telemetry -> POST /measurements/<minerKey>.
//
// Until 2026-09-18 this firmware had no /measurements client at all, which is why the server
// side had never persisted a single evidenceType='telemetry' row: there was no producer, not a
// broken consumer.
//
// Auth is the SHARED bearer (FRY_API_TOKEN), not the per-device token. /measurements is the one
// endpoint in this firmware that is gated by verify_bearer_token_general on ZEUS00 — mirrored in
// legacy-telemetry.ts, which compares the presented token against API_BEARER_TOKEN and answers
// 401 on any mismatch. A per-device token can therefore never satisfy it; sending one was
// measured on hardware as a flat "post failed http=401" once per interval, forever.
//
// The per-device token is still read, but purely as a READINESS signal: it exists only after a
// successful registration, which is also when the server has a device row this sample can be
// attributed to. Posting earlier is accepted and then dropped as "unknown_install".
//
// Conditions that skip a cycle silently rather than failing:
//   * not registered yet — no device token persisted, so the server has nothing to attribute a
//     sample to;
//   * no FRY_API_TOKEN compiled in (the default for a local build — CI injects it) — a POST
//     could only earn a 401, so the cycle is skipped and said once;
//   * empty install id or miner key — nothing the server could attribute the sample to;
//   * insufficient TOTAL free heap (HEAP_GATE_OTA). There is deliberately no contiguous-block
//     requirement: this is a ~250-byte POST to a peer that honours MFLN, so beginHttpsUrl()
//     drops BearSSL to 512/512 when the big path is unaffordable — exactly what registration,
//     lease renewal and PoC already rely on, and none of those gate on heap at all. Imposing
//     HEAP_GATE_OTA_BLOCK here refused every cycle on a board that was registering successfully
//     over HTTPS at the same moment;
//   * clock not NTP-synced — a 1970 timestamp would silently mis-date the sample.
namespace fry_telemetry {

// Drives TELEMETRY_INTERVAL_MS internally; safe to call every loop. No-op until due.
void tick();

}  // namespace fry_telemetry
