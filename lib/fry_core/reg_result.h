#pragma once
// hardwareapi registration outcome: which status code it is reported as, when to try again, and
// what the log line says (PROTOCOL.md section 11.2). Pure C++ so the native suite pins it; the
// HTTP call itself stays in src/core/hardwareapi_client.cpp.
#include <cstddef>
#include <cstdint>

#include "provisioning_fsm.h"

namespace fry {

enum class RegClass : uint8_t {
  Ok,                // 2xx
  Unauthorized,      // 401 - key unknown to the server, or a legacy IOT- key
  Forbidden,         // 403
  Conflict,          // 409 - key active on another install
  OtherClientError,  // any other 4xx except 429
  Unreachable,       // transport error, 5xx, 429, or anything else unexpected
};

RegClass classifyRegistration(int http);

// Ok -> None, then Reg401 / Reg403 / Reg409 / RegOther4xx / Unreachable.
ProvErr regClassProvErr(RegClass c);

// True only for Unreachable: one quick retry inside the same attempt. A 4xx is an answer, and
// asking again seconds later gets the same answer.
bool regClassRetryQuickly(RegClass c);

// Delay before the next registration attempt after an outcome of class `c`, where
// `consecutiveFailures` counts this failure (0 reads as 1). Unreachable: 60 s, doubling per
// consecutive failure, capped at 3600 s. Any 4xx: 3600 s. Ok: 3600 s, the hourly heartbeat.
uint32_t nextRegisterDelayMs(RegClass c, uint32_t consecutiveFailures);

// One short owner-facing explanation per class, for the serial log line.
const char* regClassText(RegClass c);

// Copies a server-supplied "detail"/"error" string for logging: at most 120 characters, printable
// ASCII only ('"' -> '\'', '\\' -> '/', anything else unprintable -> '?'), and every key-shaped
// token (FEM-/IOT- followed by 8+ alphanumerics, or `minerKey` itself) cut to prefix + 2 chars +
// "...". Always NUL-terminates; returns the length written.
size_t sanitizeServerDetail(const char* in, const char* minerKey, char* out, size_t outCap);

}  // namespace fry
