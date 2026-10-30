#pragma once
// Rules for the stale-token self-heal: boot recovery, the clock it trusts, the retry's reply and the per-boot latch.
// Pure C++ so the native suite executes them; the NVS and HTTP work they gate stays in src/core/hardwareapi_client.cpp.
// None of these changes the heal's trigger (stale_token_heal.h isStaleTokenSignature), its non-default
// apiBase condition, or its per-boot and per-6-h bounds for the first 6 h of an uptime.
#include <cstddef>
#include <cstdint>

#include "stale_token_heal.h"

namespace fry {

// Boot recovery. What it does with the shadow pair, given which live values are present. Only a COMPLETE live
// pair makes the shadows leftovers of an unconfirmed heal. An empty live pair (crash after the clear) or a half
// pair (a restore that wrote the id and not the token, or a crash after the new id was persisted) is put back
// from the shadows: dropping them on "either value present" threw away the only complete copy of the token.
enum class PairRecovery : uint8_t { DropShadows, RestoreShadows };

inline PairRecovery recoveryFor(bool installIdLive, bool deviceTokenLive) {
  return installIdLive && deviceTokenLive ? PairRecovery::DropShadows : PairRecovery::RestoreShadows;
}

// The clock. A time(nullptr) reading a heal may use: inside [kHealMinPlausibleEpoch, kHealMaxPlausibleEpoch]. Takes the
// reading as int64_t so a negative time_t (other than the -1 error value) and a 64-bit value past 2^32 are rejected
// BEFORE any cast to uint32_t can turn them into a "plausible" epoch.
inline bool healTimeUsable(int64_t t) {
  return t >= static_cast<int64_t>(kHealMinPlausibleEpoch) && t <= static_cast<int64_t>(kHealMaxPlausibleEpoch);
}

// The retry's reply. Its 2xx body is buffered only when the server announced its length and it is small (a registration
// answer is {"status","device_token"}). Unknown (-1, chunked), empty and oversized all fail closed: the heal counts
// as failed and the pair is restored. 2048 is the bound readServerDetail already applies to a 4xx body.
constexpr int kHealReplyMaxBytes = 2048;

inline bool healReplyReadable(int contentLength) { return contentLength > 0 && contentLength <= kHealReplyMaxBytes; }

// The per-boot latch. It is released after one full window of UPTIME (millis), so a transient retry failure no
// longer disables the heal until the next reboot. The persisted 6 h stamp (healWindowOpen) still gates every
// attempt, so the rate stays at most one per 6 h. `uptimeSinceBurnMs` is millis() - millis() at the burn, in
// unsigned arithmetic, which is correct across a millis() wrap.
constexpr uint32_t kHealLatchReleaseMs = kHealWindowSeconds * 1000UL;  // 21,600,000

inline bool healLatchExpired(uint32_t uptimeSinceBurnMs) { return uptimeSinceBurnMs >= kHealLatchReleaseMs; }

// A retry that answered 2xx but carried no device_token is a failure (restore the previous pair), not a
// success that discards it.
inline bool healTokenUsable(size_t tokenLength) { return tokenLength > 0; }

}  // namespace fry
