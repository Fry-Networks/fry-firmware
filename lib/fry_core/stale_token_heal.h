#pragma once
// Stale device-token self-heal: the decision and its bounds only. A registration 404 while a
// non-empty device token was sent means the stored token is stale — a WG1 apiBase skips its
// token-less first-registration route and answers a LOCAL 404, so the same rejected request would
// be retried hourly forever. Pure C++ so the native suite pins it; the NVS shadow pair and the
// retry itself live in src/core/hardwareapi_client.cpp.
#include <cstddef>
#include <cstdint>

namespace fry {

constexpr uint32_t kHealMinPlausibleEpoch = 1600000000UL;  // 2020-09-13: earlier is an unsynced clock
// 2038-01-19: the end of a signed 32-bit time_t. A reading past it (or a negative one cast to uint32_t)
// is a wrapped or hostile clock, never a time a heal may be stamped with.
constexpr uint32_t kHealMaxPlausibleEpoch = 2147483647UL;
constexpr uint32_t kHealWindowSeconds = 6UL * 3600UL;

// The ONLY trigger: a 404 with a device token actually sent. 401/403/409/429, every 5xx, a
// transport error and a 404 on a token-less attempt all stay out.
inline bool isStaleTokenSignature(int httpCode, bool deviceTokenSent) {
  return deviceTokenSent && httpCode == 404;
}

// One heal per boot and one per 6 h across reboots. An unsynced clock, or one that moved
// backwards, cannot prove the window elapsed and never opens it. Two edges are closed on top of that,
// neither of which changes any answer for a plausible clock and a stamp written by it:
//   - a clock past the 32-bit ceiling is not a clock (never opens);
//   - a stamp more than one window AHEAD of a plausible clock cannot be the record of a past heal, it was
//     written under a clock that was later corrected. It no longer blocks the heal until that bogus time
//     arrives; the per-boot flag still allows one attempt, and the heal rewrites a valid stamp.
// Consequence of the second edge, accepted: a hostile NTP source can still poison the stamp (write a far-future
// one, or move the clock back by more than a window), and that now buys at most ONE extra heal per reboot instead
// of blocking the heal for years. A heal still needs the registration 404 with a device token on a non-default
// apiBase. Any heal that passes the stash proof writes the stamp with the current time, before the retry is sent,
// whatever the retry's outcome.
inline bool healWindowOpen(bool healedThisBoot, uint32_t lastHealEpoch, uint32_t nowEpoch) {
  if (healedThisBoot || nowEpoch < kHealMinPlausibleEpoch || nowEpoch > kHealMaxPlausibleEpoch) return false;
  if (lastHealEpoch == 0) return true;
  if (lastHealEpoch > nowEpoch + kHealWindowSeconds) return true;
  return nowEpoch >= lastHealEpoch && nowEpoch - lastHealEpoch >= kHealWindowSeconds;
}

// A restore counts only when the live pair is the shadow pair byte for byte.
inline bool pairsMatchByteForByte(const char* a, const char* b) {
  if (!a || !b) return false;
  for (size_t i = 0;; i++) {
    if (a[i] != b[i]) return false;
    if (a[i] == '\0') return true;
  }
}

}  // namespace fry
