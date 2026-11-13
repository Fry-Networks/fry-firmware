#pragma once
// Retrying the stored network after a failed join at boot.
//
// A boot makes one station join attempt (WIFI_CONNECT_TIMEOUT_MS). When it fails the board waits in
// the provisioning phase, which is left only by a new provisioning commit, so a board whose stored
// network was unreachable for those seconds (site outage, access point restarting, weak signal) stayed
// offline until it was power-cycled. This keeps provisioning available exactly as before and joins
// the stored network again in the background, with a growing delay and without ever giving up.
// Pure C++ (no Arduino); src/main.cpp owns the I/O. ESP32 family only.
#include <cstdint>

#include "provisioning_fsm.h"

namespace fry {

// Delay before retry number `failures` (1 = the retry after the first failed join). A join that
// failed for a non-credential reason (no access point found, no IP) is retried soon; a rejected
// password class is retried more slowly, but never abandoned: the access point can misreport.
const uint32_t kJoinRetryFirstMs = 30UL * 1000UL;
const uint32_t kJoinRetryMaxMs = 300UL * 1000UL;
const uint32_t kJoinRetryAuthFirstMs = 120UL * 1000UL;
const uint32_t kJoinRetryAuthMaxMs = 900UL * 1000UL;
// After a provisioning session ends (a client disconnected, a commit finished) wait this long.
const uint32_t kJoinRetryQuietMs = 15UL * 1000UL;
// Re-check interval while a retry is due but the stored configuration is not usable.
const uint32_t kJoinRetryRecheckMs = 30UL * 1000UL;

uint32_t joinRetryDelayMs(uint32_t failures, bool credentialClass);

class JoinRetry {
 public:
  // A join (at boot, or after a commit, or a retry) failed with `why`.
  void onFailure(uint32_t nowMs, ProvErr why);
  // A join succeeded: forget everything.
  void onSuccess();
  // Armed and the time has come.
  bool due(uint32_t nowMs) const;
  // Not now: push the next attempt back by at least `ms` from `nowMs` (never earlier than it was).
  void defer(uint32_t nowMs, uint32_t ms);

  bool armed() const { return _armed; }
  uint32_t failures() const { return _failures; }
  uint32_t lastDelayMs() const { return _lastDelayMs; }

 private:
  bool _armed = false;
  uint32_t _failures = 0;
  uint32_t _nextMs = 0;
  uint32_t _lastDelayMs = 0;
};

// What the boot loop does about the stored network on this pass. A provisioning session (a client
// connected, a write in progress, a commit being applied) is never disturbed: the retry waits and
// resumes kJoinRetryQuietMs after it ends. A due retry with unusable stored settings checks again later.
enum class RetryAction : uint8_t { Wait, Join, DeferSession, DeferUnusable };
RetryAction nextRetryAction(const JoinRetry& r, uint32_t nowMs, bool sessionActive, bool settingsUsable);

}  // namespace fry
