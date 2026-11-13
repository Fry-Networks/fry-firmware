#include "wifi_retry.h"

namespace fry {

namespace {
// Wrap-safe "a is at or after b" on a 32-bit millisecond clock.
bool atOrAfter(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b) >= 0; }
}  // namespace

uint32_t joinRetryDelayMs(uint32_t failures, bool credentialClass) {
  const uint32_t first = credentialClass ? kJoinRetryAuthFirstMs : kJoinRetryFirstMs;
  const uint32_t cap = credentialClass ? kJoinRetryAuthMaxMs : kJoinRetryMaxMs;
  if (failures <= 1) return first;
  // 30, 60, 120, 240, 300, 300 ... (and 120, 240, 480, 900, 900 ...)
  uint32_t d = first;
  for (uint32_t i = 1; i < failures && d < cap; i++) d = d * 2 > cap ? cap : d * 2;
  return d;
}

void JoinRetry::onFailure(uint32_t nowMs, ProvErr why) {
  _armed = true;
  _deferring = false;
  if (_failures < 0xFFFFFFFFu) _failures++;
  _lastDelayMs = joinRetryDelayMs(_failures, why == ProvErr::WifiAuth);
  _nextMs = nowMs + _lastDelayMs;
}

void JoinRetry::onSuccess() {
  _armed = false;
  _deferring = false;
  _failures = 0;
  _lastDelayMs = 0;
}

bool JoinRetry::due(uint32_t nowMs) const { return _armed && atOrAfter(nowMs, _nextMs); }

void JoinRetry::defer(uint32_t nowMs, uint32_t ms) {
  const uint32_t candidate = nowMs + ms;
  if (!atOrAfter(_nextMs, candidate)) _nextMs = candidate;  // only ever later
}

RetryAction JoinRetry::decide(uint32_t nowMs, const SessionState& s, bool settingsUsable) {
  if (!due(nowMs)) return RetryAction::Wait;
  const bool active = s.busy || ((s.clientConnected || s.provisioning) && s.msSinceActivity < kSessionIdleMs);
  if (active) {
    if (!_deferring) {
      _deferring = true;
      _deferStartMs = nowMs;
    }
    // A commit in progress always defers; an active client defers for at most kDeferCapMs in a row.
    if (s.busy || static_cast<uint32_t>(nowMs - _deferStartMs) < kDeferCapMs) {
      defer(nowMs, kJoinRetryQuietMs);
      return RetryAction::DeferSession;
    }
  }
  _deferring = false;
  if (!settingsUsable) {
    defer(nowMs, kJoinRetryRecheckMs);
    return RetryAction::DeferUnusable;
  }
  return RetryAction::Join;
}

}  // namespace fry
