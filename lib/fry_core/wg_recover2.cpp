#include "wg_recover2.h"

#include <cstring>

#include <ArduinoJson.h>

namespace fry {

namespace {
uint32_t elapsedMs(uint32_t nowMs, uint32_t thenMs) { return nowMs - thenMs; }
}  // namespace

void WgRecover2::reset() {
  tracking_ = false;
  stageADone_ = false;
}

WgRecoverAction WgRecover2::decide(const WgRecover2Input& in) {
  if (!in.armed || in.up || !in.wifiUp) {  // T1: our own uplink being down is not a dead tunnel
    reset();
    return WgRecoverAction::None;
  }
  if (!tracking_) {
    tracking_ = true;
    deadSinceMs_ = in.nowMs;
    return WgRecoverAction::None;
  }
  if (elapsedMs(in.nowMs, deadSinceMs_) < kWg2DeadAfterS * 1000u) return WgRecoverAction::None;
  if (in.otaBusy) return WgRecoverAction::None;
  const uint32_t jitterMs = (in.jitterS > kWg2JitterMaxS ? kWg2JitterMaxS : in.jitterS) * 1000u;

  if (in.hostnameEndpoint && !stageADone_) {
    stageADone_ = true;
    stageAAtMs_ = in.nowMs;
    return WgRecoverAction::ReResolve;
  }
  if (in.hostnameEndpoint) {
    if (elapsedMs(in.nowMs, stageAAtMs_) < kWg2StageAWindowS * 1000u + jitterMs) {
      return WgRecoverAction::None;
    }
  } else if (elapsedMs(in.nowMs, deadSinceMs_) < kWg2DeadAfterS * 1000u + jitterMs) {
    return WgRecoverAction::None;
  }

  // Stage B gates. The T5 backoff (provBlocked) paces retries; the persisted floor only stops a
  // reboot loop, because the RAM backoff is gone after a reboot.
  if (!in.clockSynced || in.provBlocked || !in.hostResolves) return WgRecoverAction::None;
  if (in.lastStageBEpoch != 0 && in.epochNow >= in.lastStageBEpoch &&
      in.epochNow - in.lastStageBEpoch < kWg2StageBFloorS) {
    return WgRecoverAction::None;
  }
  if (in.lastStageBEpoch > in.epochNow && in.lastStageBEpoch - in.epochNow < kWg2StageBFloorS) {
    return WgRecoverAction::None;  // a stamp from the (near) future is honoured for one floor
  }
  reset();
  return WgRecoverAction::ReProvision;
}

void WgRecover2::onReResolved(bool ipChanged, uint32_t nowMs) {
  if (!ipChanged) return;
  stageADone_ = false;
  tracking_ = true;
  deadSinceMs_ = nowMs;
}

WgKeySource wgRefreshKeySource(bool activeKeypairPresent) {
  return activeKeypairPresent ? WgKeySource::UseActive : WgKeySource::NoKeyAbort;
}

void WgTrial::begin(uint32_t nowMs) {
  active_ = true;
  startMs_ = nowMs;
  lastMs_ = nowMs;
}

WgTrialEvent WgTrial::tick(bool up, uint32_t nowMs) { return tick(up, nowMs, true); }

WgTrialEvent WgTrial::tick(bool up, uint32_t nowMs, bool wifiUp) {
  if (!active_) return WgTrialEvent::None;
  if (!wifiUp) {
    startMs_ += elapsedMs(nowMs, lastMs_);  // pause the window while our own uplink is down
    lastMs_ = nowMs;
    return WgTrialEvent::None;
  }
  lastMs_ = nowMs;
  if (up) {
    active_ = false;
    return WgTrialEvent::Commit;
  }
  if (elapsedMs(nowMs, startMs_) >= kWg2TrialWindowS * 1000u) {
    active_ = false;
    return WgTrialEvent::Rollback;
  }
  return WgTrialEvent::None;
}

void WgTrial::abandon() { active_ = false; }

uint32_t wgBackoffMs(WgFetchOutcome outcome, uint32_t attempt, uint32_t retryAfterS, uint32_t rnd) {
  if (retryAfterS > 0) {
    uint64_t s = retryAfterS > kWgRetryAfterMaxS ? kWgRetryAfterMaxS : retryAfterS;
    return static_cast<uint32_t>(s * 1000ULL);
  }
  const bool denied = outcome == WgFetchOutcome::Forbidden403 ||
                      outcome == WgFetchOutcome::OtherClientError4xx;
  const uint64_t cap = denied ? kWgForbiddenCapMs : kWgBackoffCapMs;
  const uint64_t firstWindow = denied ? 300000ULL / kWg2TimerDiv : kWgBackoffFirstWindowMs;
  // window = firstWindow * 2^attempt, capped; the delay is drawn uniformly from [min, window].
  uint32_t shift = attempt > 20 ? 20 : attempt;
  uint64_t window = firstWindow << shift;
  if (window > cap) window = cap;
  uint64_t lo = kWgBackoffFirstMinMs;
  if (window < lo) window = lo;
  uint64_t span = window - lo + 1;
  return static_cast<uint32_t>(lo + (rnd % span));
}

uint32_t parseRetryAfterJson(const char* json) {
  if (json == nullptr || json[0] == 0) return 0;
  JsonDocument doc;
  if (deserializeJson(doc, json)) return 0;
  JsonVariant v = doc["retry_after_s"];
  if (!v.is<uint32_t>()) return 0;
  return v.as<uint32_t>();
}

WgMigrationAction wgMigrationDecide(const WgMigrationInput& in) {
  const char* last = in.lastVer ? in.lastVer : "";
  const char* cur = in.curVer ? in.curVer : "";
  if (std::strcmp(last, cur) == 0) return WgMigrationAction::None;
  if (!in.hasConfig || !in.rawIpEndpoint) return WgMigrationAction::RecordVersion;
  if (in.tries >= kWgMigrationMaxTries) return WgMigrationAction::GiveUp;
  return WgMigrationAction::Refresh;
}

}  // namespace fry
