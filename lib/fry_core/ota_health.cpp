#include "ota_health.h"

#include <cstring>

#include "semver.h"

namespace fry {

namespace {

bool empty(const char* s) { return s == nullptr || s[0] == 0; }

}  // namespace

bool HeartbeatTracker::note(int http, uint32_t nowMs) {
  if (http <= 0) return false;
  _lastHttp = http;
  if (http >= 200 && http < 300) {
    _okSeen = true;
    _lastOkMs = nowMs;
  }
  if (_any) return false;
  _any = true;
  return true;
}

int32_t HeartbeatTracker::ageS(uint32_t nowMs) const {
  if (!_okSeen) return -1;
  return static_cast<int32_t>((nowMs - _lastOkMs) / 1000u);
}

GuardAction decideRollbackGuard(bool pendingVerify, bool heartbeatSeen, uint32_t uptimeMs,
                                uint32_t deadlineMs) {
  if (!pendingVerify || heartbeatSeen) return GuardAction::None;
  return uptimeMs >= deadlineMs ? GuardAction::Rollback : GuardAction::None;
}

bool shouldRecordBadVersion(const char* pending, const char* running, bool lastInvalidPartition) {
  if (empty(pending) || !lastInvalidPartition) return false;
  return running == nullptr || strcmp(pending, running) != 0;
}

bool decideMarkValid(bool pending, bool heartbeatSeen, uint32_t uptimeMs, uint32_t settleMs) {
  return pending && heartbeatSeen && uptimeMs >= settleMs;
}

uint32_t accrueVerifyMs(uint32_t accruedMs, uint32_t elapsedMs, bool staConnected) {
  if (!staConnected) return accruedMs;
  return elapsedMs > 0xFFFFFFFFu - accruedMs ? 0xFFFFFFFFu : accruedMs + elapsedMs;
}

uint8_t nextStrikeCount(const char* badver, uint8_t badn, const char* rolledBackFrom,
                        bool plannedRestart, bool* changed) {
  if (changed) *changed = false;
  if (empty(rolledBackFrom) || plannedRestart) return badn;
  if (changed) *changed = true;
  if (!empty(badver) && strcmp(badver, rolledBackFrom) == 0) {
    return badn < 255 ? static_cast<uint8_t>(badn + 1) : badn;
  }
  return 1;
}

bool skipBadVersion(const char* latest, const char* badver, uint8_t badn, bool firstCheckAfterRollback) {
  if (!isSkippedBadVersion(latest, badver)) return false;
  return badn >= kOtaPermanentStrikes || firstCheckAfterRollback;
}

bool strikesReset(const char* latest, const char* badver) {
  if (empty(latest) || empty(badver)) return false;
  return strcmp(latest, badver) != 0;
}

OtaImageState otaImageState(bool pendingVerify, bool rolledBackBefore) {
  if (pendingVerify) return OtaImageState::Pending;
  return rolledBackBefore ? OtaImageState::RolledBack : OtaImageState::Valid;
}

const char* otaImageStateName(OtaImageState s) {
  switch (s) {
    case OtaImageState::Valid:
      return "valid";
    case OtaImageState::Pending:
      return "pending";
    case OtaImageState::RolledBack:
      return "rolled_back";
  }
  return "valid";
}

bool otaChannelAccepted(const char* manifestChannel, const char* ownChannel) {
  const char* got = empty(manifestChannel) ? "prod" : manifestChannel;
  const char* own = empty(ownChannel) ? "prod" : ownChannel;
  return strcmp(got, own) == 0;
}

bool isSkippedBadVersion(const char* candidate, const char* badver) {
  if (empty(candidate) || empty(badver)) return false;
  return strcmp(candidate, badver) == 0;
}

OtaDecision decideOtaUpdate(const char* manifestChannel, const char* ownChannel, const char* latest,
                            const char* current, const char* badver, const char* url,
                            const char* sha256, bool inRollout) {
  if (!otaChannelAccepted(manifestChannel, ownChannel)) return OtaDecision::WrongChannel;
  if (empty(latest) || !isNewerVersionOta(latest, current)) return OtaDecision::NotNewer;
  if (isSkippedBadVersion(latest, badver)) return OtaDecision::BadVersion;
  if (!inRollout) return OtaDecision::NotInRollout;
  if (empty(url) || empty(sha256)) return OtaDecision::NoBuild;
  return OtaDecision::Update;
}

namespace {
bool isDigit(char c) { return c >= '0' && c <= '9'; }
// MAJOR.MINOR.PATCH, then end, '-' or '+'. Anything else is not a version a rollback may name.
bool plainSemver(const char* v) {
  if (empty(v)) return false;
  for (int part = 0; part < 3; part++) {
    if (!isDigit(*v)) return false;
    while (isDigit(*v)) v++;
    if (part < 2) {
      if (*v != '.') return false;
      v++;
    }
  }
  return *v == 0 || *v == '-' || *v == '+';
}
bool isHex64(const char* s) {
  if (empty(s)) return false;
  size_t n = 0;
  for (; s[n]; n++) {
    const char c = s[n];
    if (!(isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
  }
  return n == 64;
}
}  // namespace

OtaDecision decideOtaRollback(const char* manifestChannel, const char* ownChannel, const char* running,
                              bool runningListed, const char* target, const char* badver, uint8_t badn,
                              bool firstCheckAfterRollback, const char* url, const char* sha256) {
  if (!otaChannelAccepted(manifestChannel, ownChannel)) return OtaDecision::WrongChannel;
  if (!runningListed || !plainSemver(running) || !plainSemver(target)) return OtaDecision::RollbackRefused;
  if (compareSemverPrecedence(target, running) >= 0) return OtaDecision::RollbackRefused;
  if (compareSemverPrecedence(target, "0.0.0") <= 0) return OtaDecision::RollbackRefused;
  if (skipBadVersion(target, badver, badn, firstCheckAfterRollback)) return OtaDecision::BadVersion;
  if (empty(url) || !isHex64(sha256)) return OtaDecision::NoBuild;
  return OtaDecision::Rollback;
}

const char* otaDecisionName(OtaDecision d) {
  switch (d) {
    case OtaDecision::Update:
      return "update";
    case OtaDecision::NotNewer:
      return "not_newer";
    case OtaDecision::WrongChannel:
      return "wrong_channel";
    case OtaDecision::BadVersion:
      return "bad_version";
    case OtaDecision::NoBuild:
      return "no_build";
    case OtaDecision::NotInRollout:
      return "not_in_rollout";
    case OtaDecision::Rollback:
      return "rollback";
    case OtaDecision::RollbackRefused:
      return "rollback_refused";
  }
  return "not_newer";
}

}  // namespace fry
