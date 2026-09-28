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
                            const char* sha256) {
  if (!otaChannelAccepted(manifestChannel, ownChannel)) return OtaDecision::WrongChannel;
  if (empty(latest) || !isNewerVersionOta(latest, current)) return OtaDecision::NotNewer;
  if (isSkippedBadVersion(latest, badver)) return OtaDecision::BadVersion;
  if (empty(url) || empty(sha256)) return OtaDecision::NoBuild;
  return OtaDecision::Update;
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
  }
  return "not_newer";
}

}  // namespace fry
