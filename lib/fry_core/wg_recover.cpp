#include "wg_recover.h"

#include <cstring>

namespace fry {

namespace {

// Wrap-safe elapsed milliseconds between two millis() readings.
uint32_t elapsedMs(uint32_t nowMs, uint32_t thenMs) { return nowMs - thenMs; }

bool isIpv4Literal(const char* s) {
  int octets = 0;
  const char* p = s;
  while (true) {
    if (*p < '0' || *p > '9') return false;
    int v = 0;
    int digits = 0;
    while (*p >= '0' && *p <= '9') {
      v = v * 10 + (*p - '0');
      if (++digits > 3 || v > 255) return false;
      ++p;
    }
    ++octets;
    if (*p == 0) return octets == 4;
    if (*p != '.' || octets == 4) return false;
    ++p;
  }
}

}  // namespace

void WgRecover::reset() {
  tracking_ = false;
  stageADone_ = false;
}

bool WgRecover::stageBLimited(const WgRecoverInput& in) {
  if (in.lastStageBEpoch == 0) return false;
  if (in.epochNow >= in.lastStageBEpoch) {
    futureSeen_ = false;
    return in.epochNow - in.lastStageBEpoch < kWgStageBMinIntervalS;
  }
  // A stamp from the future (clock skew or a corrupt write) still limits, but for at most one
  // interval from first sight, so it can neither be ignored nor wedge recovery forever.
  if (!futureSeen_) {
    futureSeen_ = true;
    futureCapEpoch_ = in.epochNow + kWgStageBMinIntervalS;
  }
  const uint32_t until = in.lastStageBEpoch < futureCapEpoch_ ? in.lastStageBEpoch : futureCapEpoch_;
  return in.epochNow < until;
}

WgRecoverAction WgRecover::decide(const WgRecoverInput& in) {
  if (!in.armed || in.up || !in.wifiUp) {
    reset();
    return WgRecoverAction::None;
  }
  if (!tracking_) {
    tracking_ = true;
    deadSinceMs_ = in.nowMs;
    return WgRecoverAction::None;
  }
  if (elapsedMs(in.nowMs, deadSinceMs_) < kWgDeadAfterS * 1000u) return WgRecoverAction::None;
  if (in.otaBusy) return WgRecoverAction::None;
  const uint32_t jitterMs = (in.jitterS > kWgJitterMaxS ? kWgJitterMaxS : in.jitterS) * 1000u;

  if (in.hostnameEndpoint && !stageADone_) {
    stageADone_ = true;
    stageAAtMs_ = in.nowMs;
    return WgRecoverAction::ReResolve;
  }
  if (in.hostnameEndpoint) {
    if (elapsedMs(in.nowMs, stageAAtMs_) < kWgStageAWindowS * 1000u + jitterMs) {
      return WgRecoverAction::None;
    }
  } else if (elapsedMs(in.nowMs, deadSinceMs_) < kWgDeadAfterS * 1000u + jitterMs) {
    return WgRecoverAction::None;
  }

  // Stage B gates.
  if (!in.clockSynced || in.provBlocked || !in.apiReachable) return WgRecoverAction::None;
  if (stageBLimited(in)) return WgRecoverAction::None;
  reset();
  return WgRecoverAction::ReProvision;
}

void WgRecover::onReResolved(bool ipChanged, uint32_t nowMs) {
  if (!ipChanged) return;
  stageADone_ = false;
  tracking_ = true;
  deadSinceMs_ = nowMs;
}

bool wgEndpointIsHostname(const char* endpoint) {
  if (endpoint == nullptr || endpoint[0] == 0) return false;
  if (endpoint[0] == '[' || std::strchr(endpoint, ':') != nullptr) return false;
  return !isIpv4Literal(endpoint);
}

bool wgApiRecent(int32_t heartbeatAgeS) {
  return heartbeatAgeS >= 0 && static_cast<uint32_t>(heartbeatAgeS) <= kWgApiFreshS;
}

uint32_t wgRecoverJitterS(uint64_t seed) {
  uint64_t h = 1469598103934665603ULL;  // FNV-1a 64
  for (int i = 0; i < 8; i++) {
    h ^= (seed >> (8 * i)) & 0xFFu;
    h *= 1099511628211ULL;
  }
  return static_cast<uint32_t>(h % (kWgJitterMaxS + 1u));
}

bool wgTearDownTunnel(WgTunnelOps& ops) {
  if (!ops.hasNetif()) return true;
  ops.teardown();
  return !ops.hasNetif();
}

WgRotationState wgRotationFinish(bool responseValidated, WgRotationWriter* writer) {
  if (!responseValidated || writer == nullptr) return WgRotationState::Failed;
  writer->commit();
  return WgRotationState::Committed;
}

}  // namespace fry
