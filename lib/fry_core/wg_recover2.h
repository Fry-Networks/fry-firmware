#pragma once
// RC-A recovery of a dead WireGuard tunnel: pure decision logic, zero Arduino includes, linked
// into `pio test -e native`. Supersedes wg_recover.h's WgRecover for the glue
// (src/esp32/vpn_wireguard.cpp); wg_recover.h stays for its helpers and its own tests.
//
// Target state machine (T1-T9 of the IV6 contract), the parts that live here:
//   T1  the tunnel is dead after >= 180 s without a handshake while Wi-Fi is associated. A Wi-Fi
//       outage is never a dead tunnel (decide() resets whenever the uplink is down).
//   T2  stage A: a hostname endpoint is re-resolved and the peer re-pointed without a reboot.
//   T3  stage B: re-POST provisioning with the SAME install_id and the SAME WG keypair. The old
//       config stays until the new one handshakes (WgTrial); it is persisted only then.
//   T5  wgBackoffMs: exponential backoff with full jitter, first retry 30-60 s, cap 900 s,
//       Retry-After honoured, a 403 waits at most 1 h. Never 21600 s.
//   T6  nothing here resets, erases, re-keys or reboots.
//   T7  wgMigrationDecide: one refresh of a cached raw-IP endpoint after an OTA, bounded.
//
// FRY_QA_COMPRESSED_TIMERS (esp32_qa / esp32c3_qa envs only) divides every timer by 10 so 50+
// recovery cycles fit in about an hour. Release envs never define it.
#include <cstddef>
#include <cstdint>

#include "wg_provision.h"
#include "wg_recover.h"

namespace fry {

#ifdef FRY_QA_COMPRESSED_TIMERS
constexpr uint32_t kWg2TimerDiv = 10;
#else
constexpr uint32_t kWg2TimerDiv = 1;
#endif

constexpr uint32_t kWg2DeadAfterS = 180 / kWg2TimerDiv;      // T1
constexpr uint32_t kWg2StageAWindowS = 60 / kWg2TimerDiv;    // a re-resolved tunnel's grace
constexpr uint32_t kWg2JitterMaxS = 60 / kWg2TimerDiv;       // per-device delay of stage B
constexpr uint32_t kWg2StageBFloorS = 60 / kWg2TimerDiv;     // persisted anti-reboot-loop floor
constexpr uint32_t kWg2TrialWindowS = 240 / kWg2TimerDiv;    // a refreshed config must handshake
constexpr uint32_t kWgMigrationMaxTries = 24;                // T7 gives up after this many

constexpr uint32_t kWgBackoffFirstMinMs = 30000 / kWg2TimerDiv;
constexpr uint32_t kWgBackoffFirstWindowMs = 60000 / kWg2TimerDiv;
constexpr uint32_t kWgBackoffCapMs = 900000 / kWg2TimerDiv;
constexpr uint32_t kWgForbiddenCapMs = 3600000 / kWg2TimerDiv;
constexpr uint32_t kWgRetryAfterMaxS = 3600 / kWg2TimerDiv;

// INF-1: the library's esp_wireguard_peer_is_up() stays OK while the PREVIOUS keypair is valid,
// and that keypair is never expired once the current one is destroyed (~180 s) - so a session
// that rekeyed before the hub dropped the peer reads "up" forever. Health is therefore judged
// from the age of the latest handshake against kWg2DeadAfterS (the same constant decide() uses).
//   healthy  <=>  libSaysUp && haveHandshake && handshakeAgeS < kWg2DeadAfterS
// Boundary: age == kWg2DeadAfterS is NOT healthy (decide() calls the tunnel dead at >= 180 s).
// libSaysUp == false is never healthy; haveHandshake == false (no handshake time) is not healthy.
bool wgPeerHealthy(bool libSaysUp, bool haveHandshake, uint32_t handshakeAgeS);

struct WgRecover2Input {
  bool armed = false;             // the tunnel was brought up (or stage A is in flight) this boot
  bool up = false;                // esp_wireguard_peer_is_up == ESP_OK
  bool wifiUp = false;            // STA associated
  uint32_t nowMs = 0;             // millis(); wrap-safe
  bool hostnameEndpoint = false;  // wgEndpointIsHostname(cached endpoint)
  bool otaBusy = false;           // an OTA image is pending/settling: never act
  bool clockSynced = false;       // NTP synced (the provisioning POST needs it)
  bool provBlocked = false;       // the provisioning client is inside a T5 backoff
  bool hostResolves = false;      // the provisioning host resolves (DNS works)
  uint32_t jitterS = 0;           // wgRecoverJitterS(device seed); delays stage B only
  uint32_t epochNow = 0;          // time(nullptr), meaningful only when clockSynced
  uint32_t lastStageBEpoch = 0;   // persisted epoch of the last re-POST, 0 = never
};

class WgRecover2 {
 public:
  // Call every tick. Returns the action to perform now (None almost always).
  WgRecoverAction decide(const WgRecover2Input& in);
  // The glue calls this after stage A rebuilt the tunnel; ipChanged restarts the dead clock.
  void onReResolved(bool ipChanged, uint32_t nowMs);

 private:
  bool tracking_ = false;
  uint32_t deadSinceMs_ = 0;
  bool stageADone_ = false;
  uint32_t stageAAtMs_ = 0;
  void reset();
};

// T3/T6: where the stage-B keypair comes from. Always the active one; a board without one never
// mints a replacement during recovery.
enum class WgKeySource { UseActive, NoKeyAbort };
WgKeySource wgRefreshKeySource(bool activeKeypairPresent);

// T3: a refreshed config runs as a trial. The old config is kept until it handshakes.
enum class WgTrialEvent { None, Commit, Rollback };
class WgTrial {
 public:
  void begin(uint32_t nowMs);
  bool active() const { return active_; }
  // Commit once when the trial config handshakes; Rollback when the window passes without one.
  WgTrialEvent tick(bool up, uint32_t nowMs);
  // Same, but the window only runs while Wi-Fi is associated: an outage of our own uplink is not
  // the new config's fault (the clock is paused, not reset).
  WgTrialEvent tick(bool up, uint32_t nowMs, bool wifiUp);
  void abandon();  // power loss / reboot: the trial is RAM-only and is simply gone

 private:
  bool active_ = false;
  uint32_t startMs_ = 0;
  uint32_t lastMs_ = 0;
};

// T5. attempt counts failures so far (0 = first retry). rnd is any uniform 32-bit value.
// Retry-After (seconds, header or JSON retry_after_s; 0 = none) wins, clamped to [1 s, 1 h].
uint32_t wgBackoffMs(WgFetchOutcome outcome, uint32_t attempt, uint32_t retryAfterS, uint32_t rnd);

// retry_after_s from a JSON error body; 0 when absent or unparseable.
uint32_t parseRetryAfterJson(const char* json);

// T7. lastVer is the version recorded when the migration last settled ("" on a board that never
// wrote one: a 0.3.3/0.4.1 board).
enum class WgMigrationAction { None, RecordVersion, Refresh, GiveUp };
struct WgMigrationInput {
  const char* lastVer = "";
  const char* curVer = "";
  bool hasConfig = false;
  bool rawIpEndpoint = false;
  uint32_t tries = 0;  // persisted refresh attempts so far
};
WgMigrationAction wgMigrationDecide(const WgMigrationInput& in);

}  // namespace fry
