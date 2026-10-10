// Simulated-clock state-machine test for RC-A recovery (T1-T7 invariants).
// >= 10,000 randomized fault cycles per run. Seed: env SIM_SEED, else time-based; always printed.
// The model drives the SAME pure pieces the firmware glue calls (WgRecover2, WgTrial, wgBackoffMs,
// wgMigrationDecide, wgRefreshKeySource); the world (server, Wi-Fi, NVS) is a small fake.
#include <unity.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <string>

#include "wg_recover2.h"

namespace {

struct Rng {
  uint64_t s;
  explicit Rng(uint64_t seed) : s(seed ? seed : 0x9E3779B97F4A7C15ULL) {}
  uint32_t next() {
    s ^= s << 13; s ^= s >> 7; s ^= s << 17;
    return static_cast<uint32_t>(s >> 11);
  }
  uint32_t below(uint32_t n) { return n ? next() % n : 0; }
  bool chance(uint32_t pct) { return below(100) < pct; }
  uint32_t range(uint32_t lo, uint32_t hi) { return lo + below(hi - lo + 1); }
};

constexpr uint32_t kEpoch = 1790000000;
constexpr uint32_t kTickS = 5;
constexpr uint32_t kCapS = 8 * 3600;

// Mutation controls: 0 = the real model; 1 = refresh mints a new keypair; 2 = a failed refresh
// erases NVS; 3 = the config is written when the trial STARTS, not after its handshake.
int g_mutant = 0;
uint64_t g_seed = 0;
uint32_t g_cycles = 10000;
std::string g_fail;

#define SIM_CHECK(cond, msg)                                                         \
  do {                                                                               \
    if (!(cond) && g_fail.empty()) {                                                 \
      char b[200];                                                                   \
      snprintf(b, sizeof(b), "seed=%llu cycle=%u t=%u: %s", (unsigned long long)g_seed, \
               cycle, t, msg);                                                       \
      g_fail = b;                                                                    \
    }                                                                                \
  } while (0)

// Persisted device state (survives power loss).
struct Nvs {
  int keyId = 1;          // the WG keypair: must never change
  int installId = 1;      // must never change
  int erases = 0;         // must stay 0
  uint32_t stageBStamp = 0;
  int cfgEndpointGen = 1;  // endpoint the persisted fry_vpn config points at
  bool cfgHostname = false;
  std::string lastVer = "";
  uint32_t migTries = 0;
  uint32_t cfgWrites = 0;
};


struct World {
  int serverEndpointGen = 1;
  int peerKeyId = 1;          // the public key the server registered for this device
  bool peerRegistered = true;
  uint32_t blackoutUntil = 0;
  bool wifi = true;
  uint32_t wifiBackAt = 0;
  uint32_t postFailUntil = 0;
  int postFailCode = 403;
  uint32_t postRetryAfterS = 0;
};

void runCycle(Rng& rng, uint32_t cycle) {
  Nvs nvs;
  World w;
  uint32_t t = 0;  // seconds of simulated time

  // scenario setup
  nvs.cfgHostname = rng.chance(50);
  const bool migrate = rng.chance(30);
  if (!migrate) nvs.lastVer = "0.4.2";
  const uint32_t jitterS = rng.below(fry::kWg2JitterMaxS + 1);

  // RAM state
  fry::WgRecover2 rec;
  fry::WgTrial trial;
  int trialEndpointGen = 0;
  uint32_t attempt = 0;
  uint32_t backoffUntilMs = 0;
  int resolvedGen = 1;  // what the hostname currently resolves to (RAM)
  bool migBooted = false;

  // faults
  const bool fPeerRemoved = rng.chance(40);
  const bool fIpChange = rng.chance(40);
  const bool fBlackout = rng.chance(40);
  const bool fWifi = rng.chance(35);
  const bool f403 = rng.chance(25);
  const bool f429 = rng.chance(20);
  const bool fRetryAfter = rng.chance(50);
  const uint32_t nPower = rng.chance(40) ? rng.range(1, 3) : 0;
  const uint32_t faultAt = rng.range(0, 120);
  uint32_t powerAt[3] = {rng.range(1, 3000), rng.range(1, 3000), rng.range(1, 3000)};
  bool faultsApplied = false;
  uint32_t lastFaultEnd = 0;

  std::deque<uint32_t> posts;       // sim-time of every re-POST (across reboots)
  std::deque<uint32_t> migAttempts;
  uint32_t deadSince = 0;           // continuous (wifi && !handshake) start; 0 = not dead
  bool deadTracking = false;
  uint32_t upStreak = 0;
  uint32_t lastPostAt = 0;
  bool anyPost = false;
  uint32_t migAttemptsTotal = 0;
  bool migDoneSeen = false;
  uint32_t commitsSeen = 0;   // trial commits the model performed after a handshake

  // The endpoint IP the live tunnel talks to: a trial config always carries the server's current
  // endpoint; a hostname config follows the (RAM) resolution; a raw-IP config is frozen in NVS.
  auto effectiveGen = [&]() -> int {
    if (trial.active()) return trialEndpointGen;
    return nvs.cfgHostname ? resolvedGen : nvs.cfgEndpointGen;
  };
  auto handshakeOk = [&]() -> bool {
    return w.wifi && w.peerRegistered && w.peerKeyId == nvs.keyId && t >= w.blackoutUntil &&
           effectiveGen() == w.serverEndpointGen;
  };

  auto powerLoss = [&]() {
    rec = fry::WgRecover2();
    trial.abandon();
    attempt = 0;
    backoffUntilMs = 0;
    resolvedGen = w.serverEndpointGen;  // a boot re-resolves a hostname to the current IP
    migBooted = false;
    deadTracking = false;
  };

  while (t < kCapS) {
    if (!faultsApplied && t >= faultAt) {
      faultsApplied = true;
      if (fPeerRemoved) w.peerRegistered = false;
      if (fIpChange) w.serverEndpointGen++;
      if (fBlackout) { w.blackoutUntil = t + rng.range(60, 1800); lastFaultEnd = w.blackoutUntil > lastFaultEnd ? w.blackoutUntil : lastFaultEnd; }
      if (fWifi) { w.wifi = false; w.wifiBackAt = t + rng.range(30, 1200); lastFaultEnd = w.wifiBackAt > lastFaultEnd ? w.wifiBackAt : lastFaultEnd; }
      if (f403 || f429) {
        w.postFailCode = f403 ? 403 : 429;
        w.postFailUntil = t + rng.range(30, 5400);
        w.postRetryAfterS = fRetryAfter ? rng.range(1, 7200) : 0;
        if (w.postFailUntil > lastFaultEnd) lastFaultEnd = w.postFailUntil;
      }
    }
    if (!w.wifi && t >= w.wifiBackAt) w.wifi = true;
    for (uint32_t i = 0; i < nPower; i++) {
      if (t == (powerAt[i] / kTickS) * kTickS) powerLoss();
    }

    // boot-time migration decision (RAM flag per boot, nvs for progress)
    if (!migBooted) {
      migBooted = true;
    }
    fry::WgMigrationInput mi;
    mi.lastVer = nvs.lastVer.c_str();
    mi.curVer = "0.4.2";
    mi.hasConfig = true;
    mi.rawIpEndpoint = !nvs.cfgHostname;
    mi.tries = nvs.migTries;
    fry::WgMigrationAction ma = fry::wgMigrationDecide(mi);
    if (ma == fry::WgMigrationAction::RecordVersion) nvs.lastVer = "0.4.2";
    if (ma == fry::WgMigrationAction::GiveUp) { nvs.lastVer = "0.4.2"; migDoneSeen = true; }
    SIM_CHECK(!(migDoneSeen && ma == fry::WgMigrationAction::Refresh), "refresh after give-up");

    // handshake state of the live tunnel
    bool up = handshakeOk();

    // track the continuous dead period for the T1 invariant
    if (w.wifi && !up) {
      if (!deadTracking) { deadTracking = true; deadSince = t; }
    } else {
      deadTracking = false;
    }
    upStreak = up ? upStreak + kTickS : 0;

    // trial bookkeeping
    if (trial.active()) {
      fry::WgTrialEvent ev = trial.tick(up, t * 1000u, w.wifi);
      if (ev == fry::WgTrialEvent::Commit) {
        SIM_CHECK(up, "config committed without a handshake");
        nvs.cfgEndpointGen = trialEndpointGen;
        nvs.cfgWrites++;
        commitsSeen++;
        resolvedGen = trialEndpointGen;
        attempt = 0;
        if (migrate) { nvs.lastVer = "0.4.2"; nvs.cfgHostname = true; }  // the server now hands out the hostname
      } else if (ev == fry::WgTrialEvent::Rollback) {
        // old config reloaded; the hostname (if any) is re-resolved from scratch
        resolvedGen = nvs.cfgHostname ? w.serverEndpointGen : nvs.cfgEndpointGen;
        if (g_mutant == 2) { nvs.erases++; nvs.cfgEndpointGen = 0; }  // a factory-reset style recovery
      }
    }

    fry::WgRecover2Input in;
    in.armed = true;
    in.up = up;
    in.wifiUp = w.wifi;
    in.nowMs = t * 1000u;
    in.hostnameEndpoint = nvs.cfgHostname;
    in.otaBusy = false;
    in.clockSynced = true;
    in.hostResolves = true;
    in.provBlocked = in.nowMs < backoffUntilMs;
    in.jitterS = jitterS;
    in.epochNow = kEpoch + t;
    in.lastStageBEpoch = nvs.stageBStamp;

    bool wantRefresh = false;
    fry::WgRecoverAction act = trial.active() ? fry::WgRecoverAction::None : rec.decide(in);
    if (act != fry::WgRecoverAction::None) {
      SIM_CHECK(w.wifi, "recovery action while Wi-Fi is down");
      SIM_CHECK(deadTracking && t - deadSince >= fry::kWg2DeadAfterS, "acted before the dead threshold");
    }
    if (act == fry::WgRecoverAction::ReResolve) {
      uint32_t old = resolvedGen;
      resolvedGen = w.serverEndpointGen;  // the hostname now resolves to the current IP
      rec.onReResolved(old != static_cast<uint32_t>(resolvedGen), in.nowMs);
    } else if (act == fry::WgRecoverAction::ReProvision) {
      wantRefresh = true;
    }

    // T7: one in-flight migration refresh, paced by the same backoff
    if (!wantRefresh && !trial.active() && ma == fry::WgMigrationAction::Refresh && w.wifi &&
        in.nowMs >= backoffUntilMs && nvs.stageBStamp + fry::kWg2StageBFloorS <= kEpoch + t) {
      wantRefresh = true;
      nvs.migTries++;
      migAttempts.push_back(t);
      migAttemptsTotal++;
    }

    if (wantRefresh && !trial.active()) {
      SIM_CHECK(fry::wgRefreshKeySource(true) == fry::WgKeySource::UseActive, "keypair source");
      int postKeyId = nvs.keyId;                 // UseActive: the POST carries the device's keypair
      if (g_mutant == 1) postKeyId = ++nvs.keyId;  // mutant: mint a new keypair for the refresh
      nvs.stageBStamp = kEpoch + t;  // persisted BEFORE the attempt
      posts.push_back(t);
      while (!posts.empty() && posts.front() + 3600 <= t) posts.pop_front();
      SIM_CHECK(posts.size() <= 60, "more than 60 re-POSTs in an hour");
      SIM_CHECK(!anyPost || t - lastPostAt >= fry::kWg2StageBFloorS, "re-POST gap below the floor");
      anyPost = true;
      lastPostAt = t;
      if (t < w.postFailUntil) {
        fry::WgFetchOutcome oc = w.postFailCode == 403 ? fry::WgFetchOutcome::Forbidden403
                                                       : fry::WgFetchOutcome::RateLimited429;
        uint32_t ms = fry::wgBackoffMs(oc, attempt++, w.postRetryAfterS, rng.next());
        SIM_CHECK(ms >= 1000 && ms <= 3600000, "backoff out of bounds");
        SIM_CHECK(ms != 21600000, "21600 s backoff");
        if (w.postRetryAfterS == 0) SIM_CHECK(ms >= 30000, "backoff below 30 s");
        backoffUntilMs = in.nowMs + ms;
      } else {
        // 2xx: the server re-registers the same key and returns the current endpoint.
        w.peerRegistered = true;
        w.peerKeyId = postKeyId;
        trialEndpointGen = w.serverEndpointGen;
        trial.begin(in.nowMs);
        if (g_mutant == 3) { nvs.cfgEndpointGen = trialEndpointGen; nvs.cfgWrites++; }
        resolvedGen = trialEndpointGen;
        backoffUntilMs = 0;
      }
    }

    // global invariants
    SIM_CHECK(nvs.keyId == 1 && nvs.installId == 1, "identity changed");
    SIM_CHECK(nvs.erases == 0, "NVS erased");
    SIM_CHECK(nvs.cfgWrites == commitsSeen, "config persisted outside a post-handshake commit");
    SIM_CHECK(!(migrate && nvs.migTries > fry::kWgMigrationMaxTries), "migration tries above 24");

    // done: faults over, up for a while, no trial pending
    if (t > lastFaultEnd + 60 && upStreak >= 60 && !trial.active() && faultsApplied) {
      bool migSettled = !migrate || nvs.lastVer == "0.4.2" ;
      if (migSettled) break;
    }
    t += kTickS;
  }
  SIM_CHECK(t < kCapS, "did not recover within 8 h of simulated time");
  (void)migAttemptsTotal;
}

}  // namespace

void setUp() {}
void tearDown() {}

void test_sim_randomized_fault_cycles() {
  const char* e = getenv("SIM_SEED");
  g_seed = e ? strtoull(e, nullptr, 10) : static_cast<uint64_t>(time(nullptr)) * 2654435761ULL;
  const char* c = getenv("SIM_CYCLES");
  if (c) g_cycles = static_cast<uint32_t>(strtoul(c, nullptr, 10));
  printf("sim seed=%llu cycles=%u\n", (unsigned long long)g_seed, g_cycles);
  Rng rng(g_seed);
  g_mutant = 0;
  for (uint32_t i = 0; i < g_cycles && g_fail.empty(); i++) runCycle(rng, i);
  TEST_ASSERT_TRUE_MESSAGE(g_fail.empty(), g_fail.c_str());
}

// The identity, erase and commit-without-handshake invariants must be able to FAIL: each mutant of
// the model has to trip its own check within a bounded number of cycles.
void test_sim_invariants_can_fail() {
  const char* expect[] = {"", "identity changed", "NVS erased", "config persisted outside"};
  for (int m = 1; m <= 3; m++) {
    g_mutant = m;
    g_fail.clear();
    Rng rng(12345 + m);
    for (uint32_t i = 0; i < 4000 && g_fail.empty(); i++) runCycle(rng, i);
    g_mutant = 0;
    TEST_ASSERT_FALSE_MESSAGE(g_fail.empty(), expect[m]);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_fail.c_str(), expect[m]), g_fail.c_str());
  }
  g_fail.clear();
}

int main() {
  UNITY_BEGIN();
  RUN_TEST(test_sim_randomized_fault_cycles);
  RUN_TEST(test_sim_invariants_can_fail);
  return UNITY_END();
}
