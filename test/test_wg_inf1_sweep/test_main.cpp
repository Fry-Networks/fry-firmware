// INF-1 randomized equivalence sweep (host-side, deterministic, seeded).
//
// Purpose: replace "50 hardware cycles per board" with >= 1000 simulated cycles per arm that drive
// the REAL fry_core decision code against a model of the WireGuard library's keypair lifecycle.
//
// REAL code driven here (lib/fry_core/wg_recover2.{h,cpp}):
//   fry::wgPeerHealthy, fry::kWgHandshakeDeadS, fry::kWg2DeadAfterS, fry::kWg2TimerDiv,
//   fry::kWg2StageAWindowS, fry::kWg2JitterMaxS, fry::WgRecover2 (decide, onReResolved), fry::WgTrial.
// MODELED (and only this):
//   1. The WireGuard library: keypair lifecycle and the pre-fix verdict (see WgBoard below).
//   2. The firmware glue in src/esp32/vpn_wireguard.cpp recoverTick() (~:505-640): a 5 s tick
//      (WG_RECOVER_TICK_MS), decide() fed armed/up/wifiUp/nowMs/hostnameEndpoint/jitterS/...,
//      ReResolve => teardown + rebuild + onReResolved(changed), ReProvision => blocking POST +
//      WgTrial; peerHealthy() => wgPeerHealthy(libUp, haveHs, ageS) (vpn_wireguard.cpp:63-70).
//   3. The hub/network: hub drops the peer at removal; a ReProvision POST re-adds it.
// WireGuard protocol constants (vendored .pio/libdeps/esp32/esp_wireguard/src):
//   REKEY_AFTER_TIME 120 s, REJECT_AFTER_TIME 180 s, REKEY_TIMEOUT 5 s: wireguard.h:74-76
//   rekey flag on send when initiator keypair age >= REKEY_AFTER_TIME: wireguardif.c:179
//   rekey flag on receive when initiator age >= REJECT - keepalive - REKEY_TIMEOUT: wireguardif.c:320
//   keepalive due after keepalive_interval since last tx, only while a keypair is valid: wireguardif.c:869-871
//   keepalive/data send needs curr keypair, curr destroyed at REJECT_AFTER_TIME: wireguardif.c:123,882-884
//   initiation allowed REKEY_TIMEOUT after the last one: wireguardif.c:89; start condition: :856-860
//   new handshake: curr->prev, new curr, latest_handshake = new keypair time: wireguard.c:473-495
//   verdict curr.valid || prev.valid (prev never expired): wireguardif.c:721
//   keepalive 25 s = the hub-provisioned persistent_keepalive (wg_provision_client.cpp:222).
// Seed: env INF1_SWEEP_SEED (decimal or 0x hex), else -DINF1_SWEEP_SEED, else the fixed default.
// QA timer variant: PLATFORMIO_BUILD_FLAGS=-DFRY_QA_COMPRESSED_TIMERS=1
#include <unity.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

#include "wg_recover2.h"

using fry::WgRecover2;
using fry::WgRecover2Input;
using fry::WgRecoverAction;

void setUp() {}
void tearDown() {}

namespace {

#ifndef INF1_SWEEP_SEED
#define INF1_SWEEP_SEED 0x1F1A5EED2026ULL
#endif

// WireGuard protocol constants (cited above).
constexpr uint32_t kRekeyAfterS = 120;   // wireguard.h:74
constexpr uint32_t kRejectAfterS = 180;  // wireguard.h:75
constexpr uint32_t kRekeyTimeoutS = 5;   // wireguard.h:76
constexpr uint32_t kKeepaliveS = 25;     // hub-provisioned persistent_keepalive
constexpr uint32_t kTickS = 5;           // WG_RECOVER_TICK_MS = 5000 (vpn_wireguard.cpp), real seconds in every build
constexpr uint32_t kPostMinS = 1, kPostMaxS = 8;  // blocking provisioning POST (8 s bounded client timeout)
constexpr uint32_t kHsAfterPostMinS = 1, kHsAfterPostMaxS = 5;
constexpr uint32_t kRebuildMinS = 1, kRebuildMaxS = 3;  // modeled: teardown + DNS + bringUp (ReResolve)

constexpr int kCyclesPerArm = 2000;
constexpr uint32_t kDeadPeerHorizonS = 3600;  // pre-fix "never recovers" horizon after removal
constexpr uint32_t kHealthyHorizonS = 7300;   // > 2 h simulated per healthy cycle

struct Rng {
  uint64_t s;
  uint64_t next() {  // splitmix64
    uint64_t z = (s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
  }
  uint32_t range(uint32_t lo, uint32_t hi) { return lo + static_cast<uint32_t>(next() % (hi - lo + 1)); }
  bool chance(uint32_t num, uint32_t den) { return next() % den < num; }
};

uint64_t seedValue() {
  const char* e = std::getenv("INF1_SWEEP_SEED");
  if (e && *e) return std::strtoull(e, nullptr, 0);
  return static_cast<uint64_t>(INF1_SWEEP_SEED);
}

struct Scn {
  uint32_t removalAgeS;   // session age at peer removal: 0..600
  bool hostname;
  uint32_t jitterS;       // 0..kWg2JitterMaxS (firmware: wgRecoverJitterS % (kWg2JitterMaxS+1))
  uint32_t txPhase;       // keepalive tx phase 0..24
  uint32_t rxPhase;       // hub keepalive rx phase 0..24
  uint32_t tickPhase;     // 0..kTickS-1
  uint32_t postS;         // ReProvision POST duration
  uint32_t hsAfterPostS;  // handshake delay after POST
  uint32_t rebuildS;      // ReResolve rebuild
  bool ipChangedFirst;    // first re-resolve moves the IP (restarts the dead clock once)
  uint64_t subSeed;       // healthy-arm lost-initiation stream
};

Scn genScn(Rng& r) {
  Scn s;
  s.removalAgeS = r.range(0, 600);
  s.hostname = r.chance(1, 2);
  s.jitterS = r.range(0, fry::kWg2JitterMaxS);
  s.txPhase = r.range(0, kKeepaliveS - 1);
  s.rxPhase = r.range(0, kKeepaliveS - 1);
  s.tickPhase = r.range(0, kTickS - 1);
  s.postS = r.range(kPostMinS, kPostMaxS);
  s.hsAfterPostS = r.range(kHsAfterPostMinS, kHsAfterPostMaxS);
  s.rebuildS = r.range(kRebuildMinS, kRebuildMaxS);
  s.ipChangedFirst = r.chance(1, 4);
  s.subSeed = r.next();
  return s;
}

// ---- modeled WireGuard board + hub (1 s resolution) -------------------------------------------
struct Keypair { bool valid = false; int64_t birth = 0; };
struct WgBoard {
  Keypair curr, prev;
  int64_t latestHs = -1;          // < 0: no handshake (esp_wireguard_latest_handshake fails)
  int64_t lastTx = 0, lastInitTx = -1000000;
  bool sendHs = false;
  int64_t hsDueAt = -1;           // initiation in flight, completes at this time
  bool hubAlive = true;
  int64_t hubAliveAt = -1;        // hub accepts again from this time (ReProvision POST done)
  int64_t forceInitAt = -1;
  uint32_t lostLeft = 0;          // healthy arm: consecutive initiations to lose
  uint32_t txPhase = 0, rxPhase = 0;
  void teardown(int64_t t) {      // fresh netif: no keypairs, no handshake
    curr = Keypair(); prev = Keypair(); latestHs = -1; sendHs = false; hsDueAt = -1;
    lastInitTx = -1000000; lastTx = t;
  }
  bool libUp() const { return curr.valid || prev.valid; }  // wireguardif.c:721
};

struct Result {
  bool recovered = false;
  int64_t tRecover = -1;          // seconds from removal to WgTrial Commit
  bool prevValidAtRemoval = false;
  bool currValidAtRemoval = false;
  bool rekeyedBeforeRemoval = false;
  uint32_t actions = 0, actionsBeforeRemoval = 0, reresolves = 0, reprovisions = 0;
  uint32_t maxAgeSeenS = 0;       // true handshake age at any second
  uint32_t maxAgeAtTickS = 0;
  uint32_t maxDownRunS = 0;       // longest continuous run of up==false ticks (seconds)
  uint32_t downTicks = 0;
  uint32_t rollbacks = 0;
};

// Runs one scenario. healthy: hub never removes the peer (arm C), lost initiations are injected.
Result simulate(const Scn& sc, bool fixedArm, bool healthy, uint32_t horizonAfterRemovalS) {
  Result res;
  WgBoard b;
  b.txPhase = sc.txPhase; b.rxPhase = sc.rxPhase;
  Rng sub{sc.subSeed};
  const int64_t R = healthy ? INT64_C(1) << 40 : static_cast<int64_t>(sc.removalAgeS);
  const int64_t end = healthy ? static_cast<int64_t>(kHealthyHorizonS) : R + horizonAfterRemovalS;
  // initial session: first handshake at t=0
  b.curr = {true, 0}; b.latestHs = 0; b.lastTx = -static_cast<int64_t>(sc.txPhase);

  WgRecover2 rec;
  fry::WgTrial trial;
  bool changedPending = sc.ipChangedFirst;  // consumed by the first ReResolve
  int64_t busyUntil = -1;                   // blocking glue work (rebuild / POST)
  bool downRun = false; int64_t downRunStart = 0;
  const uint32_t baseMs = 1000000u;
  bool markedRemoval = false;

  for (int64_t t = 0; t <= end; ++t) {
    if (!healthy && !markedRemoval && t >= R) {
      markedRemoval = true;
      b.hubAlive = false;
      res.prevValidAtRemoval = b.prev.valid;
      res.currValidAtRemoval = b.curr.valid;
    }
    if (b.hubAliveAt >= 0 && t >= b.hubAliveAt) { b.hubAlive = true; b.hubAliveAt = -1; }

    // 1. library timers (wireguardif_tmr)
    if (b.curr.valid && t - b.curr.birth >= static_cast<int64_t>(kRejectAfterS)) b.curr.valid = false;
    // 2. in-flight initiation completes
    if (b.hsDueAt >= 0 && t >= b.hsDueAt) {
      b.hsDueAt = -1;
      if (b.hubAlive) {  // wireguard.c add_new_keypair: curr->prev, new curr, latest handshake
        b.prev = b.curr; b.curr = {true, t}; b.latestHs = t;
        if (!markedRemoval || healthy) res.rekeyedBeforeRemoval = true;
      }
    }
    // 3. tx: keepalive needs a valid keypair for the due check but the send itself needs curr
    if ((b.curr.valid || b.prev.valid) && (t - b.lastTx >= static_cast<int64_t>(kKeepaliveS))) {
      if (b.curr.valid) {
        b.lastTx = t;
        if (t - b.curr.birth >= static_cast<int64_t>(kRekeyAfterS)) b.sendHs = true;  // wireguardif.c:179
      }
    }
    // 3b. rx: hub keepalive every 25 s on a live peer (phase random); wireguardif.c:320
    if (b.hubAlive && b.curr.valid && ((t + b.rxPhase) % kKeepaliveS == 0) &&
        t - b.curr.birth >= static_cast<int64_t>(kRejectAfterS - kKeepaliveS - kRekeyTimeoutS)) {
      b.sendHs = true;
    }
    // 4. initiation decision (wireguardif.c:856-860 + :89)
    const bool canSend = (t - b.lastInitTx) >= static_cast<int64_t>(kRekeyTimeoutS);
    if (b.forceInitAt >= 0 && t >= b.forceInitAt) {  // ReProvision: first initiation after rebuild
      b.forceInitAt = -1; b.lastInitTx = t; b.hsDueAt = t + 1; b.sendHs = false;
    } else if (b.forceInitAt < 0 && canSend && b.hsDueAt < 0 && (b.sendHs || !b.curr.valid) &&
               !(b.hubAliveAt >= 0)) {
      b.lastInitTx = t; b.sendHs = false;
      if (healthy && b.lostLeft == 0 && b.curr.valid && sub.chance(1, 3)) b.lostLeft = sub.range(0, 2);
      if (healthy && b.lostLeft > 0) { --b.lostLeft; }  // initiation lost: no completion
      else b.hsDueAt = t + 1;
    }

    // true handshake age (any second), only meaningful with a handshake
    if (b.latestHs >= 0 && (healthy || !markedRemoval)) {
      res.maxAgeSeenS = std::max<uint32_t>(res.maxAgeSeenS, static_cast<uint32_t>(t - b.latestHs));
    }

    // ---- firmware glue tick -----------------------------------------------------------------
    if (t < busyUntil) continue;
    if ((t + kTickS - sc.tickPhase) % kTickS != 0) continue;
    const uint32_t nowMs = baseMs + static_cast<uint32_t>(t) * 1000u;
    const bool haveHs = b.latestHs >= 0;
    const uint32_t ageS = (haveHs && t > b.latestHs) ? static_cast<uint32_t>(t - b.latestHs) : 0;
    const bool up = fixedArm ? fry::wgPeerHealthy(b.libUp(), haveHs, ageS) : b.libUp();
    if (haveHs) res.maxAgeAtTickS = std::max(res.maxAgeAtTickS, ageS);
    if (!up) { ++res.downTicks; if (!downRun) { downRun = true; downRunStart = t; } }
    else if (downRun) { downRun = false; res.maxDownRunS = std::max<uint32_t>(res.maxDownRunS, static_cast<uint32_t>(t - downRunStart)); }
    if (downRun) res.maxDownRunS = std::max<uint32_t>(res.maxDownRunS, static_cast<uint32_t>(t - downRunStart));

    if (trial.active()) {  // recoverTick: trial owns the tick
      fry::WgTrialEvent ev = trial.tick(up, nowMs, true);
      if (ev == fry::WgTrialEvent::Commit) { res.recovered = true; res.tRecover = t - R; return res; }
      if (ev == fry::WgTrialEvent::Rollback) ++res.rollbacks;
      continue;
    }
    WgRecover2Input in;
    in.armed = true;  // s_initialized || s_recovering
    in.up = up;
    in.wifiUp = true;
    in.nowMs = nowMs;
    in.hostnameEndpoint = sc.hostname;
    in.otaBusy = false;
    in.clockSynced = true;
    in.provBlocked = false;
    in.hostResolves = true;
    in.jitterS = sc.jitterS;
    in.epochNow = 1790000000u + static_cast<uint32_t>(t);
    in.lastStageBEpoch = 0;
    WgRecoverAction act = rec.decide(in);
    if (act == WgRecoverAction::None) continue;
    ++res.actions;
    if (!healthy && t < R) ++res.actionsBeforeRemoval;
    if (healthy) continue;  // arm C only counts; no state change needed past a (failed) assertion
    if (act == WgRecoverAction::ReResolve) {
      ++res.reresolves;
      b.teardown(t);  // netif rebuilt, hub still has no peer: no handshake
      busyUntil = t + sc.rebuildS;
      const bool changed = changedPending; changedPending = false;
      // glue calls s_recover.onReResolved(changed, millis()) when bringUp completes
      rec.onReResolved(changed, baseMs + static_cast<uint32_t>(busyUntil) * 1000u);
    } else {  // ReProvision
      ++res.reprovisions;
      b.teardown(t);
      busyUntil = t + sc.postS;                         // blocking POST
      b.hubAliveAt = t + sc.postS + sc.hsAfterPostS - 1;  // hub re-adds the peer
      b.forceInitAt = b.hubAliveAt;                     // first initiation of the rebuilt netif
      trial.begin(baseMs + static_cast<uint32_t>(busyUntil) * 1000u);
    }
  }
  return res;
}

// bound (seconds from removal) derived from the real constants; see test output
uint32_t boundS(bool hostname) {
  const uint32_t T = kTickS, jit = fry::kWg2JitterMaxS;
  const uint32_t tail = kPostMaxS + kHsAfterPostMaxS + T;  // POST + handshake + trial-commit tick
  if (!hostname) {
    // detect (age>=T1 then one tick) + dead window + jitter (+tick) + POST+handshake+commit tick
    return fry::kWgHandshakeDeadS + T + fry::kWg2DeadAfterS + jit + T + tail;
  }
  // detect + [dead window + tick + rebuild] x2 (first re-resolve may move the IP: dead clock
  // restarts once) + stage-A grace + jitter + tick + tail
  return fry::kWgHandshakeDeadS + T + 2 * (fry::kWg2DeadAfterS + T + kRebuildMaxS) +
         fry::kWg2StageAWindowS + jit + T + tail;
}

std::vector<Scn> g_scn, g_healthy;
uint64_t g_seed = 0;

void genAll() {
  if (!g_scn.empty()) return;
  g_seed = seedValue();
  Rng r{g_seed};
  for (int i = 0; i < kCyclesPerArm; ++i) g_scn.push_back(genScn(r));
  for (int i = 0; i < kCyclesPerArm; ++i) g_healthy.push_back(genScn(r));
  std::printf("INF1 sweep: seed=0x%llx cycles/arm=%d kWg2TimerDiv=%u kWgHandshakeDeadS=%u kWg2DeadAfterS=%u "
              "kWg2JitterMaxS=%u kWg2StageAWindowS=%u\n",
              static_cast<unsigned long long>(g_seed), kCyclesPerArm, static_cast<unsigned>(fry::kWg2TimerDiv),
              static_cast<unsigned>(fry::kWgHandshakeDeadS), static_cast<unsigned>(fry::kWg2DeadAfterS),
              static_cast<unsigned>(fry::kWg2JitterMaxS), static_cast<unsigned>(fry::kWg2StageAWindowS));
}

const char* ageClass(uint32_t a) { return a < kRekeyAfterS ? "young(<120)" : (a < kRejectAfterS ? "rekeyed-zone(120-180)" : "aged(>=180)"); }
int ageIdx(uint32_t a) { return a < kRekeyAfterS ? 0 : (a < kRejectAfterS ? 1 : 2); }

struct Stats { std::vector<int64_t> v; };
void printStats(const char* label, std::vector<int64_t> v) {
  if (v.empty()) { std::printf("  %-14s n=0\n", label); return; }
  std::sort(v.begin(), v.end());
  std::printf("  %-14s n=%zu min=%lld median=%lld p95=%lld max=%lld\n", label, v.size(),
              static_cast<long long>(v.front()), static_cast<long long>(v[v.size() / 2]),
              static_cast<long long>(v[(v.size() * 95) / 100]), static_cast<long long>(v.back()));
}

}  // namespace

void test_bound_is_derived_from_constants() {
  genAll();
  std::printf("INF1 bound: non-hostname = kWgHandshakeDeadS(%u) + T(%u) + kWg2DeadAfterS(%u) + jitterMax(%u) + T(%u) + [POST max %u + hs max %u + commit tick %u] = %u s\n",
              (unsigned)fry::kWgHandshakeDeadS, (unsigned)kTickS, (unsigned)fry::kWg2DeadAfterS,
              (unsigned)fry::kWg2JitterMaxS, (unsigned)kTickS, (unsigned)kPostMaxS, (unsigned)kHsAfterPostMaxS,
              (unsigned)kTickS, (unsigned)boundS(false));
  std::printf("INF1 bound: hostname     = kWgHandshakeDeadS + T + 2*(kWg2DeadAfterS + T + rebuildMax %u) + kWg2StageAWindowS(%u) + jitterMax + T + tail = %u s\n",
              (unsigned)kRebuildMaxS, (unsigned)fry::kWg2StageAWindowS, (unsigned)boundS(true));
  TEST_ASSERT_TRUE(boundS(false) > fry::kWgHandshakeDeadS);
}

void test_arm_a_fixed_dead_peer_always_recovers() {
  genAll();
  std::vector<int64_t> host, raw;
  int cls[3] = {0, 0, 0}, clsRec[3] = {0, 0, 0};
  int fail = 0, overBound = 0, early = 0, rollbacks = 0, prevAtR = 0, firstFail = -1;
  for (int i = 0; i < kCyclesPerArm; ++i) {
    const Scn& s = g_scn[i];
    Result r = simulate(s, /*fixedArm=*/true, /*healthy=*/false, kDeadPeerHorizonS);
    const int ci = ageIdx(s.removalAgeS);
    ++cls[ci];
    if (r.prevValidAtRemoval) ++prevAtR;
    if (r.actionsBeforeRemoval) ++early;
    rollbacks += r.rollbacks;
    if (!r.recovered) { ++fail; if (firstFail < 0) firstFail = i; continue; }
    ++clsRec[ci];
    if (r.tRecover > static_cast<int64_t>(boundS(s.hostname))) ++overBound;
    (s.hostname ? host : raw).push_back(r.tRecover);
  }
  std::printf("ARM A (FIXED, dead peer) cycles=%d recovered=%zu not_recovered=%d over_bound=%d actions_before_removal=%d trial_rollbacks=%d prev_valid_at_removal=%d\n",
              kCyclesPerArm, host.size() + raw.size(), fail, overBound, early, rollbacks, prevAtR);
  for (int c = 0; c < 3; ++c)
    std::printf("  class %-22s cycles=%d recovered=%d\n", c == 0 ? "young(<120)" : (c == 1 ? "rekeyed-zone(120-180)" : "aged(>=180)"), cls[c], clsRec[c]);
  std::printf("  time-to-recover from removal (s), bound raw=%u hostname=%u\n", (unsigned)boundS(false), (unsigned)boundS(true));
  printStats("raw-IP", raw);
  printStats("hostname", host);
  if (firstFail >= 0) std::printf("  first failing scenario index=%d removalAgeS=%u hostname=%d\n", firstFail, (unsigned)g_scn[firstFail].removalAgeS, (int)g_scn[firstFail].hostname);
  TEST_ASSERT_EQUAL_INT(0, fail);
  TEST_ASSERT_EQUAL_INT(0, overBound);
  TEST_ASSERT_EQUAL_INT(0, early);
  TEST_ASSERT_EQUAL_INT(0, rollbacks);
  TEST_ASSERT_TRUE(prevAtR > 100);  // control: the aged (prev-valid) class is actually exercised
}

void test_arm_b_prefix_aged_never_recovers_young_does() {
  genAll();
  int prevN = 0, prevRec = 0, noPrevN = 0, noPrevRec = 0, noPrevOver = 0;
  int tab[3][2] = {{0, 0}, {0, 0}, {0, 0}};      // [class][prev valid at removal] count
  int tabRec[3][2] = {{0, 0}, {0, 0}, {0, 0}};
  std::vector<int64_t> youngT;
  for (int i = 0; i < kCyclesPerArm; ++i) {
    const Scn& s = g_scn[i];
    Result r = simulate(s, /*fixedArm=*/false, /*healthy=*/false, kDeadPeerHorizonS);
    const int ci = ageIdx(s.removalAgeS), pv = r.prevValidAtRemoval ? 1 : 0;
    ++tab[ci][pv]; if (r.recovered) ++tabRec[ci][pv];
    if (pv) { ++prevN; if (r.recovered) ++prevRec; }
    else {
      ++noPrevN; if (r.recovered) { ++noPrevRec; youngT.push_back(r.tRecover); if (r.tRecover > static_cast<int64_t>(boundS(s.hostname)) + kRejectAfterS) ++noPrevOver; }
    }
  }
  std::printf("ARM B (PRE-FIX libSaysUp, dead peer, horizon %u s after removal) cycles=%d\n", (unsigned)kDeadPeerHorizonS, kCyclesPerArm);
  std::printf("  prev-valid-at-removal (rekeyed before removal): n=%d recovered=%d\n", prevN, prevRec);
  std::printf("  no-prev-at-removal (never rekeyed, young):     n=%d recovered=%d\n", noPrevN, noPrevRec);
  for (int c = 0; c < 3; ++c)
    std::printf("  class %-22s prev=0: n=%d rec=%d | prev=1: n=%d rec=%d\n", c == 0 ? "young(<120)" : (c == 1 ? "rekeyed-zone(120-180)" : "aged(>=180)"), tab[c][0], tabRec[c][0], tab[c][1], tabRec[c][1]);
  printStats("young-recovered", youngT);
  TEST_ASSERT_TRUE(prevN > 100);
  TEST_ASSERT_EQUAL_INT(0, prevRec);                 // THE BUG: rekeyed sessions never recover
  TEST_ASSERT_EQUAL_INT(noPrevN, noPrevRec);         // young sessions do recover
  TEST_ASSERT_EQUAL_INT(0, noPrevOver);
  TEST_ASSERT_EQUAL_INT(0, tab[2][0]);               // aged (>=180 s) sessions are all prev-valid
  TEST_ASSERT_EQUAL_INT(0, tabRec[2][1]);
}

void test_arm_c_fixed_healthy_never_acts() {
  genAll();
  int acts = 0, cyc = 0, downCycles = 0, lostCycles = 0;
  uint32_t maxSeen = 0, maxTick = 0, maxDown = 0;
  uint64_t totalDownTicks = 0;
  for (int i = 0; i < kCyclesPerArm; ++i) {
    Result r = simulate(g_healthy[i], /*fixedArm=*/true, /*healthy=*/true, 0);
    ++cyc; acts += r.actions;
    if (r.downTicks) ++downCycles;
    totalDownTicks += r.downTicks;
    maxSeen = std::max(maxSeen, r.maxAgeSeenS); maxTick = std::max(maxTick, r.maxAgeAtTickS);
    maxDown = std::max(maxDown, r.maxDownRunS);
    if (r.maxAgeSeenS >= kRejectAfterS) ++lostCycles;
  }
  std::printf("ARM C (FIXED, healthy board, %u s simulated per cycle) cycles=%d recovery_actions=%d\n", (unsigned)kHealthyHorizonS, cyc, acts);
  std::printf("  max handshake age: any-second=%u s, at-tick=%u s vs kWgHandshakeDeadS=%u (cycles reaching >=T1 via lost initiations: %d, cycles with any up==false tick: %d, total down ticks: %llu, longest continuous down run %u s vs kWg2DeadAfterS=%u)\n",
              (unsigned)maxSeen, (unsigned)maxTick, (unsigned)fry::kWgHandshakeDeadS, lostCycles, downCycles,
              (unsigned long long)totalDownTicks, (unsigned)maxDown, (unsigned)fry::kWg2DeadAfterS);
  TEST_ASSERT_EQUAL_INT(0, acts);
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_bound_is_derived_from_constants);
  RUN_TEST(test_arm_a_fixed_dead_peer_always_recovers);
  RUN_TEST(test_arm_b_prefix_aged_never_recovers_young_does);
  RUN_TEST(test_arm_c_fixed_healthy_never_acts);
  return UNITY_END();
}
