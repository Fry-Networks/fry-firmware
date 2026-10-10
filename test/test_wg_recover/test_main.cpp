// Dead-tunnel recovery decision logic (lib/fry_core/wg_recover.h).
//
// Bench evidence: with the server peer removed, a board on 0.4.1 kept re-initiating to the same
// cached endpoint forever (vpn=down, no provision POST in 5 min). These tests pin the staged
// recovery: A = re-resolve the hostname, B = clear ONLY fry_vpn and let the provision client POST
// again; never during OTA, never with an unsynced clock, at most once per hour.
#include <unity.h>

#include <cstring>
#include <string>
#include <vector>

#include "wg_recover.h"

using fry::WgRecover;
using fry::WgRecoverAction;
using fry::WgRecoverInput;

namespace {

constexpr uint32_t kS = 1000;  // ms per second
constexpr uint32_t kEpoch = 1790000000;  // a plausible synced wall clock

WgRecover rec;

WgRecoverInput base(uint32_t atS, bool up, bool hostname) {
  WgRecoverInput in;
  in.armed = true;
  in.up = up;
  in.wifiUp = true;
  in.nowMs = atS * kS;
  in.hostnameEndpoint = hostname;
  in.otaBusy = false;
  in.clockSynced = true;
  in.provBlocked = false;
  in.epochNow = kEpoch;
  in.lastStageBEpoch = 0;
  in.apiReachable = true;
  in.jitterS = 0;
  return in;
}

// Walk a dead tunnel from t=0 in 30 s steps up to (and including) `uptoS`, returning the first
// non-None action together with the time it fired (or None/0).
struct Fired {
  WgRecoverAction action = WgRecoverAction::None;
  uint32_t atS = 0;
};
Fired walkDead(uint32_t uptoS, bool hostname) {
  for (uint32_t t = 0; t <= uptoS; t += 30) {
    WgRecoverAction a = rec.decide(base(t, false, hostname));
    if (a != WgRecoverAction::None) return {a, t};
  }
  return {};
}

void test_alive_tunnel_never_acts() {
  for (uint32_t t = 0; t < 5 * 3600; t += 60) {
    TEST_ASSERT_EQUAL((int)WgRecoverAction::None, (int)rec.decide(base(t, true, true)));
  }
}

void test_dead_below_threshold_no_action() {
  Fired f = walkDead(fry::kWgDeadAfterS - 30, true);
  TEST_ASSERT_EQUAL((int)WgRecoverAction::None, (int)f.action);
}

void test_threshold_is_in_the_10_to_15_minute_band() {
  TEST_ASSERT_TRUE(fry::kWgDeadAfterS >= 600);
  TEST_ASSERT_TRUE(fry::kWgDeadAfterS <= 900);
  // At least two of WireGuard's own give-up cycles (REJECT_AFTER_TIME 180 s + REKEY_ATTEMPT 90 s).
  TEST_ASSERT_TRUE(fry::kWgDeadAfterS >= 2 * (180 + 90));
}

void test_hostname_dead_past_threshold_goes_to_stage_a() {
  Fired f = walkDead(fry::kWgDeadAfterS + 60, true);
  TEST_ASSERT_EQUAL((int)WgRecoverAction::ReResolve, (int)f.action);
  TEST_ASSERT_TRUE(f.atS >= fry::kWgDeadAfterS);
}

void test_stage_a_fires_once_not_every_tick() {
  Fired f = walkDead(fry::kWgDeadAfterS + 60, true);
  TEST_ASSERT_EQUAL((int)WgRecoverAction::ReResolve, (int)f.action);
  for (uint32_t t = f.atS + 1; t < f.atS + fry::kWgStageAWindowS; t += 5) {
    TEST_ASSERT_EQUAL((int)WgRecoverAction::None, (int)rec.decide(base(t, false, true)));
  }
}

void test_stage_a_without_ip_change_goes_to_stage_b_after_window() {
  Fired a = walkDead(fry::kWgDeadAfterS + 60, true);
  TEST_ASSERT_EQUAL((int)WgRecoverAction::ReResolve, (int)a.action);
  rec.onReResolved(/*ipChanged=*/false, a.atS * kS);
  uint32_t due = a.atS + fry::kWgStageAWindowS;
  TEST_ASSERT_EQUAL((int)WgRecoverAction::None, (int)rec.decide(base(due - 5, false, true)));
  TEST_ASSERT_EQUAL((int)WgRecoverAction::ReProvision, (int)rec.decide(base(due, false, true)));
}

void test_stage_b_also_fires_if_stage_a_never_completes() {
  // DNS keeps failing: onReResolved is never called. B must still come after the window.
  Fired a = walkDead(fry::kWgDeadAfterS + 60, true);
  uint32_t due = a.atS + fry::kWgStageAWindowS;
  TEST_ASSERT_EQUAL((int)WgRecoverAction::ReProvision, (int)rec.decide(base(due, false, true)));
}

void test_stage_a_ip_change_restarts_the_dead_clock() {
  Fired a = walkDead(fry::kWgDeadAfterS + 60, true);
  rec.onReResolved(/*ipChanged=*/true, a.atS * kS);
  // Still dead right after: nothing for a full threshold, so the new endpoint gets its chance.
  for (uint32_t t = a.atS + 5; t < a.atS + fry::kWgDeadAfterS; t += 30) {
    TEST_ASSERT_EQUAL((int)WgRecoverAction::None, (int)rec.decide(base(t, false, true)));
  }
}

void test_handshake_recovery_resets_everything() {
  Fired a = walkDead(fry::kWgDeadAfterS + 60, true);
  TEST_ASSERT_EQUAL((int)WgRecoverAction::ReResolve, (int)a.action);
  TEST_ASSERT_EQUAL((int)WgRecoverAction::None, (int)rec.decide(base(a.atS + 10, true, true)));
  // A later outage starts from scratch: stage A again, not stage B.
  uint32_t t0 = a.atS + 20;
  WgRecoverAction act = WgRecoverAction::None;
  for (uint32_t t = t0; t <= t0 + fry::kWgDeadAfterS + 60; t += 30) {
    act = rec.decide(base(t, false, true));
    if (act != WgRecoverAction::None) break;
  }
  TEST_ASSERT_EQUAL((int)WgRecoverAction::ReResolve, (int)act);
}

void test_ip_literal_goes_straight_to_stage_b() {
  Fired f = walkDead(fry::kWgDeadAfterS + 60, false);
  TEST_ASSERT_EQUAL((int)WgRecoverAction::ReProvision, (int)f.action);
  TEST_ASSERT_TRUE(f.atS >= fry::kWgDeadAfterS);
}

void test_stage_b_rate_limited_to_once_per_hour() {
  WgRecoverInput in;
  for (uint32_t t = 0; t <= fry::kWgDeadAfterS + 60; t += 30) {
    in = base(t, false, false);
    in.lastStageBEpoch = kEpoch - (fry::kWgStageBMinIntervalS - 60);  // 59 min ago
    TEST_ASSERT_EQUAL((int)WgRecoverAction::None, (int)rec.decide(in));
  }
  // The hour elapses while the tunnel stays dead: it fires on the very next tick.
  in = base(fry::kWgDeadAfterS + 90, false, false);
  in.lastStageBEpoch = kEpoch - fry::kWgStageBMinIntervalS;
  TEST_ASSERT_EQUAL((int)WgRecoverAction::ReProvision, (int)rec.decide(in));
}

void test_rate_limit_survives_a_reboot_because_it_is_an_input() {
  // A reboot wipes WgRecover (RAM) but the caller feeds the persisted epoch back in.
  WgRecover fresh;
  WgRecoverInput in;
  for (uint32_t t = 0; t <= fry::kWgDeadAfterS + 120; t += 30) {
    in = base(t, false, false);
    in.lastStageBEpoch = kEpoch - 600;  // 10 min ago, i.e. a reboot loop
    TEST_ASSERT_EQUAL((int)WgRecoverAction::None, (int)fresh.decide(in));
  }
}

void test_stage_b_after_stage_b_resets_state_and_requires_full_threshold_again() {
  Fired f = walkDead(fry::kWgDeadAfterS + 60, false);
  TEST_ASSERT_EQUAL((int)WgRecoverAction::ReProvision, (int)f.action);
  for (uint32_t t = f.atS + 5; t < f.atS + fry::kWgDeadAfterS; t += 30) {
    WgRecoverInput in = base(t, false, false);
    in.lastStageBEpoch = kEpoch;  // just persisted
    TEST_ASSERT_EQUAL((int)WgRecoverAction::None, (int)rec.decide(in));
  }
}

void test_ota_busy_blocks_every_action() {
  for (uint32_t t = 0; t <= 3 * fry::kWgDeadAfterS; t += 30) {
    WgRecoverInput in = base(t, false, true);
    in.otaBusy = true;
    TEST_ASSERT_EQUAL((int)WgRecoverAction::None, (int)rec.decide(in));
  }
  // The moment OTA settles, a long-dead tunnel is acted on.
  TEST_ASSERT_EQUAL((int)WgRecoverAction::ReResolve,
                    (int)rec.decide(base(3 * fry::kWgDeadAfterS + 30, false, true)));
}

void test_unsynced_clock_blocks_stage_b_but_not_stage_a() {
  Fired a = walkDead(fry::kWgDeadAfterS + 60, true);
  TEST_ASSERT_EQUAL((int)WgRecoverAction::ReResolve, (int)a.action);
  uint32_t due = a.atS + fry::kWgStageAWindowS;
  WgRecoverInput in = base(due, false, true);
  in.clockSynced = false;
  TEST_ASSERT_EQUAL((int)WgRecoverAction::None, (int)rec.decide(in));
  TEST_ASSERT_EQUAL((int)WgRecoverAction::ReProvision, (int)rec.decide(base(due + 30, false, true)));
}

void test_unsynced_clock_ip_literal_never_stage_b() {
  for (uint32_t t = 0; t <= 2 * fry::kWgDeadAfterS; t += 30) {
    WgRecoverInput in = base(t, false, false);
    in.clockSynced = false;
    TEST_ASSERT_EQUAL((int)WgRecoverAction::None, (int)rec.decide(in));
  }
}

void test_provision_backoff_blocks_stage_b() {
  for (uint32_t t = 0; t <= 2 * fry::kWgDeadAfterS; t += 30) {
    WgRecoverInput in = base(t, false, false);
    in.provBlocked = true;  // a 401/403/429 backoff is still running
    TEST_ASSERT_EQUAL((int)WgRecoverAction::None, (int)rec.decide(in));
  }
}

void test_wifi_down_does_not_count_as_dead() {
  for (uint32_t t = 0; t <= 4 * fry::kWgDeadAfterS; t += 30) {
    WgRecoverInput in = base(t, false, false);
    in.wifiUp = false;
    TEST_ASSERT_EQUAL((int)WgRecoverAction::None, (int)rec.decide(in));
  }
  // Wi-Fi returns: the dead clock starts only now.
  uint32_t t0 = 4 * fry::kWgDeadAfterS + 30;
  TEST_ASSERT_EQUAL((int)WgRecoverAction::None, (int)rec.decide(base(t0, false, false)));
  TEST_ASSERT_EQUAL((int)WgRecoverAction::None,
                    (int)rec.decide(base(t0 + fry::kWgDeadAfterS - 30, false, false)));
}

void test_not_armed_never_acts() {
  for (uint32_t t = 0; t <= 3 * fry::kWgDeadAfterS; t += 30) {
    WgRecoverInput in = base(t, false, false);
    in.armed = false;
    TEST_ASSERT_EQUAL((int)WgRecoverAction::None, (int)rec.decide(in));
  }
}

void test_millis_wraparound_is_safe() {
  uint32_t start = 0xFFFFFFFFu - 100 * kS;  // 100 s before the 49-day wrap
  WgRecoverAction act = WgRecoverAction::None;
  for (uint32_t t = 0; t <= fry::kWgDeadAfterS + 60; t += 30) {
    WgRecoverInput in = base(0, false, false);
    in.nowMs = start + t * kS;  // wraps mid-walk
    act = rec.decide(in);
    if (act != WgRecoverAction::None) {
      TEST_ASSERT_TRUE(t >= fry::kWgDeadAfterS);
      break;
    }
  }
  TEST_ASSERT_EQUAL((int)WgRecoverAction::ReProvision, (int)act);
}

void test_endpoint_hostname_classifier() {
  TEST_ASSERT_TRUE(fry::wgEndpointIsHostname("vpn.example.net"));
  TEST_ASSERT_TRUE(fry::wgEndpointIsHostname("1vpn.example.net"));
  TEST_ASSERT_TRUE(fry::wgEndpointIsHostname("10.0.0.1.example.net"));
  TEST_ASSERT_FALSE(fry::wgEndpointIsHostname("203.0.113.7"));
  TEST_ASSERT_FALSE(fry::wgEndpointIsHostname("[2001:db8::1]"));
  TEST_ASSERT_FALSE(fry::wgEndpointIsHostname("2001:db8::1"));
  TEST_ASSERT_FALSE(fry::wgEndpointIsHostname(""));
  TEST_ASSERT_FALSE(fry::wgEndpointIsHostname(nullptr));
}

// ── M2: gates and jitter ─────────────────────────────────────────────────────────────────────

void test_api_unreachable_blocks_stage_b_until_it_is_reachable() {
  for (uint32_t t = 0; t <= 2 * fry::kWgDeadAfterS; t += 30) {
    WgRecoverInput in = base(t, false, false);
    in.apiReachable = false;
    TEST_ASSERT_EQUAL((int)WgRecoverAction::None, (int)rec.decide(in));
  }
  TEST_ASSERT_EQUAL((int)WgRecoverAction::ReProvision,
                    (int)rec.decide(base(2 * fry::kWgDeadAfterS + 30, false, false)));
}

void test_api_recent_window() {
  TEST_ASSERT_FALSE(fry::wgApiRecent(-1));
  TEST_ASSERT_TRUE(fry::wgApiRecent(0));
  TEST_ASSERT_TRUE(fry::wgApiRecent((int32_t)fry::kWgApiFreshS));
  TEST_ASSERT_FALSE(fry::wgApiRecent((int32_t)fry::kWgApiFreshS + 1));
}

void test_jitter_is_deterministic_and_in_range() {
  TEST_ASSERT_EQUAL_UINT32(fry::wgRecoverJitterS(0xA4CF12345678ULL),
                           fry::wgRecoverJitterS(0xA4CF12345678ULL));
  bool seen[301] = {};
  int distinct = 0;
  for (uint64_t i = 0; i < 2000; i++) {
    uint32_t j = fry::wgRecoverJitterS(0xA4CF12000000ULL + i);
    TEST_ASSERT_TRUE(j <= fry::kWgJitterMaxS);
    if (!seen[j]) { seen[j] = true; distinct++; }
  }
  TEST_ASSERT_TRUE(distinct > 200);  // spreads a fleet of sequential MACs over the whole range
}

void test_jitter_delays_stage_b_for_an_ip_literal() {
  for (uint32_t t = 0; t < fry::kWgDeadAfterS + 200; t += 10) {
    WgRecoverInput in = base(t, false, false);
    in.jitterS = 200;
    TEST_ASSERT_EQUAL((int)WgRecoverAction::None, (int)rec.decide(in));
  }
  WgRecoverInput in = base(fry::kWgDeadAfterS + 200, false, false);
  in.jitterS = 200;
  TEST_ASSERT_EQUAL((int)WgRecoverAction::ReProvision, (int)rec.decide(in));
}

void test_jitter_delays_stage_b_after_stage_a_but_not_stage_a() {
  Fired a = walkDead(fry::kWgDeadAfterS + 60, true);  // jitter 0 here: A is never jittered
  TEST_ASSERT_EQUAL((int)WgRecoverAction::ReResolve, (int)a.action);
  uint32_t due = a.atS + fry::kWgStageAWindowS;
  WgRecoverInput in = base(due + 99, false, true);
  in.jitterS = 100;
  TEST_ASSERT_EQUAL((int)WgRecoverAction::None, (int)rec.decide(in));
  in = base(due + 100, false, true);
  in.jitterS = 100;
  TEST_ASSERT_EQUAL((int)WgRecoverAction::ReProvision, (int)rec.decide(in));
}

void test_future_stamp_still_rate_limits_but_is_capped() {
  // A stamp 10 days in the future (clock skew, corrupt write) must not wedge recovery forever,
  // yet must not be ignored either: limited for at most kWgStageBMinIntervalS from first sight.
  uint32_t futureStamp = kEpoch + 10 * 86400;
  uint32_t t = fry::kWgDeadAfterS + 30;
  WgRecoverInput in;
  for (uint32_t i = 0; i <= t; i += 30) {
    in = base(i, false, false);
    in.lastStageBEpoch = futureStamp;
    in.epochNow = kEpoch;
    rec.decide(in);
  }
  in = base(t + 30, false, false);
  in.lastStageBEpoch = futureStamp;
  in.epochNow = kEpoch;
  TEST_ASSERT_EQUAL((int)WgRecoverAction::None, (int)rec.decide(in));
  in = base(t + 60, false, false);
  in.lastStageBEpoch = futureStamp;
  in.epochNow = kEpoch + fry::kWgStageBMinIntervalS - 1;
  TEST_ASSERT_EQUAL((int)WgRecoverAction::None, (int)rec.decide(in));
  in = base(t + 90, false, false);
  in.lastStageBEpoch = futureStamp;
  in.epochNow = kEpoch + fry::kWgStageBMinIntervalS;
  TEST_ASSERT_EQUAL((int)WgRecoverAction::ReProvision, (int)rec.decide(in));
}

// ── M1: teardown whenever a netif exists ─────────────────────────────────────────────────────

// Models esp_wireguard.c:237-249: the netif (and the private key baked into it) is created only
// when ctx->netif == NULL; a failed connect leaves it in place.
struct FakeWg : fry::WgTunnelOps {
  bool netif = false;
  int created = 0;
  int teardowns = 0;
  bool teardownFails = false;
  std::string cfgKey = "old";
  std::string netifKey;
  bool hasNetif() override { return netif; }
  bool teardown() override {
    if (teardownFails) return false;
    netif = false;
    teardowns++;
    return true;
  }
  bool bringUp(bool connectOk) {
    if (!netif) {
      netif = true;
      created++;
      netifKey = cfgKey;
    }
    return connectOk;
  }
};

void test_failed_stage_a_reconnect_then_stage_b_gets_a_fresh_netif() {
  FakeWg w;
  TEST_ASSERT_TRUE(w.bringUp(true));  // boot: netif built from the old key
  TEST_ASSERT_TRUE(fry::wgTearDownTunnel(w));  // stage A
  TEST_ASSERT_FALSE(w.bringUp(false));         // re-resolve: netif created, connect FAILS
  TEST_ASSERT_TRUE(w.netif);                   // ...and the old-key netif is still there
  w.cfgKey = "new";                            // stage B committed a rotated key
  TEST_ASSERT_TRUE(fry::wgTearDownTunnel(w));  // must not be skipped just because !initialized
  TEST_ASSERT_TRUE(w.bringUp(true));
  TEST_ASSERT_EQUAL_STRING("new", w.netifKey.c_str());
  TEST_ASSERT_EQUAL(3, w.created);
}

void test_teardown_skipped_without_netif_and_reported_when_it_fails() {
  FakeWg w;
  TEST_ASSERT_TRUE(fry::wgTearDownTunnel(w));
  TEST_ASSERT_EQUAL(0, w.teardowns);
  w.bringUp(true);
  w.teardownFails = true;
  TEST_ASSERT_FALSE(fry::wgTearDownTunnel(w));  // caller keeps the "fresh netif required" flag
  TEST_ASSERT_TRUE(w.netif);
}

// ── M2: the config is replaced only after a validated response ───────────────────────────────

struct FakeWriter : fry::WgRotationWriter {
  int commits = 0;
  void commit() override { commits++; }
};

void test_rotation_failure_leaves_config_untouched() {
  FakeWriter w;
  TEST_ASSERT_EQUAL((int)fry::WgRotationState::Failed, (int)fry::wgRotationFinish(false, &w));
  TEST_ASSERT_EQUAL(0, w.commits);
  TEST_ASSERT_EQUAL((int)fry::WgRotationState::Failed, (int)fry::wgRotationFinish(false, nullptr));
}

void test_rotation_success_commits_exactly_once() {
  FakeWriter w;
  TEST_ASSERT_EQUAL((int)fry::WgRotationState::Committed, (int)fry::wgRotationFinish(true, &w));
  TEST_ASSERT_EQUAL(1, w.commits);
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() { rec = WgRecover(); }
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_alive_tunnel_never_acts);
  RUN_TEST(test_dead_below_threshold_no_action);
  RUN_TEST(test_threshold_is_in_the_10_to_15_minute_band);
  RUN_TEST(test_hostname_dead_past_threshold_goes_to_stage_a);
  RUN_TEST(test_stage_a_fires_once_not_every_tick);
  RUN_TEST(test_stage_a_without_ip_change_goes_to_stage_b_after_window);
  RUN_TEST(test_stage_b_also_fires_if_stage_a_never_completes);
  RUN_TEST(test_stage_a_ip_change_restarts_the_dead_clock);
  RUN_TEST(test_handshake_recovery_resets_everything);
  RUN_TEST(test_ip_literal_goes_straight_to_stage_b);
  RUN_TEST(test_stage_b_rate_limited_to_once_per_hour);
  RUN_TEST(test_rate_limit_survives_a_reboot_because_it_is_an_input);
  RUN_TEST(test_stage_b_after_stage_b_resets_state_and_requires_full_threshold_again);
  RUN_TEST(test_ota_busy_blocks_every_action);
  RUN_TEST(test_unsynced_clock_blocks_stage_b_but_not_stage_a);
  RUN_TEST(test_unsynced_clock_ip_literal_never_stage_b);
  RUN_TEST(test_provision_backoff_blocks_stage_b);
  RUN_TEST(test_wifi_down_does_not_count_as_dead);
  RUN_TEST(test_not_armed_never_acts);
  RUN_TEST(test_millis_wraparound_is_safe);
  RUN_TEST(test_endpoint_hostname_classifier);
  RUN_TEST(test_api_unreachable_blocks_stage_b_until_it_is_reachable);
  RUN_TEST(test_api_recent_window);
  RUN_TEST(test_jitter_is_deterministic_and_in_range);
  RUN_TEST(test_jitter_delays_stage_b_for_an_ip_literal);
  RUN_TEST(test_jitter_delays_stage_b_after_stage_a_but_not_stage_a);
  RUN_TEST(test_future_stamp_still_rate_limits_but_is_capped);
  RUN_TEST(test_failed_stage_a_reconnect_then_stage_b_gets_a_fresh_netif);
  RUN_TEST(test_teardown_skipped_without_netif_and_reported_when_it_fails);
  RUN_TEST(test_rotation_failure_leaves_config_untouched);
  RUN_TEST(test_rotation_success_commits_exactly_once);
  return UNITY_END();
}
