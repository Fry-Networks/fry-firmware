// RC-A recovery acceptance (lib/fry_core/wg_recover2.h, api_shapes.h, kv_guard.h).
// Written from the target state machine T1-T9 before the implementation existed.
#include <unity.h>

#include <ArduinoJson.h>

#include <cstring>
#include <string>

#include "api_shapes.h"
#include "kv_guard.h"
#include "wg_recover2.h"

using fry::WgFetchOutcome;
using fry::WgRecover2;
using fry::WgRecoverAction;
using fry::WgRecover2Input;

namespace {

constexpr uint32_t kS = 1000;
constexpr uint32_t kEpoch = 1790000000;

WgRecover2Input base(uint32_t atS, bool up, bool hostname) {
  WgRecover2Input in;
  in.armed = true;
  in.up = up;
  in.wifiUp = true;
  in.nowMs = atS * kS;
  in.hostnameEndpoint = hostname;
  in.clockSynced = true;
  in.hostResolves = true;
  in.epochNow = kEpoch + atS;
  return in;
}

// Walks a dead tunnel in 5 s ticks; returns the first non-None action and when.
struct Fired { WgRecoverAction a = WgRecoverAction::None; uint32_t atS = 0; };
Fired walkDead(WgRecover2& r, uint32_t untilS, bool hostname) {
  Fired f;
  for (uint32_t t = 0; t <= untilS; t += 5) {
    WgRecoverAction a = r.decide(base(t, false, hostname));
    if (a != WgRecoverAction::None) { f.a = a; f.atS = t; return f; }
  }
  return f;
}

}  // namespace

void setUp() {}
void tearDown() {}

// T1: dead after >= 180 s without a handshake while Wi-Fi is associated.
void test_t1_dead_threshold_is_180s() {
  TEST_ASSERT_EQUAL_UINT32(180, fry::kWg2DeadAfterS);
  WgRecover2 r;
  Fired f = walkDead(r, 170, false);
  TEST_ASSERT_TRUE(f.a == WgRecoverAction::None);  // 170 s: not dead yet
  WgRecover2 r2;
  f = walkDead(r2, 400, false);
  TEST_ASSERT_TRUE(f.a != WgRecoverAction::None);
  TEST_ASSERT_TRUE(f.atS >= 180);
}

void test_t1_hostname_stage_a_first_at_180s() {
  WgRecover2 r;
  Fired f = walkDead(r, 400, true);
  TEST_ASSERT_TRUE(f.a == WgRecoverAction::ReResolve);
  TEST_ASSERT_TRUE(f.atS >= 180 && f.atS <= 190);
}

void test_t1_wifi_loss_is_not_a_dead_tunnel() {
  WgRecover2 r;
  for (uint32_t t = 0; t <= 3000; t += 5) {
    WgRecover2Input in = base(t, false, false);
    in.wifiUp = false;
    TEST_ASSERT_TRUE(r.decide(in) == WgRecoverAction::None);
  }
  // Wi-Fi returns: a fresh 180 s clock starts, no immediate action.
  TEST_ASSERT_TRUE(r.decide(base(3005, false, false)) == WgRecoverAction::None);
  TEST_ASSERT_TRUE(r.decide(base(3100, false, false)) == WgRecoverAction::None);
}

void test_t1_stage_b_waits_for_clock_and_resolving_host() {
  WgRecover2 r;
  bool fired = false;
  for (uint32_t t = 0; t <= 1000; t += 5) {
    WgRecover2Input in = base(t, false, false);
    in.hostResolves = false;
    if (r.decide(in) != WgRecoverAction::None) fired = true;
  }
  TEST_ASSERT_FALSE(fired);
  WgRecover2 r2;
  fired = false;
  for (uint32_t t = 0; t <= 1000; t += 5) {
    WgRecover2Input in = base(t, false, false);
    in.clockSynced = false;
    if (r2.decide(in) != WgRecoverAction::None) fired = true;
  }
  TEST_ASSERT_FALSE(fired);
}

void test_t1_first_reprovision_within_one_detection_window_after_stage_a() {
  WgRecover2 r;
  Fired a = walkDead(r, 400, true);
  TEST_ASSERT_TRUE(a.a == WgRecoverAction::ReResolve);
  r.onReResolved(false, 0);  // IP unchanged: stays dead
  uint32_t bAt = 0;
  for (uint32_t t = a.atS + 5; t <= a.atS + 400; t += 5) {
    if (r.decide(base(t, false, true)) == WgRecoverAction::ReProvision) { bAt = t; break; }
  }
  TEST_ASSERT_TRUE(bAt != 0);
  TEST_ASSERT_TRUE(bAt - a.atS <= fry::kWg2StageAWindowS + fry::kWg2JitterMaxS + 10);
  TEST_ASSERT_TRUE(bAt - a.atS <= 180);  // within one detection window
}

void test_t1_persisted_floor_blocks_a_reboot_loop() {
  WgRecover2 r;
  WgRecover2Input in = base(200, false, false);
  in.lastStageBEpoch = in.epochNow - (fry::kWg2StageBFloorS - 10);
  for (uint32_t t = 0; t <= 200; t += 5) {
    WgRecover2Input x = base(t, false, false);
    x.lastStageBEpoch = x.epochNow - 5;
    TEST_ASSERT_TRUE(r.decide(x) == WgRecoverAction::None);
  }
}

// T3/T6: a stage-B refresh always uses the active keypair and never mints one.
void test_t3_same_keypair_never_minted() {
  TEST_ASSERT_TRUE(fry::wgRefreshKeySource(true) == fry::WgKeySource::UseActive);
  TEST_ASSERT_TRUE(fry::wgRefreshKeySource(false) == fry::WgKeySource::NoKeyAbort);
}

// T3: the old config stays until the trial handshakes; persist only then.
void test_t3_trial_commits_only_after_handshake() {
  fry::WgTrial t;
  TEST_ASSERT_FALSE(t.active());
  t.begin(1000);
  TEST_ASSERT_TRUE(t.active());
  TEST_ASSERT_TRUE(t.tick(false, 1000 + 60 * kS) == fry::WgTrialEvent::None);
  TEST_ASSERT_TRUE(t.tick(true, 1000 + 61 * kS) == fry::WgTrialEvent::Commit);
  TEST_ASSERT_FALSE(t.active());
  TEST_ASSERT_TRUE(t.tick(true, 1000 + 62 * kS) == fry::WgTrialEvent::None);  // commits once
}

void test_t3_trial_rolls_back_when_no_handshake() {
  fry::WgTrial t;
  t.begin(0);
  TEST_ASSERT_TRUE(t.tick(false, (fry::kWg2TrialWindowS - 1) * kS) == fry::WgTrialEvent::None);
  TEST_ASSERT_TRUE(t.tick(false, fry::kWg2TrialWindowS * kS) == fry::WgTrialEvent::Rollback);
  TEST_ASSERT_FALSE(t.active());
}

void test_t3_trial_abandon_models_power_loss() {
  fry::WgTrial t;
  t.begin(0);
  t.abandon();
  TEST_ASSERT_FALSE(t.active());
  TEST_ASSERT_TRUE(t.tick(true, 5000) == fry::WgTrialEvent::None);
}

// Review LOW: the trial window is paused while Wi-Fi is down.
void test_t3_trial_clock_pauses_while_wifi_is_down() {
  fry::WgTrial t;
  t.begin(0);
  // 100 s connected, then 2 h with Wi-Fi down, then back: no rollback until 240 s of CONNECTED time.
  TEST_ASSERT_TRUE(t.tick(false, 100 * kS, true) == fry::WgTrialEvent::None);
  for (uint32_t s = 105; s <= 100 + 7200; s += 5) {
    TEST_ASSERT_TRUE(t.tick(false, s * kS, false) == fry::WgTrialEvent::None);
  }
  uint32_t back = 100 + 7200;
  TEST_ASSERT_TRUE(t.tick(false, (back + 100) * kS, true) == fry::WgTrialEvent::None);
  TEST_ASSERT_TRUE(t.tick(false, (back + 139) * kS, true) == fry::WgTrialEvent::None);
  TEST_ASSERT_TRUE(t.tick(false, (back + 141) * kS, true) == fry::WgTrialEvent::Rollback);
  fry::WgTrial u;  // and a handshake right after Wi-Fi returns still commits
  u.begin(0);
  u.tick(false, 50 * kS, false);
  TEST_ASSERT_TRUE(u.tick(true, 9000 * kS, true) == fry::WgTrialEvent::Commit);
}

// T5 table.
void test_t5_first_retry_30_to_60s() {
  for (uint32_t rnd = 0; rnd < 5000; rnd += 7) {
    uint32_t ms = fry::wgBackoffMs(WgFetchOutcome::TransientError, 0, 0, rnd);
    TEST_ASSERT_TRUE(ms >= 30000 && ms <= 60000);
  }
}

void test_t5_cap_is_900s_and_full_jitter() {
  uint32_t lo = 0xFFFFFFFF, hi = 0;
  for (uint32_t i = 0; i < 10000; i++) {
    uint32_t rnd = i * 2654435761u;  // spread over the whole 32-bit range
    uint32_t ms = fry::wgBackoffMs(WgFetchOutcome::ServerError5xx, 40, 0, rnd);
    TEST_ASSERT_TRUE(ms >= 30000 && ms <= 900000);
    if (ms < lo) lo = ms;
    if (ms > hi) hi = ms;
  }
  TEST_ASSERT_TRUE(lo < 60000);  // full jitter spans the window
  TEST_ASSERT_TRUE(hi > 800000);
  TEST_ASSERT_TRUE(fry::wgBackoffMs(WgFetchOutcome::TransientError, 4000000000u, 0, 123) <= 900000);
}

void test_t5_window_doubles() {
  // attempt 3: window 480 s, so some draw exceeds 300 s but none exceeds 480 s
  uint32_t hi = 0;
  for (uint32_t i = 0; i < 10000; i++) {
    uint32_t rnd = i * 2654435761u;
    uint32_t ms = fry::wgBackoffMs(WgFetchOutcome::TransientError, 3, 0, rnd);
    TEST_ASSERT_TRUE(ms <= 480000);
    if (ms > hi) hi = ms;
  }
  TEST_ASSERT_TRUE(hi > 300000);
}

void test_t5_403_waits_at_most_one_hour_never_6h() {
  for (uint32_t attempt = 0; attempt < 40; attempt++) {
    for (uint32_t rnd = 0; rnd < 20000; rnd += 17) {
      uint32_t ms = fry::wgBackoffMs(WgFetchOutcome::Forbidden403, attempt, 0, rnd);
      TEST_ASSERT_TRUE(ms >= 30000 && ms <= 3600000);
      TEST_ASSERT_TRUE(ms != 21600000);
      uint32_t ms4 = fry::wgBackoffMs(WgFetchOutcome::OtherClientError4xx, attempt, 0, rnd);
      TEST_ASSERT_TRUE(ms4 <= 3600000);
    }
  }
}

void test_t5_retry_after_wins_clamped() {
  TEST_ASSERT_EQUAL_UINT32(120000, fry::wgBackoffMs(WgFetchOutcome::RateLimited429, 5, 120, 77));
  TEST_ASSERT_EQUAL_UINT32(120000, fry::wgBackoffMs(WgFetchOutcome::Forbidden403, 5, 120, 77));
  TEST_ASSERT_EQUAL_UINT32(3600000, fry::wgBackoffMs(WgFetchOutcome::Forbidden403, 0, 21600, 1));
  TEST_ASSERT_EQUAL_UINT32(3600000, fry::wgBackoffMs(WgFetchOutcome::RateLimited429, 0, 999999, 1));
  TEST_ASSERT_EQUAL_UINT32(1000, fry::wgBackoffMs(WgFetchOutcome::TransientError, 0, 1, 1));
}

void test_t5_retry_after_json_body() {
  TEST_ASSERT_EQUAL_UINT32(45, fry::parseRetryAfterJson("{\"detail\":\"x\",\"retry_after_s\":45}"));
  TEST_ASSERT_EQUAL_UINT32(0, fry::parseRetryAfterJson("{\"detail\":\"x\"}"));
  TEST_ASSERT_EQUAL_UINT32(0, fry::parseRetryAfterJson("not json"));
  TEST_ASSERT_EQUAL_UINT32(0, fry::parseRetryAfterJson(nullptr));
}

// T7: one migration per version change, never a loop.
void test_t7_raw_ip_after_ota_refreshes_once_then_records() {
  fry::WgMigrationInput in;
  in.lastVer = "";            // a 0.4.1 board never wrote one
  in.curVer = "0.4.2";
  in.hasConfig = true;
  in.rawIpEndpoint = true;
  in.tries = 0;
  TEST_ASSERT_TRUE(fry::wgMigrationDecide(in) == fry::WgMigrationAction::Refresh);
  in.tries = 5;  // failed attempts retry on the backoff
  TEST_ASSERT_TRUE(fry::wgMigrationDecide(in) == fry::WgMigrationAction::Refresh);
  in.lastVer = "0.4.2";  // recorded after the successful refresh
  TEST_ASSERT_TRUE(fry::wgMigrationDecide(in) == fry::WgMigrationAction::None);
}

void test_t7_hostname_or_no_config_just_records() {
  fry::WgMigrationInput in;
  in.lastVer = "0.4.1";
  in.curVer = "0.4.2";
  in.hasConfig = true;
  in.rawIpEndpoint = false;
  TEST_ASSERT_TRUE(fry::wgMigrationDecide(in) == fry::WgMigrationAction::RecordVersion);
  in.rawIpEndpoint = true;
  in.hasConfig = false;
  TEST_ASSERT_TRUE(fry::wgMigrationDecide(in) == fry::WgMigrationAction::RecordVersion);
}

void test_t7_gives_up_after_24_tries() {
  fry::WgMigrationInput in;
  in.lastVer = "0.4.1";
  in.curVer = "0.4.2";
  in.hasConfig = true;
  in.rawIpEndpoint = true;
  in.tries = 23;
  TEST_ASSERT_TRUE(fry::wgMigrationDecide(in) == fry::WgMigrationAction::Refresh);
  in.tries = 24;
  TEST_ASSERT_TRUE(fry::wgMigrationDecide(in) == fry::WgMigrationAction::GiveUp);
}

// T8: a key that does not exist is never read (the Preferences getString logs [E] on a miss).
struct FakeStore {
  int getCalls = 0;
  bool has = false;
  bool isKey(const char*) { return has; }
  std::string getString(const char*, const char* def) { getCalls++; return has ? "v" : def; }
};
void test_t8_missing_key_is_not_read() {
  FakeStore s;
  std::string v = fry::kvGetStringIfKey<std::string>(s, "wgPeerPub");
  TEST_ASSERT_EQUAL_STRING("", v.c_str());
  TEST_ASSERT_EQUAL_INT(0, s.getCalls);
  s.has = true;
  v = fry::kvGetStringIfKey<std::string>(s, "wgPeerPub");
  TEST_ASSERT_EQUAL_STRING("v", v.c_str());
  TEST_ASSERT_EQUAL_INT(1, s.getCalls);
}

// T8, no-namespace path (U10/S5 follow-up): a board with no fry_vpn namespace never opens the store.
struct CountingStore {
  int begins = 0, gets = 0;
  bool isKey(const char*) { return true; }
  void begin(const char*, bool) { begins++; }
  void end() {}
  std::string getString(const char*, const char*) { gets++; return "v"; }
};
void test_t8_missing_namespace_is_never_opened_and_logs_once() {
  CountingStore st;
  int nsProbes = 0;
  auto missing = [&](const char*) { nsProbes++; return false; };
  fry::OnceFlag infoLine;
  int infoLines = 0;
  for (int i = 0; i < 100; i++) {  // loadConfig() runs every 5 s while unprovisioned
    std::string v = fry::kvGetStringGuarded<std::string>(missing, st, "fry_vpn", "wgPeerPub");
    TEST_ASSERT_EQUAL_STRING("", v.c_str());
    if (v.empty() && infoLine.first()) infoLines++;
  }
  TEST_ASSERT_EQUAL_INT(0, st.begins);  // no Preferences::begin => no [E] nvs_open line
  TEST_ASSERT_EQUAL_INT(0, st.gets);
  TEST_ASSERT_EQUAL_INT(100, nsProbes);
  TEST_ASSERT_EQUAL_INT(1, infoLines);  // exactly one INFO line
  auto present = [&](const char*) { return true; };
  std::string v = fry::kvGetStringGuarded<std::string>(present, st, "fry_vpn", "wgAllowed");
  TEST_ASSERT_EQUAL_STRING("v", v.c_str());  // getWgAllowed path: key present is still read
  TEST_ASSERT_EQUAL_INT(1, st.begins);
}

// T9: the PoC software block, in the shape the hwapi version gate reads.
void test_t9_poc_software_block() {
  JsonDocument doc;
  JsonObject document = doc["document"].to<JsonObject>();
  fry::fillPocSoftware(document["software"].to<JsonObject>(), "esp32c3", "0.4.2");
  std::string out;
  serializeJson(doc, out);
  TEST_ASSERT_EQUAL_STRING(
      "{\"document\":{\"software\":{\"os\":\"esp32c3\",\"poc_version_installed\":\"1.0.0\","
      "\"software_version_installed\":\"0.4.2\"}}}",
      out.c_str());
}

// Lease: the firmware only renews, so "granted:false, holder null" (no lease held) is NEUTRAL.
void test_lease_never_acquired_null_holder_is_neutral() {
  const char* body = "{\"granted\":false,\"holder_install_id\":null,\"ttl_seconds\":0,\"error_code\":null}";
  TEST_ASSERT_TRUE(fry::parseLeaseResponse(body, "396f92aaaa").verdict == fry::LeaseVerdict::NotHeld);
  TEST_ASSERT_TRUE(fry::parseLeaseResponse(body).verdict == fry::LeaseVerdict::NotHeld);
  TEST_ASSERT_TRUE(fry::parseLeaseResponse("{\"granted\":false}", "x").verdict == fry::LeaseVerdict::NotHeld);
  TEST_ASSERT_TRUE(fry::parseLeaseResponse("{\"granted\":false,\"holder_install_id\":\"\"}", "x").verdict == fry::LeaseVerdict::NotHeld);
}

void test_lease_other_holder_is_denied() {
  const char* body = "{\"granted\":false,\"holder_install_id\":\"8258a8bbbb\",\"ttl_seconds\":300}";
  TEST_ASSERT_TRUE(fry::parseLeaseResponse(body, "396f92aaaa").verdict == fry::LeaseVerdict::Denied);
  // our own id as the holder is not a denial
  TEST_ASSERT_TRUE(fry::parseLeaseResponse("{\"granted\":false,\"holder_install_id\":\"396f92aaaa\"}", "396f92aaaa").verdict == fry::LeaseVerdict::NotHeld);
  // without our own id we cannot tell: neutral unless the reason code says so
  TEST_ASSERT_TRUE(fry::parseLeaseResponse(body, "").verdict == fry::LeaseVerdict::NotHeld);
}

void test_lease_reason_code_is_denied() {
  fry::LeaseResult r = fry::parseLeaseResponse("{\"granted\":false,\"reason_code\":\"lease_held_elsewhere\"}", "x");
  TEST_ASSERT_TRUE(r.verdict == fry::LeaseVerdict::Denied);
  TEST_ASSERT_EQUAL_STRING("lease_held_elsewhere", r.reasonCode);
  r = fry::parseLeaseResponse("{\"granted\":false,\"reason_code\":\"lease_held_elsewhere\",\"holder_install_id\":null}");
  TEST_ASSERT_TRUE(r.verdict == fry::LeaseVerdict::Denied);
  TEST_ASSERT_TRUE(fry::parseLeaseResponse("{\"granted\":false,\"reason_code\":\"something_else\"}", "x").verdict == fry::LeaseVerdict::NotHeld);
}

void test_lease_granted_and_legacy_bodies() {
  TEST_ASSERT_TRUE(fry::parseLeaseResponse("{\"granted\":true}").verdict == fry::LeaseVerdict::Granted);
  TEST_ASSERT_TRUE(fry::parseLeaseResponse("{\"ok\":true}").verdict == fry::LeaseVerdict::Granted);  // old server
  TEST_ASSERT_TRUE(fry::parseLeaseResponse("").verdict == fry::LeaseVerdict::Granted);
  TEST_ASSERT_TRUE(fry::parseLeaseResponse(nullptr).verdict == fry::LeaseVerdict::Granted);
}

int main() {
  UNITY_BEGIN();
  RUN_TEST(test_t1_dead_threshold_is_180s);
  RUN_TEST(test_t1_hostname_stage_a_first_at_180s);
  RUN_TEST(test_t1_wifi_loss_is_not_a_dead_tunnel);
  RUN_TEST(test_t1_stage_b_waits_for_clock_and_resolving_host);
  RUN_TEST(test_t1_first_reprovision_within_one_detection_window_after_stage_a);
  RUN_TEST(test_t1_persisted_floor_blocks_a_reboot_loop);
  RUN_TEST(test_t3_same_keypair_never_minted);
  RUN_TEST(test_t3_trial_commits_only_after_handshake);
  RUN_TEST(test_t3_trial_rolls_back_when_no_handshake);
  RUN_TEST(test_t3_trial_abandon_models_power_loss);
  RUN_TEST(test_t3_trial_clock_pauses_while_wifi_is_down);
  RUN_TEST(test_t5_first_retry_30_to_60s);
  RUN_TEST(test_t5_cap_is_900s_and_full_jitter);
  RUN_TEST(test_t5_window_doubles);
  RUN_TEST(test_t5_403_waits_at_most_one_hour_never_6h);
  RUN_TEST(test_t5_retry_after_wins_clamped);
  RUN_TEST(test_t5_retry_after_json_body);
  RUN_TEST(test_t7_raw_ip_after_ota_refreshes_once_then_records);
  RUN_TEST(test_t7_hostname_or_no_config_just_records);
  RUN_TEST(test_t7_gives_up_after_24_tries);
  RUN_TEST(test_t8_missing_key_is_not_read);
  RUN_TEST(test_t8_missing_namespace_is_never_opened_and_logs_once);
  RUN_TEST(test_t9_poc_software_block);
  RUN_TEST(test_lease_never_acquired_null_holder_is_neutral);
  RUN_TEST(test_lease_other_holder_is_denied);
  RUN_TEST(test_lease_reason_code_is_denied);
  RUN_TEST(test_lease_granted_and_legacy_bodies);
  return UNITY_END();
}
