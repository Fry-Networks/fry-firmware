// The pure decisions of lib/fry_core/ota_confirm.*: confirming a new image once core health is
// proven, the install-attempt record, what the last permitted attempt may do, and the probation
// after the confirm. The whole-board behaviour and the I/O order are in test_ota_boot_flow.
//
// Before: a new image stayed PENDING_VERIFY for POC_INTERVAL_MS + 60 s and ANY reset inside that
// window made the bootloader boot the previous image. A previous image with no memory of the
// failure installs the new one again at once, with no cap, so a board that kept resetting early
// alternated between the two images.
#include <unity.h>

#include <cstdint>
#include <cstring>

#include "ota_confirm.h"
#include "ota_health.h"

using fry::BootAction;
using fry::ResetClass;

namespace {

// esp_reset_reason_t values of the ESP-IDF shipped with the Arduino core.
const uint32_t kUnknown = 0, kPowerOn = 1, kExt = 2, kSw = 3, kPanic = 4, kIntWdt = 5, kTaskWdt = 6,
               kOtherWdt = 7, kDeepSleep = 8, kBrownout = 9, kSdio = 10;

const uint32_t kHeapGate = 20000;  // HEAP_GATE_OTA
const uint32_t kSettleMs = 11UL * 60UL * 1000UL;

fry::CoreHealth healthy(uint32_t uptimeMs) {
  fry::CoreHealth h;
  h.staUp = true;
  h.apiOk2xx = true;
  h.startupDone = true;
  h.tunnelSettled = true;
  h.loopPasses = 10;
  h.freeHeap = 90000;
  h.uptimeMs = uptimeMs;
  return h;
}

// ---- reset classes ----------------------------------------------------------------------------

void test_reset_reasons_are_classified() {
  const uint32_t crash[] = {kPanic, kIntWdt, kTaskWdt, kOtherWdt};
  for (size_t i = 0; i < sizeof(crash) / sizeof(crash[0]); i++) {
    TEST_ASSERT_EQUAL((int)ResetClass::Crash, (int)fry::classifyResetReason(crash[i]));
  }
  const uint32_t benign[] = {kPowerOn, kExt, kSw, kDeepSleep, kSdio};
  for (size_t i = 0; i < sizeof(benign) / sizeof(benign[0]); i++) {
    TEST_ASSERT_EQUAL((int)ResetClass::Benign, (int)fry::classifyResetReason(benign[i]));
  }
  TEST_ASSERT_EQUAL((int)ResetClass::Brownout, (int)fry::classifyResetReason(kBrownout));
  TEST_ASSERT_EQUAL((int)ResetClass::Unknown, (int)fry::classifyResetReason(kUnknown));
  TEST_ASSERT_EQUAL((int)ResetClass::Unknown, (int)fry::classifyResetReason(255));
}

// ---- early confirm ----------------------------------------------------------------------------

void test_confirms_as_soon_as_core_health_and_the_minimum_uptime_hold() {
  TEST_ASSERT_TRUE(fry::decideEarlyConfirm(true, healthy(fry::kEarlyConfirmMinUptimeMs), kHeapGate));
  TEST_ASSERT_TRUE(fry::decideEarlyConfirm(true, healthy(45000), kHeapGate));
  TEST_ASSERT_TRUE_MESSAGE(fry::kEarlyConfirmMinUptimeMs < 60000UL, "target is well under a minute");
}

void test_every_condition_is_needed() {
  TEST_ASSERT_FALSE(fry::decideEarlyConfirm(true, healthy(fry::kEarlyConfirmMinUptimeMs - 1), kHeapGate));
  TEST_ASSERT_FALSE(fry::decideEarlyConfirm(false, healthy(45000), kHeapGate));  // nothing pending
  fry::CoreHealth h = healthy(45000);
  h.staUp = false;
  TEST_ASSERT_FALSE(fry::decideEarlyConfirm(true, h, kHeapGate));
  h = healthy(45000);
  h.apiOk2xx = false;
  TEST_ASSERT_FALSE(fry::decideEarlyConfirm(true, h, kHeapGate));
  h = healthy(45000);
  h.startupDone = false;
  TEST_ASSERT_FALSE(fry::decideEarlyConfirm(true, h, kHeapGate));
  h = healthy(45000);
  h.tunnelSettled = false;
  TEST_ASSERT_FALSE(fry::decideEarlyConfirm(true, h, kHeapGate));
  h = healthy(45000);
  h.loopPasses = fry::kEarlyConfirmMinLoopPasses - 1;
  TEST_ASSERT_FALSE(fry::decideEarlyConfirm(true, h, kHeapGate));
  h = healthy(45000);
  h.freeHeap = kHeapGate - 1;
  TEST_ASSERT_FALSE(fry::decideEarlyConfirm(true, h, kHeapGate));
  h.freeHeap = kHeapGate;
  TEST_ASSERT_TRUE(fry::decideEarlyConfirm(true, h, kHeapGate));
}

void test_the_tunnel_bring_up_is_waited_for_when_it_will_happen() {
  // a config is stored and the bring-up has not been attempted: wait
  TEST_ASSERT_FALSE(fry::tunnelSettled(true, false, false, 40000));
  TEST_ASSERT_FALSE(fry::tunnelSettled(true, false, true, 40000));  // a fetch does not help when the config exists
  TEST_ASSERT_TRUE(fry::tunnelSettled(true, true, false, 40000));
  // no config yet: wait for the provisioning fetch to complete one attempt, whatever its outcome
  TEST_ASSERT_FALSE(fry::tunnelSettled(false, false, false, 40000));
  TEST_ASSERT_TRUE(fry::tunnelSettled(false, false, true, 40000));
  // the fetch succeeded and stored a config: now the bring-up is what is awaited
  TEST_ASSERT_FALSE(fry::tunnelSettled(true, false, true, 40000));
  // a tunnel service outage cannot block validation for ever
  TEST_ASSERT_FALSE(fry::tunnelSettled(false, false, false, fry::kTunnelWaitCapMs - 1));
  TEST_ASSERT_TRUE(fry::tunnelSettled(false, false, false, fry::kTunnelWaitCapMs));
  TEST_ASSERT_TRUE(fry::tunnelSettled(true, false, false, fry::kTunnelWaitCapMs));
}

void test_a_server_that_answers_errors_to_everything_still_validates_at_the_old_settle_time() {
  fry::CoreHealth h = healthy(120000);
  h.apiOk2xx = false;
  TEST_ASSERT_FALSE(fry::decideEarlyConfirm(true, h, kHeapGate));
  TEST_ASSERT_FALSE(fry::decideMarkValid(true, true, kSettleMs - 1, kSettleMs));
  TEST_ASSERT_TRUE(fry::decideMarkValid(true, true, kSettleMs, kSettleMs));
}

void test_the_no_answer_deadline_keeps_its_meaning() {
  const uint32_t d = fry::kOtaVerifyDeadlineProdMs;
  TEST_ASSERT_EQUAL_UINT32(1200000UL, d);
  TEST_ASSERT_EQUAL((int)fry::GuardAction::None, (int)fry::decideRollbackGuard(true, false, d - 1, d));
  TEST_ASSERT_EQUAL((int)fry::GuardAction::Rollback, (int)fry::decideRollbackGuard(true, false, d, d));
  TEST_ASSERT_EQUAL_UINT32(0, fry::accrueVerifyMs(0, 600000, false));
}

// ---- attempt record ---------------------------------------------------------------------------

void test_the_record_round_trips_and_is_per_version() {
  char rec[32];
  fry::AttemptRecord r;
  r.n = 2;
  TEST_ASSERT_TRUE(fry::formatAttemptRecord(rec, sizeof(rec), "0.4.29", r) > 0);
  TEST_ASSERT_EQUAL_STRING("0.4.29#2", rec);  // the short form while nothing else is known
  r.healthy = true;
  r.boots = 5;
  TEST_ASSERT_TRUE(fry::formatAttemptRecord(rec, sizeof(rec), "0.4.29", r) > 0);
  TEST_ASSERT_EQUAL_STRING("0.4.29#2#1#5", rec);
  const fry::AttemptRecord back = fry::parseAttemptRecord(rec, "0.4.29");
  TEST_ASSERT_EQUAL_UINT8(2, back.n);
  TEST_ASSERT_TRUE(back.healthy);
  TEST_ASSERT_EQUAL_UINT8(5, back.boots);
  TEST_ASSERT_EQUAL_UINT8(2, fry::attemptsOf("0.4.29#2", "0.4.29"));
  TEST_ASSERT_FALSE(fry::parseAttemptRecord("0.4.29#2", "0.4.29").healthy);
  TEST_ASSERT_TRUE(fry::parseAttemptRecord("0.4.29#3#1", "0.4.29").healthy);
  TEST_ASSERT_EQUAL_UINT8(0, fry::attemptsOf(rec, "0.4.30"));
  TEST_ASSERT_EQUAL_UINT8(0, fry::attemptsOf(rec, "0.4.2"));
  const char* bad[] = {"", "0.4.29#", "0.4.29#x", "0.4.29", "0.4.29#2#", "0.4.29#2#2", "0.4.29#2#1#", "0.4.29#2#1#x", "0.4.29#2x"};
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) TEST_ASSERT_EQUAL_UINT8(0, fry::attemptsOf(bad[i], "0.4.29"));
  TEST_ASSERT_EQUAL_UINT8(0, fry::attemptsOf(nullptr, "0.4.29"));
  TEST_ASSERT_EQUAL_UINT8(255, fry::attemptsOf("0.4.29#999", "0.4.29"));  // saturates
  char tiny[4];
  TEST_ASSERT_EQUAL(0, (int)fry::formatAttempts(tiny, sizeof(tiny), "0.4.29", 1));
  char edge[12];  // "0.4.29#1#1#0" needs 13
  r = fry::AttemptRecord();
  r.n = 1;
  r.healthy = true;
  TEST_ASSERT_EQUAL(0, (int)fry::formatAttemptRecord(edge, sizeof(edge), "0.4.29", r));
}

// ---- boot decision ----------------------------------------------------------------------------

fry::BootInputs in(bool pending, uint8_t attempts, uint8_t fails, uint32_t reason, bool slotOk = true,
                   bool crashed = false, bool strikes = false, bool quarantine = false, bool earlierHealth = true,
                   uint8_t boots = 0) {
  fry::BootInputs b;
  b.pendingBoot = pending;
  b.record.n = attempts;
  b.record.healthy = earlierHealth;
  b.record.boots = boots;
  b.failCount = fails;
  b.reset = fry::classifyResetReason(reason);
  b.otherSlotIntact = slotOk;
  b.failLimit = 3;
  b.crashEvidence = crashed;
  b.oldKeepsStrikes = strikes;
  b.quarantineAvailable = quarantine;
  return b;
}

void test_pending_boots_count_attempts_before_the_last_one() {
  for (uint8_t before = 0; before + 1 < fry::kStickyInstallAttempt; before++) {
    const fry::BootDecision d = fry::decideBoot(in(true, before, 0, kSw));
    TEST_ASSERT_EQUAL((int)BootAction::Continue, (int)d.action);
    TEST_ASSERT_EQUAL_UINT8(before + 1, d.record.n);
    TEST_ASSERT_TRUE(d.writeRecord);
  }
  TEST_ASSERT_EQUAL_UINT8(255, fry::decideBoot(in(true, 255, 0, kSw)).record.n);
}

void test_no_probation_without_a_record() {
  const fry::BootDecision d = fry::decideBoot(in(false, 0, 0, kPanic));
  TEST_ASSERT_EQUAL((int)BootAction::Continue, (int)d.action);
  TEST_ASSERT_FALSE(d.writeRecord);
  TEST_ASSERT_FALSE(d.writeFailCount);
  TEST_ASSERT_FALSE(d.inProbation);
}

void test_power_cycles_during_probation_are_neutral() {
  uint8_t fails = 0;
  for (int i = 0; i < 7; i++) {
    const uint32_t reasons[] = {kPowerOn, kExt, kSw, kDeepSleep, kUnknown};
    const fry::BootDecision d = fry::decideBoot(in(false, 1, fails, reasons[i % 5], true, false, false, false, true, (uint8_t)i));
    TEST_ASSERT_EQUAL((int)BootAction::Continue, (int)d.action);
    TEST_ASSERT_FALSE(d.writeFailCount);
    TEST_ASSERT_TRUE(d.inProbation);
    TEST_ASSERT_EQUAL_UINT8(i + 1, d.record.boots);
    fails = d.failCount;
  }
  TEST_ASSERT_EQUAL_UINT8(0, fails);
}

void test_crash_boots_without_health_roll_back_at_the_limit() {
  uint8_t fails = 0;
  for (int i = 1; i <= 2; i++) {
    const fry::BootDecision d = fry::decideBoot(in(false, 1, fails, kPanic));
    TEST_ASSERT_EQUAL((int)BootAction::Continue, (int)d.action);
    TEST_ASSERT_TRUE(d.writeFailCount);
    TEST_ASSERT_EQUAL_UINT8(i, d.failCount);
    fails = d.failCount;
  }
  TEST_ASSERT_EQUAL((int)BootAction::RollbackNow, (int)fry::decideBoot(in(false, 1, fails, kTaskWdt)).action);
  // a neutral reset in between neither counts nor forgives
  TEST_ASSERT_EQUAL((int)BootAction::Continue, (int)fry::decideBoot(in(false, 1, fails, kPowerOn)).action);
  TEST_ASSERT_EQUAL_UINT8(2, fry::decideBoot(in(false, 1, fails, kPowerOn)).failCount);
}

void test_a_brownout_counts_only_with_a_core_dump() {
  TEST_ASSERT_EQUAL((int)BootAction::Continue, (int)fry::decideBoot(in(false, 1, 2, kBrownout)).action);
  TEST_ASSERT_EQUAL_UINT8(2, fry::decideBoot(in(false, 1, 2, kBrownout)).failCount);
  TEST_ASSERT_FALSE(fry::decideBoot(in(false, 1, 2, kBrownout)).writeFailCount);
  TEST_ASSERT_EQUAL((int)BootAction::RollbackNow, (int)fry::decideBoot(in(false, 1, 2, kBrownout, true, true)).action);
}

void test_no_rollback_without_an_intact_slot() {
  TEST_ASSERT_EQUAL((int)BootAction::Continue, (int)fry::decideBoot(in(false, 1, 2, kPanic, false)).action);
}

void test_counters_saturate() {
  TEST_ASSERT_EQUAL_UINT8(255, fry::decideBoot(in(false, 1, 255, kPanic, false)).failCount);
}

void test_an_open_record_expires_after_a_number_of_boots() {
  const fry::BootDecision ok = fry::decideBoot(in(false, 1, 0, kPowerOn, true, false, false, false, true, fry::kProbationMaxBoots - 1));
  TEST_ASSERT_FALSE(ok.probationExpired);
  TEST_ASSERT_EQUAL_UINT8(fry::kProbationMaxBoots, ok.record.boots);
  const fry::BootDecision gone = fry::decideBoot(in(false, 1, 2, kPanic, true, false, false, false, true, fry::kProbationMaxBoots));
  TEST_ASSERT_TRUE(gone.probationExpired);
  TEST_ASSERT_FALSE(gone.inProbation);
  TEST_ASSERT_EQUAL((int)BootAction::Continue, (int)gone.action);  // even a crash boot: the window is over
  // a fresh install opens a fresh window
  TEST_ASSERT_EQUAL_UINT8(0, fry::decideBoot(in(true, 1, 0, kSw, true, false, false, false, true, 7)).record.boots);
}

// ---- the last permitted attempt (strike-less previous image) -------------------------------------

const uint8_t kLast = fry::kStickyInstallAttempt - 1;  // record.n before the last attempt

void test_external_resets_after_an_earlier_attempt_reached_the_api_confirm_at_once() {
  const fry::BootDecision d = fry::decideBoot(in(true, kLast, 0, kSw, true, false, false, true, /*earlierHealth=*/true));
  TEST_ASSERT_EQUAL((int)BootAction::ConfirmNow, (int)d.action);
  TEST_ASSERT_EQUAL((int)BootAction::ConfirmNow, (int)fry::decideBoot(in(true, kLast, 0, kSw, false, false, false, false, true)).action);
}

void test_a_dump_of_this_build_means_never_force_confirm() {
  fry::BootDecision d = fry::decideBoot(in(true, kLast, 0, kSw, true, true, false, true, true));
  TEST_ASSERT_EQUAL((int)BootAction::AbandonNow, (int)d.action);
  TEST_ASSERT_TRUE(d.quarantine);
  d = fry::decideBoot(in(true, kLast, 0, kSw, true, true, false, false, true));  // no way to stop the previous image
  TEST_ASSERT_EQUAL((int)BootAction::Continue, (int)d.action);
  d = fry::decideBoot(in(true, kLast, 0, kSw, false, true, false, true, true));  // no bootable previous slot
  TEST_ASSERT_EQUAL((int)BootAction::Continue, (int)d.action);
  d = fry::decideBoot(in(true, 1, 0, kSw, true, true, false, true, true));  // earlier attempts are untouched
  TEST_ASSERT_EQUAL((int)BootAction::Continue, (int)d.action);
}

void test_a_silent_failure_is_not_force_confirmed_either() {
  // no dump, but no earlier attempt ever got Wi-Fi with a 2xx
  fry::BootDecision d = fry::decideBoot(in(true, kLast, 0, kSw, true, false, false, true, /*earlierHealth=*/false));
  TEST_ASSERT_EQUAL((int)BootAction::AbandonNow, (int)d.action);
  TEST_ASSERT_TRUE(d.quarantine);
  d = fry::decideBoot(in(true, kLast, 0, kSw, true, false, false, false, false));  // knob unavailable: as before
  TEST_ASSERT_EQUAL((int)BootAction::Continue, (int)d.action);
}

// ---- the last permitted attempt (previous image keeps strikes) -------------------------------------

void test_with_strikes_the_last_attempt_is_never_force_confirmed() {
  TEST_ASSERT_EQUAL((int)BootAction::Continue, (int)fry::decideBoot(in(true, kLast, 0, kSw, true, false, true, true, true)).action);
  TEST_ASSERT_EQUAL((int)BootAction::Continue, (int)fry::decideBoot(in(true, kLast, 0, kSw, true, false, true, true, false)).action);
  const fry::BootDecision d = fry::decideBoot(in(true, kLast, 0, kSw, true, true, true, true, true));
  TEST_ASSERT_EQUAL((int)BootAction::AbandonNow, (int)d.action);
  TEST_ASSERT_FALSE(d.quarantine);  // the previous image counts the strike, no address is needed
}

// ---- probation at and after the last attempt -----------------------------------------------------

void test_probation_at_the_last_attempt_only_gives_up_with_a_dump_and_a_way_out() {
  const uint8_t at = fry::kStickyInstallAttempt;
  TEST_ASSERT_EQUAL((int)BootAction::Continue, (int)fry::decideBoot(in(false, at, 2, kPanic, true, false, false, true)).action);
  TEST_ASSERT_EQUAL((int)BootAction::RollbackNow, (int)fry::decideBoot(in(false, at, 2, kPanic, true, true, true, false)).action);
  const fry::BootDecision q = fry::decideBoot(in(false, at, 2, kPanic, true, true, false, true));
  TEST_ASSERT_EQUAL((int)BootAction::AbandonNow, (int)q.action);
  TEST_ASSERT_TRUE(q.quarantine);
  TEST_ASSERT_EQUAL((int)BootAction::Continue, (int)fry::decideBoot(in(false, at, 2, kPanic, true, true, false, false)).action);
  TEST_ASSERT_EQUAL((int)BootAction::RollbackNow, (int)fry::decideBoot(in(false, kLast, 2, kPanic)).action);
}

void test_strike_detection_and_the_quarantine_address() {
  TEST_ASSERT_TRUE(fry::oldKeepsStrikes("0.4.29", 1, "0.4.29"));
  TEST_ASSERT_FALSE(fry::oldKeepsStrikes("0.4.29", 0, "0.4.29"));
  TEST_ASSERT_FALSE(fry::oldKeepsStrikes("0.4.28", 2, "0.4.29"));
  TEST_ASSERT_FALSE(fry::oldKeepsStrikes("", 2, "0.4.29"));
  TEST_ASSERT_FALSE(fry::oldKeepsStrikes(nullptr, 2, "0.4.29"));
  char q[160];
  TEST_ASSERT_TRUE(fry::quarantineUrlFrom("https://example.test/org/repo/releases/latest/download/manifest.json", q, sizeof(q)));
  TEST_ASSERT_EQUAL_STRING("https://example.test/org/repo/releases/download/quarantine/manifest.json", q);
  TEST_ASSERT_FALSE(fry::quarantineUrlFrom("https://example.test/manifest.json", q, sizeof(q)));
  TEST_ASSERT_FALSE(fry::quarantineUrlFrom("", q, sizeof(q)));
  TEST_ASSERT_FALSE(fry::quarantineUrlFrom(nullptr, q, sizeof(q)));
  char tiny[20];
  TEST_ASSERT_FALSE(fry::quarantineUrlFrom("https://example.test/org/repo/releases/latest/download/manifest.json", tiny, sizeof(tiny)));
  TEST_ASSERT_TRUE(fry::shouldClearQuarantine("Q", "Q", "0.4.29", "0.4.30"));
  TEST_ASSERT_FALSE(fry::shouldClearQuarantine("Q", "Q", "0.4.29", "0.4.29"));
  TEST_ASSERT_FALSE(fry::shouldClearQuarantine("other", "Q", "0.4.29", "0.4.30"));
  TEST_ASSERT_FALSE(fry::shouldClearQuarantine("", "Q", "0.4.29", "0.4.30"));
  TEST_ASSERT_FALSE(fry::shouldClearQuarantine("Q", "Q", "", "0.4.30"));
}

// ---- probation progress -----------------------------------------------------------------------

void test_the_crash_count_is_forgiven_only_after_the_old_settle_horizon_and_a_poc() {
  using fry::ProbationStep;
  const uint32_t horizon = 660UL * 1000UL;
  TEST_ASSERT_EQUAL_UINT32(horizon, fry::kProbationHealthyMs);
  TEST_ASSERT_EQUAL_UINT32(kSettleMs, fry::kProbationHealthyMs);
  // a boot that is healthy for 300 s or 500 s but has not reached the horizon forgives nothing
  TEST_ASSERT_EQUAL((int)ProbationStep::None, (int)fry::decideProbationProgress(true, true, 300000, 2, true));
  TEST_ASSERT_EQUAL((int)ProbationStep::None, (int)fry::decideProbationProgress(true, true, 500000, 2, true));
  TEST_ASSERT_EQUAL((int)ProbationStep::None, (int)fry::decideProbationProgress(true, true, horizon - 1, 2, true));
  // past the horizon it still needs a completed PoC/lease 2xx in this boot
  TEST_ASSERT_EQUAL((int)ProbationStep::None, (int)fry::decideProbationProgress(true, true, horizon, 2, false));
  TEST_ASSERT_EQUAL((int)ProbationStep::ClearFails, (int)fry::decideProbationProgress(true, true, horizon, 2, true));
  TEST_ASSERT_EQUAL((int)ProbationStep::None, (int)fry::decideProbationProgress(true, true, horizon, 0, true));
  TEST_ASSERT_EQUAL((int)ProbationStep::None, (int)fry::decideProbationProgress(true, false, horizon, 2, true));
  TEST_ASSERT_EQUAL((int)ProbationStep::None, (int)fry::decideProbationProgress(false, true, 5000000, 2, true));
  TEST_ASSERT_EQUAL((int)ProbationStep::End, (int)fry::decideProbationProgress(true, true, fry::kProbationEndMs, 0, false));
  TEST_ASSERT_EQUAL((int)ProbationStep::End, (int)fry::decideProbationProgress(true, true, fry::kProbationEndMs, 2, true));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_reset_reasons_are_classified);
  RUN_TEST(test_confirms_as_soon_as_core_health_and_the_minimum_uptime_hold);
  RUN_TEST(test_every_condition_is_needed);
  RUN_TEST(test_the_tunnel_bring_up_is_waited_for_when_it_will_happen);
  RUN_TEST(test_a_server_that_answers_errors_to_everything_still_validates_at_the_old_settle_time);
  RUN_TEST(test_the_no_answer_deadline_keeps_its_meaning);
  RUN_TEST(test_the_record_round_trips_and_is_per_version);
  RUN_TEST(test_pending_boots_count_attempts_before_the_last_one);
  RUN_TEST(test_no_probation_without_a_record);
  RUN_TEST(test_power_cycles_during_probation_are_neutral);
  RUN_TEST(test_crash_boots_without_health_roll_back_at_the_limit);
  RUN_TEST(test_a_brownout_counts_only_with_a_core_dump);
  RUN_TEST(test_no_rollback_without_an_intact_slot);
  RUN_TEST(test_counters_saturate);
  RUN_TEST(test_an_open_record_expires_after_a_number_of_boots);
  RUN_TEST(test_external_resets_after_an_earlier_attempt_reached_the_api_confirm_at_once);
  RUN_TEST(test_a_dump_of_this_build_means_never_force_confirm);
  RUN_TEST(test_a_silent_failure_is_not_force_confirmed_either);
  RUN_TEST(test_with_strikes_the_last_attempt_is_never_force_confirmed);
  RUN_TEST(test_probation_at_the_last_attempt_only_gives_up_with_a_dump_and_a_way_out);
  RUN_TEST(test_strike_detection_and_the_quarantine_address);
  RUN_TEST(test_the_crash_count_is_forgiven_only_after_the_old_settle_horizon_and_a_poc);
  return UNITY_END();
}
