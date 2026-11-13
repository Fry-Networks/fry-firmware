// Confirming a new image once core health is proven, a bounded number of install attempts, and a
// short probation after the confirm (lib/fry_core/ota_confirm.*, next to ota_health.*).
//
// Before: a new image stayed PENDING_VERIFY for POC_INTERVAL_MS + 60 s and ANY reset inside that
// window made the bootloader boot the previous image. A previous image with no memory of the
// failure installs the new one again at once, with no cap, so a board that kept resetting early
// alternated between the two images. The new image now (a) confirms itself as soon as the core
// path works, (b) counts its own install attempts in NVS (a key the previous image does not
// touch) and stops being rolled back after the last permitted attempt, and (c) after the confirm
// rolls back only when it keeps crashing without ever being healthy.
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
  h.loopPasses = 10;
  h.freeHeap = 90000;
  h.uptimeMs = uptimeMs;
  return h;
}

// ---- reset classes ----------------------------------------------------------------------------

void test_reset_reasons_are_classified() {
  const uint32_t crash[] = {kPanic, kIntWdt, kTaskWdt, kOtherWdt, kBrownout};
  for (size_t i = 0; i < sizeof(crash) / sizeof(crash[0]); i++) {
    TEST_ASSERT_EQUAL((int)ResetClass::Crash, (int)fry::classifyResetReason(crash[i]));
  }
  const uint32_t benign[] = {kPowerOn, kExt, kSw, kDeepSleep, kSdio};
  for (size_t i = 0; i < sizeof(benign) / sizeof(benign[0]); i++) {
    TEST_ASSERT_EQUAL((int)ResetClass::Benign, (int)fry::classifyResetReason(benign[i]));
  }
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
  h.startupDone = false;  // the tunnel bring-up attempt has not finished yet
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

void test_the_tunnel_is_not_a_precondition_only_its_attempt() {
  // CoreHealth has no "tunnel up" input at all: the attempt is covered by startupDone.
  fry::CoreHealth h = healthy(45000);
  TEST_ASSERT_TRUE(fry::decideEarlyConfirm(true, h, kHeapGate));
}

void test_a_server_that_answers_errors_to_everything_still_validates_at_the_old_settle_time() {
  // No 2xx: never early. The unchanged rule (any answer + settle window) still applies.
  fry::CoreHealth h = healthy(120000);
  h.apiOk2xx = false;
  TEST_ASSERT_FALSE(fry::decideEarlyConfirm(true, h, kHeapGate));
  TEST_ASSERT_FALSE(fry::decideMarkValid(true, true, kSettleMs - 1, kSettleMs));
  TEST_ASSERT_TRUE(fry::decideMarkValid(true, true, kSettleMs, kSettleMs));
}

void test_the_no_answer_deadline_keeps_its_meaning() {
  // 1200 s of Wi-Fi time without any answer rolls back; time without Wi-Fi does not count.
  const uint32_t d = fry::kOtaVerifyDeadlineProdMs;
  TEST_ASSERT_EQUAL_UINT32(1200000UL, d);
  TEST_ASSERT_EQUAL((int)fry::GuardAction::None, (int)fry::decideRollbackGuard(true, false, d - 1, d));
  TEST_ASSERT_EQUAL((int)fry::GuardAction::Rollback, (int)fry::decideRollbackGuard(true, false, d, d));
  TEST_ASSERT_EQUAL_UINT32(0, fry::accrueVerifyMs(0, 600000, false));
}

// ---- attempts record --------------------------------------------------------------------------

void test_attempts_record_round_trips_and_is_per_version() {
  char rec[24];
  TEST_ASSERT_TRUE(fry::formatAttempts(rec, sizeof(rec), "0.4.29", 2) > 0);
  TEST_ASSERT_EQUAL_STRING("0.4.29#2", rec);
  TEST_ASSERT_EQUAL_UINT8(2, fry::attemptsOf(rec, "0.4.29"));
  TEST_ASSERT_EQUAL_UINT8(0, fry::attemptsOf(rec, "0.4.30"));
  TEST_ASSERT_EQUAL_UINT8(0, fry::attemptsOf(rec, "0.4.2"));
  TEST_ASSERT_EQUAL_UINT8(0, fry::attemptsOf("", "0.4.29"));
  TEST_ASSERT_EQUAL_UINT8(0, fry::attemptsOf(nullptr, "0.4.29"));
  TEST_ASSERT_EQUAL_UINT8(0, fry::attemptsOf("0.4.29#", "0.4.29"));
  TEST_ASSERT_EQUAL_UINT8(0, fry::attemptsOf("0.4.29#x", "0.4.29"));
  TEST_ASSERT_EQUAL_UINT8(0, fry::attemptsOf("0.4.29", "0.4.29"));
  TEST_ASSERT_EQUAL_UINT8(255, fry::attemptsOf("0.4.29#999", "0.4.29"));  // saturates
  char tiny[4];
  TEST_ASSERT_EQUAL(0, (int)fry::formatAttempts(tiny, sizeof(tiny), "0.4.29", 1));
}

// ---- boot decision ----------------------------------------------------------------------------

fry::BootInputs in(bool pending, uint8_t attempts, uint8_t fails, uint32_t reason, bool slotOk = true,
                   bool crashed = false, bool strikes = false, bool quarantine = false) {
  fry::BootInputs b;
  b.crashEvidence = crashed;
  b.oldKeepsStrikes = strikes;
  b.quarantineAvailable = quarantine;
  b.pendingBoot = pending;
  b.attemptsBefore = attempts;
  b.failCount = fails;
  b.reset = fry::classifyResetReason(reason);
  b.otherSlotIntact = slotOk;
  b.failLimit = 3;
  return b;
}

void test_pending_boots_count_attempts_and_the_last_one_sticks() {
  for (uint8_t before = 0; before + 1 < fry::kStickyInstallAttempt; before++) {
    const fry::BootDecision d = fry::decideBoot(in(true, before, 0, kSw));
    TEST_ASSERT_EQUAL((int)BootAction::Continue, (int)d.action);
    TEST_ASSERT_EQUAL_UINT8(before + 1, d.attempts);
    TEST_ASSERT_TRUE(d.writeAttempts);
  }
  const fry::BootDecision last = fry::decideBoot(in(true, fry::kStickyInstallAttempt - 1, 0, kPowerOn));
  TEST_ASSERT_EQUAL((int)BootAction::ConfirmNow, (int)last.action);
  const fry::BootDecision beyond = fry::decideBoot(in(true, 200, 0, kPowerOn));
  TEST_ASSERT_EQUAL((int)BootAction::ConfirmNow, (int)beyond.action);
}

void test_no_probation_without_a_record() {
  const fry::BootDecision d = fry::decideBoot(in(false, 0, 0, kPanic));
  TEST_ASSERT_EQUAL((int)BootAction::Continue, (int)d.action);
  TEST_ASSERT_FALSE(d.writeAttempts);
  TEST_ASSERT_FALSE(d.writeFailCount);
  TEST_ASSERT_FALSE(d.inProbation);
}

void test_power_cycles_during_probation_are_neutral() {
  uint8_t fails = 0;
  for (int i = 0; i < 10; i++) {
    const uint32_t reasons[] = {kPowerOn, kExt, kSw, kDeepSleep, kUnknown};
    const fry::BootDecision d = fry::decideBoot(in(false, 1, fails, reasons[i % 5]));
    TEST_ASSERT_EQUAL((int)BootAction::Continue, (int)d.action);
    TEST_ASSERT_FALSE(d.writeFailCount);
    TEST_ASSERT_TRUE(d.inProbation);
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

void test_no_rollback_without_an_intact_slot_or_after_the_sticky_attempt() {
  TEST_ASSERT_EQUAL((int)BootAction::Continue, (int)fry::decideBoot(in(false, 1, 2, kPanic, false)).action);
  TEST_ASSERT_EQUAL((int)BootAction::Continue,
                    (int)fry::decideBoot(in(false, fry::kStickyInstallAttempt, 2, kPanic)).action);
  TEST_ASSERT_EQUAL((int)BootAction::RollbackNow,
                    (int)fry::decideBoot(in(false, fry::kStickyInstallAttempt - 1, 2, kPanic)).action);
}

void test_counters_saturate() {
  const fry::BootDecision d = fry::decideBoot(in(false, 1, 255, kPanic, false));
  TEST_ASSERT_EQUAL_UINT8(255, d.failCount);
  TEST_ASSERT_EQUAL_UINT8(255, fry::decideBoot(in(true, 255, 0, kSw)).attempts);
}

// ---- crash evidence at the last permitted attempt -----------------------------------------------

void test_without_crash_evidence_the_last_attempt_confirms_whatever_else_is_known() {
  const uint8_t last = fry::kStickyInstallAttempt - 1;
  TEST_ASSERT_EQUAL((int)BootAction::ConfirmNow, (int)fry::decideBoot(in(true, last, 0, kSw)).action);
  TEST_ASSERT_EQUAL((int)BootAction::ConfirmNow,
                    (int)fry::decideBoot(in(true, last, 0, kSw, true, false, true, true)).action);
}

void test_with_crash_evidence_the_last_attempt_is_never_force_confirmed() {
  const uint8_t last = fry::kStickyInstallAttempt - 1;
  // a previous image that keeps strikes: leave through it, no address stored
  fry::BootDecision d = fry::decideBoot(in(true, last, 0, kSw, true, true, true, true));
  TEST_ASSERT_EQUAL((int)BootAction::AbandonNow, (int)d.action);
  TEST_ASSERT_FALSE(d.quarantine);
  // one without strikes: store the quarantine address first
  d = fry::decideBoot(in(true, last, 0, kSw, true, true, false, true));
  TEST_ASSERT_EQUAL((int)BootAction::AbandonNow, (int)d.action);
  TEST_ASSERT_TRUE(d.quarantine);
  // no way to stop the previous image: neither confirm nor leave
  d = fry::decideBoot(in(true, last, 0, kSw, true, true, false, false));
  TEST_ASSERT_EQUAL((int)BootAction::Continue, (int)d.action);
  // no bootable previous slot: nothing to leave through
  d = fry::decideBoot(in(true, last, 0, kSw, false, true, false, true));
  TEST_ASSERT_EQUAL((int)BootAction::Continue, (int)d.action);
  // earlier attempts are untouched by evidence
  d = fry::decideBoot(in(true, 1, 0, kSw, true, true, false, true));
  TEST_ASSERT_EQUAL((int)BootAction::Continue, (int)d.action);
}

void test_probation_at_the_last_attempt_only_gives_up_with_evidence_and_a_way_out() {
  const uint8_t at = fry::kStickyInstallAttempt;
  TEST_ASSERT_EQUAL((int)BootAction::Continue, (int)fry::decideBoot(in(false, at, 2, kPanic, true, false, false, true)).action);
  TEST_ASSERT_EQUAL((int)BootAction::RollbackNow, (int)fry::decideBoot(in(false, at, 2, kPanic, true, true, true, false)).action);
  const fry::BootDecision q = fry::decideBoot(in(false, at, 2, kPanic, true, true, false, true));
  TEST_ASSERT_EQUAL((int)BootAction::AbandonNow, (int)q.action);
  TEST_ASSERT_TRUE(q.quarantine);
  TEST_ASSERT_EQUAL((int)BootAction::Continue, (int)fry::decideBoot(in(false, at, 2, kPanic, true, true, false, false)).action);
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
  // cleared only when a different build than the quarantined one runs and the override is ours
  TEST_ASSERT_TRUE(fry::shouldClearQuarantine("Q", "Q", "0.4.29", "0.4.30"));
  TEST_ASSERT_FALSE(fry::shouldClearQuarantine("Q", "Q", "0.4.29", "0.4.29"));
  TEST_ASSERT_FALSE(fry::shouldClearQuarantine("other", "Q", "0.4.29", "0.4.30"));
  TEST_ASSERT_FALSE(fry::shouldClearQuarantine("", "Q", "0.4.29", "0.4.30"));
  TEST_ASSERT_FALSE(fry::shouldClearQuarantine("Q", "Q", "", "0.4.30"));
}

// ---- probation progress -----------------------------------------------------------------------

void test_probation_progress() {
  using fry::ProbationStep;
  TEST_ASSERT_EQUAL((int)ProbationStep::None, (int)fry::decideProbationProgress(true, true, 119999, 2));
  TEST_ASSERT_EQUAL((int)ProbationStep::ClearFails, (int)fry::decideProbationProgress(true, true, 120000, 2));
  TEST_ASSERT_EQUAL((int)ProbationStep::None, (int)fry::decideProbationProgress(true, true, 500000, 0));
  TEST_ASSERT_EQUAL((int)ProbationStep::None, (int)fry::decideProbationProgress(true, false, 500000, 2));
  TEST_ASSERT_EQUAL((int)ProbationStep::None, (int)fry::decideProbationProgress(false, true, 5000000, 2));
  TEST_ASSERT_EQUAL((int)ProbationStep::End, (int)fry::decideProbationProgress(true, true, fry::kProbationEndMs, 0));
  TEST_ASSERT_EQUAL((int)ProbationStep::End, (int)fry::decideProbationProgress(true, true, fry::kProbationEndMs, 2));
}

// ---- whole-board simulation -------------------------------------------------------------------
//
// Bootloader rules: a reset while the running image is PENDING_VERIFY boots the other slot; a
// reset of a confirmed image boots the same image. The previous image installs the new one at once
// at every boot (the worst case: no strike memory, no back-off); with oldKeepsStrikes it instead
// stops after three failed installs, like an image that counts strikes.

struct Board {
  bool oldKeepsStrikes = false;
  bool otherSlotIntact = true;
  bool installAllowed = true;
  bool knobAvailable = true;  // the quarantine address can be stored (and the previous image honours it)
  // slot state
  bool onNew = false;
  bool pendingVerify = false;
  // NVS (new image's view)
  bool nvsPending = false;
  uint8_t fails = 0;
  bool hasRecord = false;
  uint8_t attempts = 0;
  uint8_t badn = 0;       // written by a previous image that keeps strikes
  bool dump = false;      // a core dump of the new build exists
  bool quarantined = false;
  // counters for the assertions
  int installs = 0;
  int rollbacksByProbation = 0;
  int bootsOnNew = 0;
  bool confirmedEver = false;
  uint32_t lastConfirmAtMs = 0;

  void install() {
    if (!installAllowed) return;
    onNew = true;
    pendingVerify = true;
    nvsPending = true;
    installs++;
  }
  // The previous image runs after a rollback and installs the new image again (or not).
  void previousImageRuns() {
    onNew = false;
    pendingVerify = false;
    nvsPending = false;  // the previous image clears the pending flag and the boot counter
    fails = 0;
    if (oldKeepsStrikes) {
      badn++;
      if (badn >= 3) installAllowed = false;  // permanently skipped
    }
    install();
  }
  void clearNewPending() {
    pendingVerify = false;
    nvsPending = false;
    fails = 0;
    confirmedEver = true;
  }

  // One boot of the new image. `reason` = reset reason, `aliveMs` = how long it runs before the
  // next reset, `apiOkAtMs` = when the first 2xx arrives (-1 never), `startupAtMs` = when the
  // tunnel attempt is over (-1 never), `endCrash` = the life ends in a panic (leaves a core dump).
  // Returns true if the board is still on the new image.
  bool runNew(uint32_t reason, uint32_t aliveMs, int apiOkAtMs = 8000, int startupAtMs = 12000,
              bool endCrash = false) {
    bootsOnNew++;
    const fry::ResetClass rc = fry::classifyResetReason(reason);
    if (rc == ResetClass::Crash && reason != kBrownout) dump = true;  // the previous life left a dump
    const bool pendingBoot = pendingVerify || nvsPending;
    fry::BootInputs b;
    b.pendingBoot = pendingBoot;
    b.attemptsBefore = hasRecord ? attempts : 0;
    b.failCount = fails;
    b.reset = rc;
    b.otherSlotIntact = otherSlotIntact;
    b.failLimit = 3;
    b.crashEvidence = dump && b.attemptsBefore > 0;
    b.oldKeepsStrikes = badn > 0;
    b.quarantineAvailable = knobAvailable;
    const fry::BootDecision d = fry::decideBoot(b);
    if (d.writeAttempts) {
      hasRecord = true;
      attempts = d.attempts;
    }
    if (d.writeFailCount) fails = d.failCount;
    if (d.action == BootAction::RollbackNow || d.action == BootAction::AbandonNow) {
      if (!pendingBoot) rollbacksByProbation++;
      if (d.quarantine) {
        quarantined = true;
        installAllowed = false;  // the previous image reads the quarantine address: no update
      }
      nvsPending = true;  // names the abandoned version for a previous image that counts strikes
      fails = 0;
      previousImageRuns();
      return false;
    }
    if (d.action == BootAction::ConfirmNow) {
      clearNewPending();
    }
    bool inProbation = d.inProbation || pendingBoot;
    // life of this boot, in the order the events happen
    bool confirmed = !(pendingVerify || nvsPending);
    bool probationOver = false;
    uint32_t t = 0;
    while (t < aliveMs) {
      t = (t + 1000 > aliveMs) ? aliveMs : t + 1000;
      const bool api = apiOkAtMs >= 0 && t >= (uint32_t)apiOkAtMs;
      const bool startup = startupAtMs >= 0 && t >= (uint32_t)startupAtMs;
      fry::CoreHealth h;
      h.staUp = true;
      h.apiOk2xx = api;
      h.startupDone = startup;
      h.loopPasses = startup ? 10 : 0;
      h.freeHeap = 90000;
      h.uptimeMs = t;
      if (!confirmed && (fry::decideEarlyConfirm(true, h, kHeapGate) ||
                         fry::decideMarkValid(true, api, t, kSettleMs))) {
        clearNewPending();
        confirmed = true;
        lastConfirmAtMs = t;
      }
      if (confirmed && inProbation && !probationOver) {
        const bool coreOk = api && startup;
        const fry::ProbationStep s = fry::decideProbationProgress(true, coreOk, t, fails);
        if (s == fry::ProbationStep::ClearFails) fails = 0;
        if (s == fry::ProbationStep::End) {
          fails = 0;
          hasRecord = false;
          attempts = 0;
          probationOver = true;
        }
      }
    }
    if (endCrash) dump = true;
    if (pendingVerify) {  // still pending at the reset: the bootloader boots the other slot
      previousImageRuns();
      return false;
    }
    return true;
  }
};

void test_a_healthy_install_confirms_in_well_under_a_minute() {
  Board b;
  b.install();
  TEST_ASSERT_TRUE(b.runNew(kSw, 60000));
  TEST_ASSERT_TRUE(b.confirmedEver);
  TEST_ASSERT_TRUE(b.lastConfirmAtMs >= 30000 && b.lastConfirmAtMs <= 40000);
  TEST_ASSERT_EQUAL_INT(1, b.installs);
}

void test_a_reset_25_s_after_the_confirm_does_not_roll_back() {
  Board b;
  b.install();
  TEST_ASSERT_TRUE(b.runNew(kSw, 30000 + 25000));  // confirm at 30 s, reset 25 s later
  TEST_ASSERT_TRUE(b.confirmedEver);
  TEST_ASSERT_TRUE(b.onNew);
  TEST_ASSERT_TRUE(b.runNew(kPowerOn, 90000));  // and it comes back as itself
  TEST_ASSERT_EQUAL_INT(1, b.installs);
  TEST_ASSERT_EQUAL_INT(0, b.rollbacksByProbation);
}

void test_a_reset_before_core_health_goes_back_to_the_previous_image_and_it_tries_again() {
  Board b;
  b.install();
  TEST_ASSERT_FALSE(b.runNew(kSw, 10000));  // reset at 10 s, before the confirm
  TEST_ASSERT_TRUE(b.onNew);                // previous image ran and installed it again
  TEST_ASSERT_EQUAL_INT(2, b.installs);
  TEST_ASSERT_TRUE(b.runNew(kSw, 60000));  // the second attempt gets through
  TEST_ASSERT_TRUE(b.confirmedEver);
}

void test_an_image_that_never_gets_an_answer_is_not_confirmed_and_hits_the_deadline() {
  Board b;
  b.install();
  TEST_ASSERT_FALSE(b.runNew(kSw, 30 * 60000UL, /*apiOkAtMs=*/-1));
  TEST_ASSERT_FALSE(b.confirmedEver);
  // the loop guard (unchanged) is what rolls such an image back, at 1200 s of Wi-Fi time
  TEST_ASSERT_EQUAL((int)fry::GuardAction::Rollback,
                    (int)fry::decideRollbackGuard(true, false, 1200000UL, fry::kOtaVerifyDeadlineProdMs));
}

void test_an_image_that_dies_in_the_tunnel_start_is_never_confirmed() {
  Board b;
  b.install();
  // alive 12 s, the startup finishes at 14 s: dies inside it, however healthy the API looks
  TEST_ASSERT_FALSE(b.runNew(kSw, 12000, 8000, 14000));
  TEST_ASSERT_FALSE(b.confirmedEver);
  TEST_ASSERT_EQUAL_INT(2, b.installs);
}

void test_three_external_resets_before_core_health_the_third_install_confirms_and_stays() {
  Board b;  // previous image without strike memory; resets from power, EN or the cable: no core dump
  b.install();
  int guard = 0;
  while (guard++ < 50) {
    if (b.runNew(kSw, 10000)) break;
  }
  TEST_ASSERT_TRUE(b.onNew);
  TEST_ASSERT_TRUE(b.confirmedEver);
  TEST_ASSERT_EQUAL_INT(fry::kStickyInstallAttempt, b.installs);
  TEST_ASSERT_FALSE(b.dump);
  for (int i = 0; i < 20; i++) TEST_ASSERT_TRUE(b.runNew(kPowerOn, 10000));
  TEST_ASSERT_EQUAL_INT(fry::kStickyInstallAttempt, b.installs);
}

void test_crash_evidence_stops_the_forced_confirm_and_the_board_ends_on_the_previous_image() {
  Board b;  // previous image without strikes, knob available
  b.install();
  int guard = 0;
  while (guard++ < 50 && b.onNew) b.runNew(kSw, 10000, 8000, 12000, /*endCrash=*/true);
  TEST_ASSERT_FALSE(b.onNew);
  TEST_ASSERT_FALSE(b.confirmedEver);
  TEST_ASSERT_TRUE(b.quarantined);
  TEST_ASSERT_EQUAL_INT(fry::kStickyInstallAttempt, b.installs);  // and no install after the third
}

void test_crash_evidence_with_a_previous_image_that_keeps_strikes_needs_no_address() {
  Board b;
  b.oldKeepsStrikes = true;
  b.install();
  int guard = 0;
  while (guard++ < 50 && b.onNew) b.runNew(kSw, 10000, 8000, 12000, true);
  TEST_ASSERT_FALSE(b.onNew);
  TEST_ASSERT_FALSE(b.quarantined);
  TEST_ASSERT_FALSE(b.installAllowed);
  TEST_ASSERT_EQUAL_INT(3, b.installs);
  TEST_ASSERT_FALSE(b.confirmedEver);
}

void test_strikes_win_over_the_forced_confirm_without_evidence_too() {
  Board b;  // a previous image that keeps strikes, resets that left no dump: still settles at the third install
  b.oldKeepsStrikes = true;
  b.install();
  int guard = 0;
  while (guard++ < 50) {
    if (b.runNew(kSw, 10000)) break;
  }
  TEST_ASSERT_TRUE(b.onNew);
  TEST_ASSERT_TRUE(b.confirmedEver);
}

void test_when_the_previous_image_cannot_be_stopped_the_image_is_not_force_confirmed() {
  Board b;  // no strike memory and no usable quarantine address: never worse than before
  b.knobAvailable = false;
  b.install();
  for (int i = 0; i < 40; i++) b.runNew(kSw, 10000, 8000, 12000, true);
  TEST_ASSERT_FALSE(b.confirmedEver);
  TEST_ASSERT_FALSE(b.quarantined);
  TEST_ASSERT_TRUE(b.installs > fry::kStickyInstallAttempt);  // it keeps alternating, as it always did
}

void test_an_external_reset_pattern_with_one_earlier_crash_is_given_up_not_forced() {
  Board b;
  b.install();
  b.runNew(kSw, 10000, 8000, 12000, true);   // one crash leaves a dump
  b.runNew(kSw, 10000);                       // external
  b.runNew(kSw, 10000);                       // third install: evidence exists
  TEST_ASSERT_FALSE(b.onNew);
  TEST_ASSERT_TRUE(b.quarantined);
}

void test_three_power_cycles_with_health_reached_are_not_a_rollback() {
  Board b;
  b.install();
  TEST_ASSERT_TRUE(b.runNew(kSw, 200000));
  for (int i = 0; i < 3; i++) TEST_ASSERT_TRUE(b.runNew(kPowerOn, 50000));
  TEST_ASSERT_EQUAL_INT(0, b.rollbacksByProbation);
  TEST_ASSERT_EQUAL_INT(1, b.installs);
  TEST_ASSERT_EQUAL_UINT8(0, b.fails);
}

void test_power_cycles_before_health_in_probation_are_not_a_rollback_either() {
  Board b;
  b.install();
  TEST_ASSERT_TRUE(b.runNew(kSw, 40000));  // confirmed at 30 s
  for (int i = 0; i < 6; i++) TEST_ASSERT_TRUE(b.runNew(kPowerOn, 5000));  // owner replugging, no health
  TEST_ASSERT_EQUAL_INT(0, b.rollbacksByProbation);
  TEST_ASSERT_EQUAL_INT(1, b.installs);
}

void test_a_confirmed_image_that_keeps_crashing_is_abandoned_for_the_previous_slot() {
  Board b;
  b.install();
  TEST_ASSERT_TRUE(b.runNew(kSw, 45000));             // confirmed
  TEST_ASSERT_TRUE(b.runNew(kPanic, 45000));          // crash boot 1, healthy 45 s only
  TEST_ASSERT_TRUE(b.runNew(kPanic, 45000));          // crash boot 2
  TEST_ASSERT_EQUAL_UINT8(2, b.fails);
  TEST_ASSERT_FALSE(b.runNew(kPanic, 45000));         // crash boot 3 -> rolled back at init
  TEST_ASSERT_EQUAL_INT(1, b.rollbacksByProbation);
  TEST_ASSERT_EQUAL_INT(2, b.installs);               // previous image installed it again
}

void test_a_crash_followed_by_a_healthy_stretch_resets_the_count() {
  Board b;
  b.install();
  TEST_ASSERT_TRUE(b.runNew(kSw, 45000));
  TEST_ASSERT_TRUE(b.runNew(kPanic, 45000));
  TEST_ASSERT_TRUE(b.runNew(kPanic, 45000));
  TEST_ASSERT_TRUE(b.runNew(kPowerOn, 130000));  // healthy for 120 s: counter forgiven
  TEST_ASSERT_EQUAL_UINT8(0, b.fails);
  TEST_ASSERT_TRUE(b.runNew(kPanic, 45000));
  TEST_ASSERT_EQUAL_INT(0, b.rollbacksByProbation);
}

void test_probation_does_not_roll_back_when_the_previous_slot_is_not_intact() {
  Board b;
  b.otherSlotIntact = false;
  b.install();
  TEST_ASSERT_TRUE(b.runNew(kSw, 45000));
  for (int i = 0; i < 10; i++) TEST_ASSERT_TRUE(b.runNew(kPanic, 45000));
  TEST_ASSERT_EQUAL_INT(0, b.rollbacksByProbation);
  TEST_ASSERT_EQUAL_INT(1, b.installs);
}

void test_probation_ends_after_a_long_healthy_run() {
  Board b;
  b.install();
  TEST_ASSERT_TRUE(b.runNew(kSw, fry::kProbationEndMs + 5000));
  TEST_ASSERT_FALSE(b.hasRecord);
  for (int i = 0; i < 10; i++) TEST_ASSERT_TRUE(b.runNew(kPanic, 45000));  // later crashes: not this mechanism
  TEST_ASSERT_EQUAL_INT(0, b.rollbacksByProbation);
}

// Property: whatever the reset pattern, the new image is installed a bounded number of times when
// the previous image can be stopped (strikes or the quarantine address).
void test_no_reset_pattern_alternates_forever() {
  uint32_t seed = 12345;
  const uint32_t reasons[] = {kPowerOn, kSw, kPanic, kBrownout, kTaskWdt, kExt, kUnknown, kDeepSleep};
  for (int run = 0; run < 400; run++) {
    Board b;
    b.oldKeepsStrikes = (run % 2) == 1;
    b.otherSlotIntact = (run % 7) != 0;
    b.knobAvailable = (run % 3) != 0;
    b.install();
    for (int boots = 0; boots < 400; boots++) {
      seed = seed * 1664525u + 1013904223u;
      const uint32_t reason = reasons[(seed >> 8) % 8];
      seed = seed * 1664525u + 1013904223u;
      const uint32_t alive = 1000 + ((seed >> 8) % 300) * 1000;  // 1 s .. 300 s
      seed = seed * 1664525u + 1013904223u;
      const int apiAt = ((seed >> 8) % 5 == 0) ? -1 : (int)(2000 + ((seed >> 12) % 10) * 1000);
      const bool endCrash = ((seed >> 20) % 4) == 0;
      b.runNew(reason, alive, apiAt, 12000, endCrash);
      if (!b.onNew && !b.installAllowed) break;  // given up, stable on the previous image
    }
    if (b.oldKeepsStrikes || b.knobAvailable || !b.otherSlotIntact) {
      if (b.otherSlotIntact) {
        TEST_ASSERT_TRUE_MESSAGE(b.installs <= 6, "installs bounded");
      }
    }
  }
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_reset_reasons_are_classified);
  RUN_TEST(test_confirms_as_soon_as_core_health_and_the_minimum_uptime_hold);
  RUN_TEST(test_every_condition_is_needed);
  RUN_TEST(test_the_tunnel_is_not_a_precondition_only_its_attempt);
  RUN_TEST(test_a_server_that_answers_errors_to_everything_still_validates_at_the_old_settle_time);
  RUN_TEST(test_the_no_answer_deadline_keeps_its_meaning);
  RUN_TEST(test_attempts_record_round_trips_and_is_per_version);
  RUN_TEST(test_pending_boots_count_attempts_and_the_last_one_sticks);
  RUN_TEST(test_no_probation_without_a_record);
  RUN_TEST(test_power_cycles_during_probation_are_neutral);
  RUN_TEST(test_crash_boots_without_health_roll_back_at_the_limit);
  RUN_TEST(test_no_rollback_without_an_intact_slot_or_after_the_sticky_attempt);
  RUN_TEST(test_counters_saturate);
  RUN_TEST(test_without_crash_evidence_the_last_attempt_confirms_whatever_else_is_known);
  RUN_TEST(test_with_crash_evidence_the_last_attempt_is_never_force_confirmed);
  RUN_TEST(test_probation_at_the_last_attempt_only_gives_up_with_evidence_and_a_way_out);
  RUN_TEST(test_strike_detection_and_the_quarantine_address);
  RUN_TEST(test_probation_progress);
  RUN_TEST(test_a_healthy_install_confirms_in_well_under_a_minute);
  RUN_TEST(test_a_reset_25_s_after_the_confirm_does_not_roll_back);
  RUN_TEST(test_a_reset_before_core_health_goes_back_to_the_previous_image_and_it_tries_again);
  RUN_TEST(test_an_image_that_never_gets_an_answer_is_not_confirmed_and_hits_the_deadline);
  RUN_TEST(test_an_image_that_dies_in_the_tunnel_start_is_never_confirmed);
  RUN_TEST(test_three_external_resets_before_core_health_the_third_install_confirms_and_stays);
  RUN_TEST(test_crash_evidence_stops_the_forced_confirm_and_the_board_ends_on_the_previous_image);
  RUN_TEST(test_crash_evidence_with_a_previous_image_that_keeps_strikes_needs_no_address);
  RUN_TEST(test_strikes_win_over_the_forced_confirm_without_evidence_too);
  RUN_TEST(test_when_the_previous_image_cannot_be_stopped_the_image_is_not_force_confirmed);
  RUN_TEST(test_an_external_reset_pattern_with_one_earlier_crash_is_given_up_not_forced);
  RUN_TEST(test_three_power_cycles_with_health_reached_are_not_a_rollback);
  RUN_TEST(test_power_cycles_before_health_in_probation_are_not_a_rollback_either);
  RUN_TEST(test_a_confirmed_image_that_keeps_crashing_is_abandoned_for_the_previous_slot);
  RUN_TEST(test_a_crash_followed_by_a_healthy_stretch_resets_the_count);
  RUN_TEST(test_probation_does_not_roll_back_when_the_previous_slot_is_not_intact);
  RUN_TEST(test_probation_ends_after_a_long_healthy_run);
  RUN_TEST(test_no_reset_pattern_alternates_forever);
  return UNITY_END();
}
