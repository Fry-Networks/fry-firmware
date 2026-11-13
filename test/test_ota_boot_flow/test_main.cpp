// The I/O side of the boot decision (lib/fry_core/ota_boot_flow.*) on a host-side fake: how the
// inputs are built from the stored state, the order of the writes, the rollback and its failure,
// the serial lines, and whole-board simulations (bootloader + previous image) on top of it.
#include <unity.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "ota_boot_flow.h"
#include "ota_health.h"

using fry::BootFlowResult;
using fry::CrashEvidence;
using fry::FlowOutcome;

namespace {

// esp_reset_reason_t values of the ESP-IDF shipped with the Arduino core.
const uint32_t kPowerOn = 1, kSw = 3, kPanic = 4, kBrownout = 9;
const uint32_t kHeapGate = 20000;
const char* kVersion = "0.4.29";
const char* kManifest = "https://example.test/org/repo/releases/latest/download/manifest.json";
const char* kQuarantine = "https://example.test/org/repo/releases/download/quarantine/manifest.json";

class Fake : public fry::OtaBootPorts {
 public:
  // stored state
  std::string att, badver, url, qver, pending;
  uint8_t fails = 0, badn = 0;
  bool rbk = false;
  // platform
  bool pendingVerify = false;
  uint32_t reason = kSw;
  bool slotIntact = true;
  CrashEvidence evidence = CrashEvidence::No;
  bool failSelect = false, failAttWrite = false, failFailsWrite = false;
  // what happened, in order
  std::vector<std::string> writes;
  std::vector<std::string> logs;
  int selected = 0, finished = 0;

  void getAttempts(char* out, size_t cap) override { std::strncpy(out, att.c_str(), cap - 1); out[cap - 1] = 0; }
  bool setAttempts(const char* r) override {
    if (failAttWrite) return false;
    att = r;
    writes.push_back(std::string("att=") + r);
    return true;
  }
  void clearAttempts() override { att.clear(); writes.push_back("att cleared"); }
  uint8_t getBootFails() override { return fails; }
  bool setBootFails(uint8_t v) override {
    if (failFailsWrite) return false;
    fails = v;
    writes.push_back("fails=" + std::to_string(v));
    return true;
  }
  void getBadVer(char* out, size_t cap) override { std::strncpy(out, badver.c_str(), cap - 1); out[cap - 1] = 0; }
  uint8_t getBadN() override { return badn; }
  void getUrl(char* out, size_t cap) override { std::strncpy(out, url.c_str(), cap - 1); out[cap - 1] = 0; }
  void setUrl(const char* u) override { url = u; writes.push_back(std::string("url=") + u); }
  void getQuarantined(char* out, size_t cap) override { std::strncpy(out, qver.c_str(), cap - 1); out[cap - 1] = 0; }
  void setQuarantined(const char* v) override { qver = v; writes.push_back(std::string("qver=") + v); }
  void setPending(const char* v) override { pending = v; writes.push_back(std::string("pending=") + v); }
  bool pendingBoot() override { return pendingVerify || pending == kVersion; }
  uint32_t resetReason() override { return reason; }
  bool otherSlotIntact() override { return slotIntact; }
  CrashEvidence crashEvidence() override { return evidence; }
  bool selectOtherSlot() override {
    writes.push_back("select");
    if (failSelect) {
      pending.clear();
      rbk = false;
      return false;
    }
    selected++;
    rbk = true;
    return true;
  }
  void finishRollback() override { finished++; fails = 0; writes.push_back("restart"); }
  void log(const char* line) override { logs.push_back(line); }

  bool logged(const char* part) const {
    for (size_t i = 0; i < logs.size(); i++) {
      if (logs[i].find(part) != std::string::npos) return true;
    }
    return false;
  }
  int indexOfWrite(const std::string& w) const {
    for (size_t i = 0; i < writes.size(); i++) {
      if (writes[i] == w) return (int)i;
    }
    return -1;
  }
};

fry::BootFlowConfig cfg(const char* manifest = kManifest) {
  fry::BootFlowConfig c;
  c.version = kVersion;
  c.manifestUrl = manifest;
  c.failLimit = 3;
  return c;
}

// ---- the glue ----------------------------------------------------------------------------------

void test_the_first_pending_boot_opens_a_record_and_says_so() {
  Fake f;
  f.pendingVerify = true;
  f.pending = kVersion;
  const BootFlowResult r = fry::runBootFlow(f, cfg());
  TEST_ASSERT_EQUAL((int)FlowOutcome::Continue, (int)r.outcome);
  TEST_ASSERT_EQUAL_STRING("0.4.29#1", f.att.c_str());
  TEST_ASSERT_TRUE(f.logged("ota: install attempt 1 of 0.4.29 (decision at attempt 3)"));
  TEST_ASSERT_TRUE(r.inProbation);
  TEST_ASSERT_FALSE(f.logged("crash evidence"));  // nothing is read from flash for a build without a record
  TEST_ASSERT_EQUAL(0, f.selected);
}

void test_a_confirmed_boot_counts_a_crash_and_prints_the_probation_line() {
  Fake f;
  f.att = "0.4.29#1#1#0";
  f.reason = kPanic;
  f.evidence = CrashEvidence::Yes;
  const BootFlowResult r = fry::runBootFlow(f, cfg());
  TEST_ASSERT_EQUAL((int)FlowOutcome::Continue, (int)r.outcome);
  TEST_ASSERT_EQUAL_UINT8(1, f.fails);
  TEST_ASSERT_EQUAL_STRING("0.4.29#1#1#1", f.att.c_str());
  TEST_ASSERT_TRUE(f.logged("ota: probation for 0.4.29 - 1/3 crash boots without health, reset_reason=4"));
  TEST_ASSERT_TRUE(f.logged("ota: crash evidence for 0.4.29: yes"));
}

void test_inputs_come_from_the_stored_state_and_a_strike_keeper_gets_no_address() {
  Fake f;  // third pending boot, two strikes written by the previous image, a dump of this build
  f.pendingVerify = true;
  f.pending = kVersion;
  f.att = "0.4.29#2";
  f.badver = kVersion;
  f.badn = 2;
  f.evidence = CrashEvidence::Yes;
  const BootFlowResult r = fry::runBootFlow(f, cfg());
  TEST_ASSERT_EQUAL((int)FlowOutcome::RolledBack, (int)r.outcome);
  TEST_ASSERT_EQUAL(1, f.selected);
  TEST_ASSERT_EQUAL(1, f.finished);
  TEST_ASSERT_EQUAL_STRING("", f.url.c_str());
  TEST_ASSERT_EQUAL_STRING("", f.qver.c_str());
  TEST_ASSERT_EQUAL_STRING("0.4.29", f.pending.c_str());  // names the abandoned build for the strike
  TEST_ASSERT_TRUE(f.logged("ota: 0.4.29 is given up - the previous image keeps its strike"));
}

void test_the_quarantine_note_is_written_version_first_then_address_then_the_rollback() {
  Fake f;
  f.pendingVerify = true;
  f.pending = kVersion;
  f.att = "0.4.29#2#1";
  f.evidence = CrashEvidence::Yes;
  const BootFlowResult r = fry::runBootFlow(f, cfg());
  TEST_ASSERT_EQUAL((int)FlowOutcome::RolledBack, (int)r.outcome);
  const int q = f.indexOfWrite("qver=0.4.29");
  const int u = f.indexOfWrite(std::string("url=") + kQuarantine);
  const int p = f.indexOfWrite("pending=0.4.29");
  const int s = f.indexOfWrite("select");
  const int e = f.indexOfWrite("restart");
  TEST_ASSERT_TRUE(q >= 0 && u > q && p > u && s > p && e > s);
  TEST_ASSERT_TRUE(f.logged("pointed at the quarantine manifest"));
}

void test_a_failed_rollback_after_the_note_undoes_the_note() {
  Fake f;
  f.pendingVerify = true;
  f.pending = kVersion;
  f.att = "0.4.29#2#1";
  f.evidence = CrashEvidence::Yes;
  f.failSelect = true;
  const BootFlowResult r = fry::runBootFlow(f, cfg());
  TEST_ASSERT_EQUAL((int)FlowOutcome::RollbackFailed, (int)r.outcome);
  TEST_ASSERT_EQUAL_STRING("", f.url.c_str());
  TEST_ASSERT_EQUAL_STRING("", f.qver.c_str());
  TEST_ASSERT_EQUAL(0, f.selected);
  TEST_ASSERT_EQUAL(1, f.finished);  // it still restarts, as the rollback always did
  TEST_ASSERT_TRUE(f.logged("cannot be booted"));
}

void test_another_override_or_an_odd_compiled_address_means_no_quarantine() {
  Fake f;
  f.pendingVerify = true;
  f.pending = kVersion;
  f.att = "0.4.29#2#1";
  f.evidence = CrashEvidence::Yes;
  f.url = "https://lab.example.test/manifest.json";
  BootFlowResult r = fry::runBootFlow(f, cfg());
  TEST_ASSERT_EQUAL((int)FlowOutcome::Continue, (int)r.outcome);
  TEST_ASSERT_EQUAL_STRING("https://lab.example.test/manifest.json", f.url.c_str());
  TEST_ASSERT_EQUAL(0, f.selected);
  TEST_ASSERT_TRUE(f.logged("not confirmed at once"));
  Fake g;
  g.pendingVerify = true;
  g.pending = kVersion;
  g.att = "0.4.29#2#1";
  g.evidence = CrashEvidence::Yes;
  r = fry::runBootFlow(g, cfg("https://example.test/manifest.json"));
  TEST_ASSERT_EQUAL((int)FlowOutcome::Continue, (int)r.outcome);
  TEST_ASSERT_EQUAL(0, g.selected);
}

void test_the_note_is_cleared_when_a_different_build_runs_and_kept_for_the_same_one() {
  Fake f;
  f.url = kQuarantine;
  f.qver = "0.4.28";
  fry::runBootFlow(f, cfg());
  TEST_ASSERT_EQUAL_STRING("", f.url.c_str());
  TEST_ASSERT_EQUAL_STRING("", f.qver.c_str());
  TEST_ASSERT_TRUE(f.indexOfWrite("qver=") >= 0 && f.indexOfWrite("qver=") < f.indexOfWrite("url="));
  Fake g;
  g.url = kQuarantine;
  g.qver = kVersion;
  fry::runBootFlow(g, cfg());
  TEST_ASSERT_EQUAL_STRING(kQuarantine, g.url.c_str());
  Fake h;  // an operator override that merely differs is never touched
  h.url = "https://lab.example.test/manifest.json";
  h.qver = "0.4.28";
  fry::runBootFlow(h, cfg());
  TEST_ASSERT_EQUAL_STRING("https://lab.example.test/manifest.json", h.url.c_str());
}

void test_unavailable_crash_evidence_is_said_out_loud() {
  Fake f;
  f.att = "0.4.29#1";
  f.evidence = CrashEvidence::Unavailable;
  fry::runBootFlow(f, cfg());
  TEST_ASSERT_TRUE(f.logged("ota: crash evidence for 0.4.29: unavailable"));
  TEST_ASSERT_TRUE(f.logged("core dump inspection is unavailable"));
  Fake g;
  g.att = "0.4.29#1";
  g.evidence = CrashEvidence::No;
  fry::runBootFlow(g, cfg());
  TEST_ASSERT_TRUE(g.logged("ota: crash evidence for 0.4.29: no"));
  TEST_ASSERT_FALSE(g.logged("unavailable"));
}

void test_a_failed_nvs_write_is_logged_and_never_makes_a_decision_less_safe() {
  Fake f;
  f.pendingVerify = true;
  f.pending = kVersion;
  f.failAttWrite = true;
  BootFlowResult r = fry::runBootFlow(f, cfg());
  TEST_ASSERT_TRUE(r.recordWriteFailed);
  TEST_ASSERT_TRUE(f.logged("NVS write failed for the install attempt record"));
  TEST_ASSERT_EQUAL_STRING("", f.att.c_str());  // the count stays as it was: the next boot decides from the old record
  TEST_ASSERT_EQUAL((int)FlowOutcome::Continue, (int)r.outcome);
  Fake g;  // a lost crash counter can only delay a rollback, never cause one
  g.att = "0.4.29#1#1#0";
  g.reason = kPanic;
  g.failFailsWrite = true;
  r = fry::runBootFlow(g, cfg());
  TEST_ASSERT_TRUE(g.logged("NVS write failed for the crash boot counter"));
  TEST_ASSERT_EQUAL_UINT8(0, g.fails);
  TEST_ASSERT_EQUAL((int)FlowOutcome::Continue, (int)r.outcome);
}

void test_the_health_note_is_written_once_retried_once_and_logged_when_lost() {
  Fake f;
  f.att = "0.4.29#2";
  fry::AttemptRecord rec = fry::parseAttemptRecord(f.att.c_str(), kVersion);
  TEST_ASSERT_TRUE(fry::recordHealthReached(f, cfg(), &rec));
  TEST_ASSERT_EQUAL_STRING("0.4.29#2#1#0", f.att.c_str());
  TEST_ASSERT_TRUE(rec.healthy);
  const size_t before = f.writes.size();
  TEST_ASSERT_TRUE(fry::recordHealthReached(f, cfg(), &rec));  // already noted: no second write
  TEST_ASSERT_EQUAL((int)before, (int)f.writes.size());
  Fake g;
  g.att = "0.4.29#2";
  g.failAttWrite = true;
  rec = fry::parseAttemptRecord(g.att.c_str(), kVersion);
  TEST_ASSERT_FALSE(fry::recordHealthReached(g, cfg(), &rec));
  TEST_ASSERT_FALSE(rec.healthy);
  TEST_ASSERT_TRUE(g.logged("NVS write failed for the health note"));
}

void test_a_long_open_record_is_dropped() {
  Fake f;
  f.att = "0.4.29#1#1#8";
  f.reason = kPanic;
  f.fails = 2;
  const BootFlowResult r = fry::runBootFlow(f, cfg());
  TEST_ASSERT_EQUAL((int)FlowOutcome::Continue, (int)r.outcome);
  TEST_ASSERT_EQUAL_STRING("", f.att.c_str());
  TEST_ASSERT_EQUAL_UINT8(0, f.fails);
  TEST_ASSERT_FALSE(r.inProbation);
  TEST_ASSERT_TRUE(f.logged("ota: probation over for 0.4.29 - 8 boots"));
}

void test_the_last_attempt_lines() {
  Fake f;  // an earlier attempt reached the API, no dump: external resets, confirmed at once
  f.pendingVerify = true;
  f.pending = kVersion;
  f.att = "0.4.29#2#1";
  const BootFlowResult r = fry::runBootFlow(f, cfg());
  TEST_ASSERT_EQUAL((int)FlowOutcome::ConfirmNow, (int)r.outcome);
  TEST_ASSERT_TRUE(f.logged("ota: install attempt 3 of 0.4.29"));
  TEST_ASSERT_TRUE(f.logged("an earlier attempt reached the API, confirmed at once"));
  TEST_ASSERT_EQUAL(0, f.selected);
}

// ---- whole-board simulation --------------------------------------------------------------------
//
// Bootloader rules: a reset while the running image is PENDING_VERIFY boots the other slot; a reset
// of a confirmed image boots the same image. The previous image installs the new one at once at
// every boot (the worst case: no back-off); with oldKeepsStrikes it counts strikes and stops after
// three, and any image honours a quarantine address (an update check that finds nothing).

struct Board {
  Fake nvs;
  fry::BootFlowConfig conf = cfg();
  bool oldKeepsStrikes = false;
  bool installAllowed = true;
  bool coredump = true;       // the core dump API is usable
  bool onNew = false;
  int installs = 0;
  bool confirmedEver = false;
  bool dump = false;          // a core dump of the new build exists
  uint32_t lastConfirmAtMs = 0;
  int bootsOnNew = 0;
  bool rolledByProbation = false;
  fry::AttemptRecord rec;

  Board() { nvs.slotIntact = true; }

  void install() {
    if (!installAllowed) return;
    onNew = true;
    nvs.pendingVerify = true;
    nvs.pending = kVersion;
    installs++;
  }
  void previousImageRuns() {
    onNew = false;
    nvs.pendingVerify = false;
    nvs.pending.clear();  // the previous image clears the pending flag and the boot counter
    nvs.fails = 0;
    if (oldKeepsStrikes) {
      nvs.badver = kVersion;
      nvs.badn++;
      if (nvs.badn >= 3) installAllowed = false;  // permanently skipped
    }
    if (!nvs.url.empty()) installAllowed = false;  // reads the quarantine address: no update
    install();
  }
  void confirm() {
    nvs.pendingVerify = false;
    nvs.pending.clear();
    nvs.fails = 0;
    confirmedEver = true;
  }

  // One boot of the new image. Returns true if the board is still on it afterwards.
  bool runNew(uint32_t reason, uint32_t aliveMs, int apiOkAtMs = 8000, bool endCrash = false,
              int pocOkAtMs = 610000) {
    bootsOnNew++;
    if (reason >= 4 && reason <= 7) dump = true;  // the life before this boot ended in a panic or watchdog
    nvs.reason = reason;
    nvs.evidence = !coredump ? CrashEvidence::Unavailable : (dump ? CrashEvidence::Yes : CrashEvidence::No);
    const bool pendingAtStart = nvs.pendingVerify;
    const fry::BootFlowResult fr = fry::runBootFlow(nvs, conf);
    if (fr.outcome == FlowOutcome::RolledBack) {
      if (!pendingAtStart) rolledByProbation = true;
      previousImageRuns();
      return false;
    }
    if (fr.outcome == FlowOutcome::RollbackFailed) return pendingAtStart ? (previousImageRuns(), false) : true;
    if (fr.outcome == FlowOutcome::ConfirmNow) confirm();
    rec = fr.record;
    uint8_t fails = nvs.fails;
    bool inProbation = fr.inProbation;
    bool confirmed = !nvs.pendingVerify;
    bool probationOver = false;
    uint32_t t = 0;
    while (t < aliveMs) {
      t = (t + 1000 > aliveMs) ? aliveMs : t + 1000;
      const bool api = apiOkAtMs >= 0 && t >= (uint32_t)apiOkAtMs;
      const bool poc = pocOkAtMs >= 0 && t >= (uint32_t)pocOkAtMs;
      fry::CoreHealth h;
      h.staUp = true;
      h.apiOk2xx = api;
      h.startupDone = t >= 12000;
      h.tunnelSettled = t >= 12000;
      h.loopPasses = h.startupDone ? 10 : 0;
      h.freeHeap = 90000;
      h.uptimeMs = t;
      if (inProbation && rec.n > 0 && !rec.healthy && h.staUp && h.apiOk2xx) fry::recordHealthReached(nvs, conf, &rec);
      if (!confirmed && (fry::decideEarlyConfirm(true, h, kHeapGate) || fry::decideMarkValid(true, api, t, 660000))) {
        confirm();
        confirmed = true;
        lastConfirmAtMs = t;
      }
      if (confirmed && inProbation && !probationOver) {
        const fry::ProbationStep s = fry::decideProbationProgress(true, fry::coreHealthy(h, kHeapGate), t, nvs.fails, poc);
        if (s == fry::ProbationStep::ClearFails) nvs.fails = 0;
        if (s == fry::ProbationStep::End) {
          nvs.fails = 0;
          nvs.att.clear();
          rec = fry::AttemptRecord();
          probationOver = true;
        }
      }
    }
    (void)fails;
    if (endCrash) dump = true;
    if (nvs.pendingVerify) {  // still pending at the reset: the bootloader boots the other slot
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
  TEST_ASSERT_TRUE(b.runNew(kSw, 30000 + 25000));
  TEST_ASSERT_TRUE(b.onNew);
  TEST_ASSERT_TRUE(b.runNew(kPowerOn, 90000));
  TEST_ASSERT_EQUAL_INT(1, b.installs);
}

void test_a_reset_before_core_health_goes_back_and_the_second_attempt_gets_through() {
  Board b;
  b.install();
  TEST_ASSERT_FALSE(b.runNew(kSw, 10000));
  TEST_ASSERT_TRUE(b.onNew);
  TEST_ASSERT_EQUAL_INT(2, b.installs);
  TEST_ASSERT_TRUE(b.runNew(kSw, 60000));
  TEST_ASSERT_TRUE(b.confirmedEver);
}

void test_an_image_that_dies_in_the_tunnel_start_is_never_confirmed() {
  Board b;
  b.install();
  TEST_ASSERT_FALSE(b.runNew(kSw, 11000));  // the tunnel attempt would end at 12 s
  TEST_ASSERT_FALSE(b.confirmedEver);
  TEST_ASSERT_EQUAL_INT(2, b.installs);
}

void test_three_external_resets_after_reaching_the_api_the_third_install_confirms_and_stays() {
  Board b;  // previous image without strike memory; power, EN or cable: no core dump
  b.install();
  int guard = 0;
  while (guard++ < 50) {
    if (b.runNew(kSw, 20000)) break;  // the API answers at 8 s, the reset comes at 20 s
  }
  TEST_ASSERT_TRUE(b.onNew);
  TEST_ASSERT_TRUE(b.confirmedEver);
  TEST_ASSERT_EQUAL_INT(fry::kStickyInstallAttempt, b.installs);
  for (int i = 0; i < 20; i++) TEST_ASSERT_TRUE(b.runNew(kPowerOn, 10000));
  TEST_ASSERT_EQUAL_INT(fry::kStickyInstallAttempt, b.installs);
}

void test_sequence_a_a_silent_failure_with_a_strike_keeping_previous_image_is_not_stranded() {
  Board b;  // the build never gets an answer from the API (no panic, no dump)
  b.oldKeepsStrikes = true;
  b.install();
  int guard = 0;
  while (guard++ < 50 && b.onNew) b.runNew(kSw, 1300000, /*apiOkAtMs=*/-1);
  TEST_ASSERT_FALSE(b.onNew);
  TEST_ASSERT_FALSE(b.confirmedEver);  // the third install was not force-confirmed
  TEST_ASSERT_EQUAL_INT(3, b.installs);
  TEST_ASSERT_FALSE(b.installAllowed);  // the previous image's third strike ended it
}

void test_sequence_b_a_silent_failure_with_a_strike_less_previous_image_is_quarantined_after_four_installs() {
  Board b;
  b.install();
  int guard = 0;
  while (guard++ < 50 && b.onNew) b.runNew(kSw, 1300000, -1);
  TEST_ASSERT_FALSE(b.onNew);
  TEST_ASSERT_FALSE(b.confirmedEver);
  TEST_ASSERT_EQUAL_INT(4, b.installs);  // attempt 3 ran under the normal rules and also failed
  TEST_ASSERT_EQUAL_STRING(kQuarantine, b.nvs.url.c_str());
  TEST_ASSERT_EQUAL_STRING("0.4.29", b.nvs.qver.c_str());
}

void test_two_early_external_resets_never_quarantine_a_healthy_board() {
  Board b;  // resets at 3 s on attempts 1 and 2, before any 2xx; the third install is healthy
  b.install();
  TEST_ASSERT_FALSE(b.runNew(kSw, 3000));
  TEST_ASSERT_FALSE(b.runNew(kSw, 3000));
  TEST_ASSERT_TRUE(b.runNew(kSw, 60000));  // attempt 3: no give-up, the normal early confirm decides
  TEST_ASSERT_TRUE(b.confirmedEver);
  TEST_ASSERT_EQUAL_INT(3, b.installs);
  TEST_ASSERT_EQUAL_STRING("", b.nvs.url.c_str());
  TEST_ASSERT_EQUAL_STRING("", b.nvs.qver.c_str());
  TEST_ASSERT_TRUE(b.nvs.logged("quarantine exit available: yes, other slot bootable: yes"));
}

void test_a_third_install_that_reaches_the_api_and_is_then_reset_is_confirmed_by_the_fourth() {
  Board b;
  b.install();
  TEST_ASSERT_FALSE(b.runNew(kSw, 3000));
  TEST_ASSERT_FALSE(b.runNew(kSw, 3000));
  TEST_ASSERT_FALSE(b.runNew(kSw, 20000));  // attempt 3: the API answers at 8 s, a reset at 20 s
  TEST_ASSERT_TRUE(b.runNew(kSw, 60000));   // attempt 4: an earlier attempt reached the API, no dump: confirm
  TEST_ASSERT_TRUE(b.confirmedEver);
  TEST_ASSERT_EQUAL_INT(4, b.installs);
  TEST_ASSERT_EQUAL_STRING("", b.nvs.url.c_str());
}

void test_three_early_resets_then_a_failing_fourth_is_given_up_and_the_log_says_why_before() {
  Board b;
  b.install();
  for (int i = 0; i < 3; i++) TEST_ASSERT_FALSE(b.runNew(kSw, 3000));
  TEST_ASSERT_FALSE(b.runNew(kSw, 3000));  // attempt 4: given up at init
  TEST_ASSERT_FALSE(b.onNew);
  TEST_ASSERT_EQUAL_INT(4, b.installs);
  TEST_ASSERT_EQUAL_STRING(kQuarantine, b.nvs.url.c_str());
}

void test_the_log_says_why_attempt_3_continues() {
  Fake f;  // an operator override stored: the exit is not available
  f.pendingVerify = true;
  f.pending = kVersion;
  f.att = "0.4.29#2";
  f.url = "https://lab.example.test/manifest.json";
  fry::runBootFlow(f, cfg());
  TEST_ASSERT_TRUE(f.logged("ota: quarantine exit available: no, other slot bootable: yes"));
  Fake g;  // no bootable previous slot
  g.pendingVerify = true;
  g.pending = kVersion;
  g.att = "0.4.29#2";
  g.slotIntact = false;
  fry::runBootFlow(g, cfg());
  TEST_ASSERT_TRUE(g.logged("ota: quarantine exit available: yes, other slot bootable: no"));
}

void test_crash_evidence_stops_the_forced_confirm_and_the_board_ends_on_the_previous_image() {
  Board b;
  b.install();
  int guard = 0;
  while (guard++ < 50 && b.onNew) b.runNew(kSw, 20000, 8000, /*endCrash=*/true);
  TEST_ASSERT_FALSE(b.onNew);
  TEST_ASSERT_FALSE(b.confirmedEver);
  TEST_ASSERT_EQUAL_INT(3, b.installs);
  TEST_ASSERT_EQUAL_STRING(kQuarantine, b.nvs.url.c_str());
}

void test_crash_evidence_with_a_previous_image_that_keeps_strikes_needs_no_address() {
  Board b;
  b.oldKeepsStrikes = true;
  b.install();
  int guard = 0;
  while (guard++ < 50 && b.onNew) b.runNew(kSw, 20000, 8000, true);
  TEST_ASSERT_FALSE(b.onNew);
  TEST_ASSERT_EQUAL_STRING("", b.nvs.url.c_str());
  TEST_ASSERT_FALSE(b.installAllowed);
  TEST_ASSERT_EQUAL_INT(3, b.installs);
  TEST_ASSERT_FALSE(b.confirmedEver);
}

void test_when_the_previous_image_cannot_be_stopped_the_image_is_not_force_confirmed() {
  Board b;  // no strike memory and no usable quarantine address: the behaviour stays as it was
  b.conf = cfg("https://example.test/manifest.json");
  b.install();
  for (int i = 0; i < 40; i++) b.runNew(kSw, 20000, 8000, true);
  TEST_ASSERT_FALSE(b.confirmedEver);
  TEST_ASSERT_TRUE(b.installs > fry::kStickyInstallAttempt);
}

void test_unreadable_evidence_is_never_read_as_no_evidence_at_the_last_attempt() {
  Board b;  // no core dump partition: a missing dump proves nothing
  b.coredump = false;
  b.install();
  for (int i = 0; i < 12; i++) b.runNew(kSw, 20000);  // external-looking resets, the API answered at 8 s each time
  TEST_ASSERT_FALSE(b.confirmedEver);                  // not force-confirmed
  TEST_ASSERT_FALSE(b.nvs.url == kQuarantine);         // and not given up either: the behaviour stays as it was
  TEST_ASSERT_TRUE(b.nvs.logged("not confirmed at once"));
}

void test_a_panic_is_evidence_even_when_the_dump_cannot_be_read() {
  Board b;  // a confirmed image panics at 300 s, three times; the dump partition is missing
  b.coredump = false;
  b.install();
  b.rec.n = 0;
  TEST_ASSERT_TRUE(b.runNew(kSw, 300000, 8000, true));
  b.nvs.att = "0.4.29#3#1";  // at the last attempt, so a plain rollback is no longer allowed without evidence
  TEST_ASSERT_TRUE(b.runNew(kPanic, 300000, 8000, true));
  TEST_ASSERT_TRUE(b.runNew(kPanic, 300000, 8000, true));
  TEST_ASSERT_FALSE(b.runNew(kPanic, 300000, 8000, true));
  TEST_ASSERT_EQUAL_STRING(kQuarantine, b.nvs.url.c_str());
}

// ---- probation (M1, S3) ---------------------------------------------------------------------------

void test_three_consecutive_boots_that_panic_at_300_s_roll_back_on_the_third() {
  Board b;
  b.install();
  TEST_ASSERT_TRUE(b.runNew(kSw, 300000, 8000, true));       // confirmed at ~32 s, panics at 300 s
  TEST_ASSERT_TRUE(b.runNew(kPanic, 300000, 8000, true));    // crash boot 1; 300 s of health forgives nothing
  TEST_ASSERT_EQUAL_UINT8(1, b.nvs.fails);
  TEST_ASSERT_TRUE(b.runNew(kPanic, 300000, 8000, true));    // crash boot 2
  TEST_ASSERT_EQUAL_UINT8(2, b.nvs.fails);
  TEST_ASSERT_FALSE(b.runNew(kPanic, 300000, 8000, true));   // crash boot 3: rolled back at init
  TEST_ASSERT_TRUE(b.rolledByProbation);
  TEST_ASSERT_EQUAL_INT(2, b.installs);
}

void test_the_same_at_500_s() {
  Board b;
  b.install();
  TEST_ASSERT_TRUE(b.runNew(kSw, 500000, 8000, true));
  TEST_ASSERT_TRUE(b.runNew(kPanic, 500000, 8000, true));
  TEST_ASSERT_TRUE(b.runNew(kPanic, 500000, 8000, true));
  TEST_ASSERT_FALSE(b.runNew(kPanic, 500000, 8000, true));
  TEST_ASSERT_TRUE(b.rolledByProbation);
}

void test_a_boot_that_is_healthy_past_the_horizon_with_a_poc_clears_the_count() {
  Board b;
  b.install();
  TEST_ASSERT_TRUE(b.runNew(kSw, 100000, 8000, true));
  TEST_ASSERT_TRUE(b.runNew(kPanic, 100000, 8000, true));
  TEST_ASSERT_TRUE(b.runNew(kPanic, 100000, 8000, true));
  TEST_ASSERT_EQUAL_UINT8(2, b.nvs.fails);
  TEST_ASSERT_TRUE(b.runNew(kPowerOn, 700000, 8000, false));  // past 660 s with a PoC answer at 610 s
  TEST_ASSERT_EQUAL_UINT8(0, b.nvs.fails);
  TEST_ASSERT_TRUE(b.runNew(kPanic, 100000, 8000, true));     // the next crash starts counting from one again
  TEST_ASSERT_EQUAL_UINT8(1, b.nvs.fails);
  TEST_ASSERT_FALSE(b.rolledByProbation);
}

void test_forgiveness_needs_the_poc_answer() {
  Board b;
  b.install();
  TEST_ASSERT_TRUE(b.runNew(kSw, 100000, 8000, true));
  TEST_ASSERT_TRUE(b.runNew(kPanic, 100000, 8000, true));
  TEST_ASSERT_EQUAL_UINT8(1, b.nvs.fails);
  TEST_ASSERT_TRUE(b.runNew(kPowerOn, 700000, 8000, false, /*pocOkAtMs=*/-1));
  TEST_ASSERT_EQUAL_UINT8(1, b.nvs.fails);  // past 660 s but no PoC/lease 2xx: not forgiven
  TEST_ASSERT_TRUE(b.runNew(kPowerOn, 700000, 8000, false, 610000));
  TEST_ASSERT_EQUAL_UINT8(0, b.nvs.fails);
}

void test_power_cycles_never_count_even_without_health() {
  Board b;
  b.install();
  TEST_ASSERT_TRUE(b.runNew(kSw, 40000));
  for (int i = 0; i < 6; i++) TEST_ASSERT_TRUE(b.runNew(kPowerOn, 5000));
  TEST_ASSERT_EQUAL_INT(0, b.rolledByProbation);
  TEST_ASSERT_EQUAL_INT(1, b.installs);
  TEST_ASSERT_EQUAL_UINT8(0, b.nvs.fails);
}

void test_brownouts_without_a_dump_do_not_roll_back_a_healthy_image() {
  Board b;
  b.install();
  TEST_ASSERT_TRUE(b.runNew(kSw, 40000));
  for (int i = 0; i < 6; i++) TEST_ASSERT_TRUE(b.runNew(kBrownout, 40000));
  TEST_ASSERT_FALSE(b.rolledByProbation);
  TEST_ASSERT_EQUAL_UINT8(0, b.nvs.fails);
}

void test_the_probation_record_is_dropped_after_a_number_of_boots_for_a_board_that_never_runs_long() {
  Board b;
  b.install();
  TEST_ASSERT_TRUE(b.runNew(kSw, 40000));
  for (int i = 0; i < fry::kProbationMaxBoots + 1; i++) TEST_ASSERT_TRUE(b.runNew(kPowerOn, 40000));
  TEST_ASSERT_EQUAL_STRING("", b.nvs.att.c_str());
  for (int i = 0; i < 6; i++) TEST_ASSERT_TRUE(b.runNew(kPanic, 40000));  // later crashes are not this mechanism
  TEST_ASSERT_FALSE(b.rolledByProbation);
}

void test_probation_ends_after_a_long_healthy_run() {
  Board b;
  b.install();
  TEST_ASSERT_TRUE(b.runNew(kSw, fry::kProbationEndMs + 5000));
  TEST_ASSERT_EQUAL_STRING("", b.nvs.att.c_str());
}

// Property: whatever the reset pattern, with a way to stop the previous image the new image is installed
// at most kStickyInstallAttempt (strikes, or a dump) or kStickyInstallAttempt + 1 (a silent failure) times.
void test_no_reset_pattern_alternates_forever() {
  uint32_t seed = 12345;
  const uint32_t reasons[] = {kPowerOn, kSw, kPanic, kBrownout, 6, 2, 0, 8};
  for (int run = 0; run < 400; run++) {
    Board b;
    b.oldKeepsStrikes = (run % 2) == 1;
    b.nvs.slotIntact = (run % 7) != 0;
    const bool knob = (run % 3) != 0;
    if (!knob) b.conf = cfg("https://example.test/manifest.json");
    b.coredump = (run % 5) != 0;
    b.install();
    for (int boots = 0; boots < 400; boots++) {
      seed = seed * 1664525u + 1013904223u;
      const uint32_t reason = reasons[(seed >> 8) % 8];
      seed = seed * 1664525u + 1013904223u;
      const uint32_t alive = 1000 + ((seed >> 8) % 400) * 1000;  // 1 s .. 400 s
      seed = seed * 1664525u + 1013904223u;
      const int apiAt = ((seed >> 8) % 5 == 0) ? -1 : (int)(2000 + ((seed >> 12) % 10) * 1000);
      const bool endCrash = ((seed >> 20) % 4) == 0;
      b.runNew(reason, alive, apiAt, endCrash);
      if (!b.onNew && !b.installAllowed) break;
    }
    // Bounds per row (a way to stop the previous image, a bootable slot, a readable dump partition):
    // strikes or a dump give up at attempt 3; a silent failure without a dump one install later.
    if ((b.oldKeepsStrikes || knob) && b.nvs.slotIntact && b.coredump) {
      const int bound = b.oldKeepsStrikes ? fry::kStickyInstallAttempt : fry::kStickyInstallAttempt + 1;
      TEST_ASSERT_TRUE_MESSAGE(b.installs <= bound, "installs bounded");
    }
  }
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_first_pending_boot_opens_a_record_and_says_so);
  RUN_TEST(test_a_confirmed_boot_counts_a_crash_and_prints_the_probation_line);
  RUN_TEST(test_inputs_come_from_the_stored_state_and_a_strike_keeper_gets_no_address);
  RUN_TEST(test_the_quarantine_note_is_written_version_first_then_address_then_the_rollback);
  RUN_TEST(test_a_failed_rollback_after_the_note_undoes_the_note);
  RUN_TEST(test_another_override_or_an_odd_compiled_address_means_no_quarantine);
  RUN_TEST(test_the_note_is_cleared_when_a_different_build_runs_and_kept_for_the_same_one);
  RUN_TEST(test_unavailable_crash_evidence_is_said_out_loud);
  RUN_TEST(test_a_failed_nvs_write_is_logged_and_never_makes_a_decision_less_safe);
  RUN_TEST(test_the_health_note_is_written_once_retried_once_and_logged_when_lost);
  RUN_TEST(test_a_long_open_record_is_dropped);
  RUN_TEST(test_the_last_attempt_lines);
  RUN_TEST(test_a_healthy_install_confirms_in_well_under_a_minute);
  RUN_TEST(test_a_reset_25_s_after_the_confirm_does_not_roll_back);
  RUN_TEST(test_a_reset_before_core_health_goes_back_and_the_second_attempt_gets_through);
  RUN_TEST(test_an_image_that_dies_in_the_tunnel_start_is_never_confirmed);
  RUN_TEST(test_three_external_resets_after_reaching_the_api_the_third_install_confirms_and_stays);
  RUN_TEST(test_sequence_a_a_silent_failure_with_a_strike_keeping_previous_image_is_not_stranded);
  RUN_TEST(test_sequence_b_a_silent_failure_with_a_strike_less_previous_image_is_quarantined_after_four_installs);
  RUN_TEST(test_two_early_external_resets_never_quarantine_a_healthy_board);
  RUN_TEST(test_a_third_install_that_reaches_the_api_and_is_then_reset_is_confirmed_by_the_fourth);
  RUN_TEST(test_three_early_resets_then_a_failing_fourth_is_given_up_and_the_log_says_why_before);
  RUN_TEST(test_the_log_says_why_attempt_3_continues);
  RUN_TEST(test_crash_evidence_stops_the_forced_confirm_and_the_board_ends_on_the_previous_image);
  RUN_TEST(test_crash_evidence_with_a_previous_image_that_keeps_strikes_needs_no_address);
  RUN_TEST(test_when_the_previous_image_cannot_be_stopped_the_image_is_not_force_confirmed);
  RUN_TEST(test_unreadable_evidence_is_never_read_as_no_evidence_at_the_last_attempt);
  RUN_TEST(test_a_panic_is_evidence_even_when_the_dump_cannot_be_read);
  RUN_TEST(test_three_consecutive_boots_that_panic_at_300_s_roll_back_on_the_third);
  RUN_TEST(test_the_same_at_500_s);
  RUN_TEST(test_a_boot_that_is_healthy_past_the_horizon_with_a_poc_clears_the_count);
  RUN_TEST(test_forgiveness_needs_the_poc_answer);
  RUN_TEST(test_power_cycles_never_count_even_without_health);
  RUN_TEST(test_brownouts_without_a_dump_do_not_roll_back_a_healthy_image);
  RUN_TEST(test_the_probation_record_is_dropped_after_a_number_of_boots_for_a_board_that_never_runs_long);
  RUN_TEST(test_probation_ends_after_a_long_healthy_run);
  RUN_TEST(test_no_reset_pattern_alternates_forever);
  return UNITY_END();
}
