// The OTA check waits, bounded, for the previous connection's leftovers before it measures the heap it starts on (ESP8266).
//
// lib/fry_core/ota_settle.h has the story. The report tick (registration / telemetry / PoC) runs right before a check and its connection leaves
// small lwIP blocks in the middle of the free region for a few milliseconds to a few seconds. x3-tip bench capture (lo/c1-x3t-204146.lines.txt):
//   cycle C: a 24 B block at offset 11688 was still alive at the check start: blk 32360 instead of the settled 39448. The wait after the
//            manifest (settleAfterManifest) takes "blk at the check start" as its reference, so it released the download at once (no
//            "settled" line) onto a heap that the manifest connection's own survivors still split: download-begin blk 26280 instead of 32808.
//   cycle G: a 192 B + 112 B pair alive at the check start: blk 29776, and the manifest gate (blk >= 29808) skipped the whole check.
// Both victims have the same cause, a check that starts on a heap that has not settled, and the reference "what the check started with" cannot
// see it. This test pins the baseline that can: the largest block an earlier check started on (kept for the boot, rising only as the heap
// recovers, adopting a lower level once when the bound is reached), the decision, the bound (<= 5 s, 20 ms polls), and where
// src/core/ota_client.cpp calls the wait: in checkNow(), before the manifest gate and before s_blkAtCheckStart is measured.
#include <unity.h>

#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "ota_settle.h"

namespace {

const uint32_t kMax = fry::kOtaSettleMaxMs;
const uint32_t kSlack = fry::kOtaSettleSlackBytes;
const int kHold = static_cast<int>(fry::SettleHold::Hold);
const int kProceed = static_cast<int>(fry::SettleHold::Proceed);

// The numbers of the x3-tip capture.
const uint32_t kSettled = 39448;       // pre-check blk of the five clean cycles
const uint32_t kCycleCStart = 32360;   // cycle C: the 24 B block at 11688 splits 4624..11688 | 11712..end
const uint32_t kCycleCAfterManifest = 32624;  // what the old wait saw at its first look (>= 32360 - 64): released
const uint32_t kCycleGStart = 29776;   // cycle G: 192 + 112 B pair; the manifest gate wants 29808

int decide(uint32_t now, uint32_t base, uint32_t held, uint32_t stable) {
  return static_cast<int>(fry::decideCheckStartSettle(now, base, kSlack, held, stable, kMax));
}

void test_cycle_c_at_the_check_start_is_held_until_the_block_is_back() {
  TEST_ASSERT_EQUAL_INT_MESSAGE(kHold, decide(kCycleCStart, kSettled, 0, 0), "24 B survivor: blk 32360 against a settled 39448");
  TEST_ASSERT_EQUAL_INT(kHold, decide(kCycleCStart, kSettled, 3000, 3000));
  TEST_ASSERT_EQUAL_INT_MESSAGE(kHold, decide(kCycleCAfterManifest, kSettled, 100, 0), "the first look of the old wait: still short of the settled block");
  TEST_ASSERT_EQUAL_INT_MESSAGE(kProceed, decide(kSettled, kSettled, 200, 0), "back at the settled block: go");
  TEST_ASSERT_EQUAL_INT(kProceed, decide(kSettled + 8, kSettled, 0, 0));
}

void test_cycle_g_at_the_check_start_is_held_before_the_manifest_gate_samples() {
  TEST_ASSERT_EQUAL_INT_MESSAGE(kHold, decide(kCycleGStart, kSettled, 0, 0), "192 + 112 B pair: blk 29776");
  TEST_ASSERT_EQUAL_INT(kHold, decide(kCycleGStart, kSettled, 1100, 1100));
  TEST_ASSERT_EQUAL_INT(kProceed, decide(kSettled, kSettled, 1200, 0));
}

void test_the_old_reference_let_cycle_c_through() {
  // The wait after the manifest takes the check-start block as its reference: with the split start it is satisfied at the first look.
  TEST_ASSERT_EQUAL_INT_MESSAGE(kProceed,
                                static_cast<int>(fry::decideHeapSettle(kCycleCAfterManifest, kCycleCStart, kSlack, 0, kMax)),
                                "the reference the old code used: why the check-start block cannot be the baseline");
}

void test_the_wait_is_bounded_at_five_seconds_whatever_the_heap_looks_like() {
  TEST_ASSERT_TRUE_MESSAGE(kMax <= 5000, "the lead's bound: at most 5 s");
  TEST_ASSERT_EQUAL_INT(kProceed, decide(kCycleCStart, kSettled, kMax, 0));
  TEST_ASSERT_EQUAL_INT(kProceed, decide(0, kSettled, kMax + 1, 0));
  TEST_ASSERT_EQUAL_INT(kProceed, decide(0, kSettled, UINT32_MAX, 0));
  uint32_t t = 0;
  for (;; t += fry::kOtaSettlePollMs) {
    if (decide(20000, kSettled, t, t) == kProceed) break;
    TEST_ASSERT_TRUE_MESSAGE(t <= kMax, "starved past the bound");
  }
  TEST_ASSERT_TRUE_MESSAGE(t >= kMax && t < kMax + fry::kOtaSettlePollMs, "released by the bound, to within one poll");
}

void test_a_survivor_that_dies_inside_the_bound_releases_the_check_by_recovery() {
  uint32_t t = 0;
  uint32_t blk = 0;
  for (;; t += fry::kOtaSettlePollMs) {
    blk = t < 3100 ? kCycleCStart : kSettled;  // cycle C's 24 B block was alive for up to 3.1 s
    if (decide(blk, kSettled, t, 0) == kProceed) break;
    TEST_ASSERT_TRUE_MESSAGE(t < kMax, "never released");
  }
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(kSettled, blk, "released by the block coming back, not by the bound");
  TEST_ASSERT_TRUE(t >= 3100 && t < 3100 + fry::kOtaSettlePollMs);
}

void test_no_baseline_yet_waits_for_the_block_to_stand_still() {
  // The first check of a boot has no earlier check to compare with: it waits until the block has been the same for kOtaCheckStartStableMs.
  TEST_ASSERT_TRUE(fry::kOtaCheckStartStableMs >= 500 && fry::kOtaCheckStartStableMs <= 2000);
  TEST_ASSERT_EQUAL_INT(kHold, decide(kSettled, 0, 0, 0));
  TEST_ASSERT_EQUAL_INT(kHold, decide(kSettled, 0, 900, fry::kOtaCheckStartStableMs - 1));
  TEST_ASSERT_EQUAL_INT(kProceed, decide(kSettled, 0, 1000, fry::kOtaCheckStartStableMs));
  TEST_ASSERT_EQUAL_INT_MESSAGE(kProceed, decide(kCycleCStart, 0, kMax, 0), "and the bound still ends it");
}

void test_the_slack_is_exact_and_does_not_wrap() {
  TEST_ASSERT_EQUAL_INT(kProceed, decide(kSettled - kSlack, kSettled, 0, 0));
  TEST_ASSERT_EQUAL_INT_MESSAGE(kHold, decide(kSettled - kSlack - 8, kSettled, 0, 0), "one umm block under the slack: still short");
  TEST_ASSERT_EQUAL_INT_MESSAGE(kProceed, static_cast<int>(fry::decideCheckStartSettle(0, 32, 64, 0, 0, kMax)), "baseline < slack: want 0, not 2^32 - 32");
}

void test_the_baseline_rises_with_the_heap_and_never_falls_by_itself() {
  TEST_ASSERT_EQUAL_UINT32(kSettled, fry::nextCheckStartBaseline(0, kSettled, false));
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(kSettled, fry::nextCheckStartBaseline(kSettled, kCycleCStart, false),
                                   "a split check start must not lower the baseline");
  TEST_ASSERT_EQUAL_UINT32(kSettled, fry::nextCheckStartBaseline(30072, kSettled, false));
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(kSettled, fry::nextCheckStartBaseline(kSettled, kSettled - kSlack, false), "within the slack: unchanged");
}

void test_a_heap_that_did_not_recover_by_the_bound_becomes_the_new_level_once() {
  // A persistent block that landed mid-heap (dl-31: 40 B at 12544, settled blk 30072 against 38040): the first check after it waits the
  // whole bound; the later ones must not.
  const uint32_t lowered = fry::nextCheckStartBaseline(38040, 30072, true);
  TEST_ASSERT_EQUAL_UINT32(30072, lowered);
  TEST_ASSERT_EQUAL_INT_MESSAGE(kProceed, decide(30072, lowered, 0, 0), "the next check does not wait again");
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(38040, fry::nextCheckStartBaseline(38040, 38040, true), "bound reached but the block is back: nothing lowers");
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(38040, fry::nextCheckStartBaseline(30072, 38040, true), "and a recovery after a lowering raises it again");
}

void test_the_constants() {
  TEST_ASSERT_TRUE(fry::kOtaSettlePollMs == 20);
  TEST_ASSERT_TRUE(kMax <= 5000 && kMax >= 1000);
}

// ---- checkNow() must run the wait before the gate and before the block it measures ---------------------------------------------
bool readFile(const std::string& path, std::string& out) {
  std::ifstream f(path.c_str(), std::ios::in | std::ios::binary);
  if (!f) return false;
  std::ostringstream ss;
  ss << f.rdbuf();
  out = ss.str();
  return !out.empty();
}

bool loadSource(const std::string& rel, std::string& out) {
  const std::string self = __FILE__;
  const std::string tail = "test/test_ota_settle_start/test_main.cpp";
  std::vector<std::string> prefixes;
  if (self.size() >= tail.size() && self.compare(self.size() - tail.size(), tail.size(), tail) == 0) {
    prefixes.push_back(self.substr(0, self.size() - tail.size()));
  }
  const char* ups[] = {"", "../", "../../", "../../../", "../../../../"};
  for (size_t i = 0; i < sizeof(ups) / sizeof(ups[0]); i++) prefixes.push_back(ups[i]);
  for (size_t i = 0; i < prefixes.size(); i++) {
    if (readFile(prefixes[i] + rel, out)) return true;
  }
  return false;
}

int countOf(const std::string& hay, const std::string& needle) {
  int n = 0;
  for (size_t pos = hay.find(needle); pos != std::string::npos; pos = hay.find(needle, pos + needle.size())) n++;
  return n;
}

bool checkNowBody(std::string& fn) {
  std::string src;
  if (!loadSource("src/core/ota_client.cpp", src)) return false;
  const size_t a = src.find("bool checkNow() {");
  const size_t b = src.find("FRY_OTA_ESP8266_NOINLINE static bool evaluateManifest(const String& body, OtaPlan& plan) {", a);
  if (a == std::string::npos || b == std::string::npos) return false;
  fn = src.substr(a, b - a);
  return true;
}

// True when `pos` of `text` is inside an open `#if defined(ARDUINO_ARCH_ESP8266)` branch (not its #else).
bool inEsp8266Branch(const std::string& text, size_t pos) {
  const size_t guard = text.rfind("#if defined(ARDUINO_ARCH_ESP8266)", pos);
  if (guard == std::string::npos) return false;
  int depth = 1;
  std::istringstream lines(text.substr(guard + 1, pos - guard - 1));
  std::string line;
  std::getline(lines, line);
  while (std::getline(lines, line)) {
    const size_t i = line.find_first_not_of(" \t");
    if (i == std::string::npos || line[i] != '#') continue;
    const std::string d = line.substr(i + 1);
    if (d.compare(0, 2, "if") == 0) depth++;
    else if (d.compare(0, 5, "endif") == 0) depth--;
    else if ((d.compare(0, 4, "else") == 0 || d.compare(0, 4, "elif") == 0) && depth == 1) return false;
    if (depth < 1) return false;
  }
  return true;
}

void test_checkNow_waits_before_the_manifest_gate_and_before_it_measures() {
  std::string fn;
  TEST_ASSERT_TRUE_MESSAGE(checkNowBody(fn), "cannot find checkNow() in src/core/ota_client.cpp");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "settleBeforeCheck();"), "one wait in checkNow()");
  const size_t wait = fn.find("settleBeforeCheck();");
  const size_t gate = fn.find("fry::waitForHeapGate(HEAP_GATE_OTA_MANIFEST, HEAP_GATE_OTA_MANIFEST_BLOCK, 1)");
  const size_t reserve = fn.find("plan.reserveEarly();");
  const size_t measure = fn.find("s_blkAtCheckStart = fry::queryMaxFreeBlock();");
  TEST_ASSERT_TRUE_MESSAGE(wait != std::string::npos && gate != std::string::npos && reserve != std::string::npos && measure != std::string::npos,
                           "the wait, the manifest gate, the plan reservation and the measurement are all in checkNow()");
  TEST_ASSERT_TRUE_MESSAGE(wait < gate, "before the manifest gate samples blk (cycle G: 29776 against 29808)");
  TEST_ASSERT_TRUE_MESSAGE(wait < reserve && wait < measure, "before the block the download will wait for is measured (cycle C)");
  TEST_ASSERT_TRUE_MESSAGE(inEsp8266Branch(fn, wait), "in the ESP8266 branch: the ESP32 keeps its image");
  TEST_ASSERT_TRUE_MESSAGE(fn.find("fry_identity::ensureMinerKey(") < wait, "after the keyless early return: a check that is not going to run does not wait");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(fn, "settleAfterManifest("), "the wait after the manifest stays in downloadAndApply()");
}

void test_the_wait_polls_with_delay_under_the_decision_the_baseline_and_the_bound() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/core/ota_client.cpp", src), "cannot read src/core/ota_client.cpp");
  const size_t a = src.find("static void settleBeforeCheck() {");
  TEST_ASSERT_TRUE_MESSAGE(a != std::string::npos, "settleBeforeCheck() is defined");
  const size_t b = src.find("\n}\n", a);
  TEST_ASSERT_TRUE_MESSAGE(b != std::string::npos, "...and ends");
  const std::string fn = src.substr(a, b - a);
  TEST_ASSERT_TRUE_MESSAGE(fn.find("fry::queryMaxFreeBlock()") != std::string::npos, "it looks at the largest free block");
  TEST_ASSERT_TRUE_MESSAGE(fn.find("fry::decideCheckStartSettle(") != std::string::npos, "through the tested decision");
  TEST_ASSERT_TRUE_MESSAGE(fn.find("fry::nextCheckStartBaseline(") != std::string::npos, "and updates the baseline through the tested rule");
  TEST_ASSERT_TRUE_MESSAGE(fn.find("fry::kOtaSettleSlackBytes") != std::string::npos && fn.find("fry::kOtaSettleMaxMs") != std::string::npos,
                           "with its slack and its bound");
  TEST_ASSERT_TRUE_MESSAGE(fn.find("delay(fry::kOtaSettlePollMs)") != std::string::npos, "and gives lwIP the time (delay runs its input and timers)");
  TEST_ASSERT_TRUE_MESSAGE(src.find("static uint32_t s_blkSettledBase") != std::string::npos, "the baseline is one static word");
  TEST_ASSERT_TRUE_MESSAGE(inEsp8266Branch(src, a), "ESP8266 only");
  const size_t chk = src.find("bool checkNow() {");
  TEST_ASSERT_TRUE_MESSAGE(chk != std::string::npos && a < chk, "defined before checkNow()");
  TEST_ASSERT_TRUE_MESSAGE(fn.find("new ") == std::string::npos && fn.find("malloc") == std::string::npos && fn.find("String") == std::string::npos,
                           "the wait itself allocates nothing");
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_cycle_c_at_the_check_start_is_held_until_the_block_is_back);
  RUN_TEST(test_cycle_g_at_the_check_start_is_held_before_the_manifest_gate_samples);
  RUN_TEST(test_the_old_reference_let_cycle_c_through);
  RUN_TEST(test_the_wait_is_bounded_at_five_seconds_whatever_the_heap_looks_like);
  RUN_TEST(test_a_survivor_that_dies_inside_the_bound_releases_the_check_by_recovery);
  RUN_TEST(test_no_baseline_yet_waits_for_the_block_to_stand_still);
  RUN_TEST(test_the_slack_is_exact_and_does_not_wrap);
  RUN_TEST(test_the_baseline_rises_with_the_heap_and_never_falls_by_itself);
  RUN_TEST(test_a_heap_that_did_not_recover_by_the_bound_becomes_the_new_level_once);
  RUN_TEST(test_the_constants);
  RUN_TEST(test_checkNow_waits_before_the_manifest_gate_and_before_it_measures);
  RUN_TEST(test_the_wait_polls_with_delay_under_the_decision_the_baseline_and_the_bound);
  return UNITY_END();
}
