// The OTA download waits, bounded, for the manifest connection's teardown before it builds its clients (ESP8266).
//
// lib/fry_core/ota_settle.h has the whole story: the connection's pcb (192 B), the pbuf of its last TLS record (112 B) and that record's
// tcp_seg (24 B) are still alive when the download's constructors run a millisecond after the manifest's clients are gone, and where they
// sit decides where the download's work block and BearSSL thunk land. Bench X2: the download's block after its constructors was 29072,
// 29072, 23000, 22648, 22648, 22648, 15008 over seven consecutive checks. This test pins the decision (hold until the largest block is back,
// release at the bound), the constants, and that src/core/ota_client.cpp checkNow() measures the block before the session and that
// downloadAndApply() waits as its first act, before the clients it is about to construct (test_ota_release pins the release block before it). The allocator effect is read from the real umm_malloc replays of the bench heaps
// (c1/logs/settle-host-replay.log) and from the device heap map.
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

int decide(uint32_t now, uint32_t before, uint32_t held) {
  return static_cast<int>(fry::decideHeapSettle(now, before, kSlack, held, kMax));
}

void test_it_waits_while_the_largest_block_is_short_of_where_the_check_started() {
  // X2 check 3: 35712 at the start, 28880 right after the manifest's clients went (survivors alive).
  TEST_ASSERT_EQUAL_INT_MESSAGE(kHold, decide(28880, 35712, 0), "survivors still split the region: wait");
  TEST_ASSERT_EQUAL_INT(kHold, decide(15728, 35712, kMax - 1));
  TEST_ASSERT_EQUAL_INT_MESSAGE(kHold, decide(35712 - kSlack - 8, 35712, 100), "one block under the slack: still short");
}

void test_it_proceeds_once_the_block_is_back() {
  TEST_ASSERT_EQUAL_INT(kProceed, decide(35712, 35712, 0));
  TEST_ASSERT_EQUAL_INT_MESSAGE(kProceed, decide(35712 + 8, 35712, 0), "above the start counts as back");
  TEST_ASSERT_EQUAL_INT_MESSAGE(kProceed, decide(35712 - kSlack, 35712, 0), "exactly at the slack counts as back");
}

void test_the_wait_is_bounded_whatever_the_heap_looks_like() {
  TEST_ASSERT_EQUAL_INT_MESSAGE(kProceed, decide(15728, 35712, kMax), "at the bound the download goes on");
  TEST_ASSERT_EQUAL_INT(kProceed, decide(0, 35712, kMax + 1));
  TEST_ASSERT_EQUAL_INT(kProceed, decide(0, 35712, UINT32_MAX));
}

void test_a_heap_that_never_recovers_cannot_starve_the_download() {
  uint32_t t = 0;
  for (;; t += fry::kOtaSettlePollMs) {
    if (decide(20000, 35712, t) == kProceed) break;
    TEST_ASSERT_TRUE_MESSAGE(t <= kMax, "starved past the bound");
  }
  TEST_ASSERT_TRUE_MESSAGE(t >= kMax && t < kMax + fry::kOtaSettlePollMs, "released by the bound, to within one poll");
}

void test_a_heap_that_recovers_inside_the_bound_is_released_by_recovering() {
  // the survivors die 700 ms in
  uint32_t t = 0;
  uint32_t blk = 0;
  for (;; t += fry::kOtaSettlePollMs) {
    blk = t < 700 ? 28880u : 35712u;
    if (decide(blk, 35712, t) == kProceed) break;
    TEST_ASSERT_TRUE_MESSAGE(t < kMax, "never released");
  }
  TEST_ASSERT_EQUAL_UINT_MESSAGE(35712, blk, "released by the block coming back, not by the bound");
  TEST_ASSERT_TRUE(t >= 700 && t < 700 + fry::kOtaSettlePollMs);
}

void test_a_slack_larger_than_the_block_does_not_wrap() {
  TEST_ASSERT_EQUAL_INT_MESSAGE(kProceed, static_cast<int>(fry::decideHeapSettle(0, 32, 64, 0, kMax)), "before < slack: want 0, not 2^32 - 32");
  TEST_ASSERT_EQUAL_INT(kProceed, static_cast<int>(fry::decideHeapSettle(0, 0, 0, 0, kMax)));
}

void test_the_constants() {
  TEST_ASSERT_TRUE_MESSAGE(kMax >= 1000 && kMax <= 10000, "a few seconds: far above the 60 ms the survivors took, far below a TIME_WAIT window");
  TEST_ASSERT_TRUE_MESSAGE(fry::kOtaSettlePollMs >= 10 && fry::kOtaSettlePollMs <= 100, "delay() granularity: lwIP runs in it");
  TEST_ASSERT_TRUE_MESSAGE(kSlack >= 8 && kSlack <= 256, "at least one umm block, well under the 328 B of survivors it must not let through");
}

// ---- checkNow() must measure before the session, downloadAndApply() must wait before it builds its clients -----------------------
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
  const std::string tail = "test/test_ota_settle/test_main.cpp";
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

// True when `pos` of `text` is inside an open `#if defined(ARDUINO_ARCH_ESP8266)` branch (not its #else): walk the preprocessor lines from
// the nearest such #if to `pos`.
bool inEsp8266Branch(const std::string& text, size_t pos) {
  const size_t guard = text.rfind("#if defined(ARDUINO_ARCH_ESP8266)", pos);
  if (guard == std::string::npos) return false;
  int depth = 1;
  std::istringstream lines(text.substr(guard + 1, pos - guard - 1));
  std::string line;
  std::getline(lines, line);  // the rest of the guard line
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

void test_checkNow_measures_the_block_after_the_plan_and_before_the_session() {
  std::string fn;
  TEST_ASSERT_TRUE_MESSAGE(checkNowBody(fn), "cannot find checkNow() in src/core/ota_client.cpp");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "s_blkAtCheckStart = fry::queryMaxFreeBlock();"), "one measurement");
  const size_t reserve = fn.find("plan.reserveEarly();");
  const size_t measure = fn.find("s_blkAtCheckStart = fry::queryMaxFreeBlock();");
  const size_t clients = fn.find("std::unique_ptr<ManifestClients> clients(new (std::nothrow) ManifestClients());");
  TEST_ASSERT_TRUE_MESSAGE(reserve != std::string::npos && measure != std::string::npos && clients != std::string::npos, "all three are in checkNow()");
  TEST_ASSERT_TRUE_MESSAGE(reserve < measure && measure < clients,
                           "after the plan's Strings are reserved (they sit below the session), before the session's clients exist");
  TEST_ASSERT_TRUE_MESSAGE(inEsp8266Branch(fn, measure), "in the ESP8266 branch: the ESP32 keeps its image");
}

void test_downloadAndApply_waits_before_it_builds_its_clients() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/core/ota_client.cpp", src), "cannot read src/core/ota_client.cpp");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "settleAfterManifest(s_blkAtCheckStart);"), "one wait in the file");
  const size_t fnA = src.find("FRY_OTA_ESP8266_NOINLINE bool downloadAndApply(const String& url, const String& shaExpect,");
  TEST_ASSERT_TRUE_MESSAGE(fnA != std::string::npos, "downloadAndApply() is there");
  const size_t wait = src.find("settleAfterManifest(s_blkAtCheckStart);", fnA);
  const size_t work = src.find("new (std::nothrow) DownloadWork()", fnA);
  TEST_ASSERT_TRUE_MESSAGE(wait != std::string::npos && work != std::string::npos, "the wait and the download's clients are both in downloadAndApply()");
  TEST_ASSERT_TRUE_MESSAGE(wait < work, "the wait comes first: the clients (and the BearSSL thunk with them) are built on the settled heap");
  const std::string between = src.substr(fnA, wait - fnA);
  TEST_ASSERT_TRUE_MESSAGE(between.find("new ") == std::string::npos && between.find("malloc") == std::string::npos &&
                               between.find("Serial.print") == std::string::npos,
                           "nothing allocates between the function's entry and the wait");
  TEST_ASSERT_TRUE_MESSAGE(inEsp8266Branch(src, wait), "the wait is in the ESP8266 branch, not in its #else");
  // and the release block that runs right before the call is the one test_ota_release pins: the wait must not be wedged into it
  std::string fn;
  TEST_ASSERT_TRUE_MESSAGE(checkNowBody(fn), "cannot find checkNow()");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(fn, "settleAfterManifest("), "checkNow() itself does not wait");
}

void test_the_wait_polls_with_delay_under_the_decision_and_its_bound() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/core/ota_client.cpp", src), "cannot read src/core/ota_client.cpp");
  TEST_ASSERT_TRUE_MESSAGE(src.find("#include \"ota_settle.h\"") != std::string::npos, "ota_client.cpp includes ota_settle.h");
  const size_t a = src.find("static void settleAfterManifest(uint32_t blkBefore) {");
  TEST_ASSERT_TRUE_MESSAGE(a != std::string::npos, "settleAfterManifest() is defined");
  const size_t b = src.find("\n}\n", a);
  TEST_ASSERT_TRUE_MESSAGE(b != std::string::npos, "...and ends");
  const std::string fn = src.substr(a, b - a);
  TEST_ASSERT_TRUE_MESSAGE(fn.find("fry::queryMaxFreeBlock()") != std::string::npos, "it looks at the largest free block");
  TEST_ASSERT_TRUE_MESSAGE(fn.find("fry::decideHeapSettle(") != std::string::npos, "through the tested decision");
  TEST_ASSERT_TRUE_MESSAGE(fn.find("fry::kOtaSettleSlackBytes") != std::string::npos && fn.find("fry::kOtaSettleMaxMs") != std::string::npos,
                           "with its slack and its bound");
  TEST_ASSERT_TRUE_MESSAGE(fn.find("delay(fry::kOtaSettlePollMs)") != std::string::npos, "and gives lwIP the time (delay runs its input and timers)");
  TEST_ASSERT_TRUE_MESSAGE(inEsp8266Branch(src, a), "ESP8266 only");
  const size_t dl = src.find("FRY_OTA_ESP8266_NOINLINE bool downloadAndApply(");
  TEST_ASSERT_TRUE_MESSAGE(dl != std::string::npos && a < dl, "defined before downloadAndApply()");
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_it_waits_while_the_largest_block_is_short_of_where_the_check_started);
  RUN_TEST(test_it_proceeds_once_the_block_is_back);
  RUN_TEST(test_the_wait_is_bounded_whatever_the_heap_looks_like);
  RUN_TEST(test_a_heap_that_never_recovers_cannot_starve_the_download);
  RUN_TEST(test_a_heap_that_recovers_inside_the_bound_is_released_by_recovering);
  RUN_TEST(test_a_slack_larger_than_the_block_does_not_wrap);
  RUN_TEST(test_the_constants);
  RUN_TEST(test_checkNow_measures_the_block_after_the_plan_and_before_the_session);
  RUN_TEST(test_downloadAndApply_waits_before_it_builds_its_clients);
  RUN_TEST(test_the_wait_polls_with_delay_under_the_decision_and_its_bound);
  return UNITY_END();
}
