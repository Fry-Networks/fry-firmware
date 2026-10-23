// A manifest check refused for lack of heap is asked again in 10 minutes, at most 6 times, then the 6 h cadence resumes.
//
// Before: tick() set s_lastCheckMs = now before every checkNow() and never touched it again, so any refusal (the boot check at
// ~8 s sees blk 29.1 K, lo/c1-p3-125815.lines.txt) waited OTA_CHECK_MS = 21 600 000 ms. A refusal opens no connection, so a
// retry is one free-heap sample; every other outcome keeps the long wait (a handshake costs 12.9 K of churn and a TIME_WAIT pcb).
#include <unity.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "ota_retry.h"

namespace {

constexpr uint32_t kSixHours = 21600000UL;  // include/config.h OTA_CHECK_MS

void test_a_refusal_is_retried_in_ten_minutes() {
  uint8_t retries = 0;
  TEST_ASSERT_EQUAL_UINT32(600000UL, fry::kOtaHeapRetryMs);
  TEST_ASSERT_EQUAL_UINT32(600000UL, fry::otaNextCheckDelayMs(true, retries, kSixHours));
  TEST_ASSERT_EQUAL_UINT8(1, retries);
}

void test_at_most_six_retries_then_the_normal_cadence() {
  uint8_t retries = 0;
  for (int i = 0; i < 6; i++) {
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(fry::kOtaHeapRetryMs, fry::otaNextCheckDelayMs(true, retries, kSixHours), "retry 1..6");
  }
  TEST_ASSERT_EQUAL_UINT8(6, retries);
  TEST_ASSERT_EQUAL_UINT8(6, fry::kOtaHeapRetryMax);
  for (int i = 0; i < 4; i++) {
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(kSixHours, fry::otaNextCheckDelayMs(true, retries, kSixHours), "7th refusal on: 6 h");
  }
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(6, retries, "an exhausted run does not count further");
}

void test_any_other_outcome_keeps_the_normal_cadence_and_resets_the_run() {
  uint8_t retries = 3;
  TEST_ASSERT_EQUAL_UINT32(kSixHours, fry::otaNextCheckDelayMs(false, retries, kSixHours));
  TEST_ASSERT_EQUAL_UINT8(0, retries);
  // ...so the next refusal starts a fresh run of six.
  TEST_ASSERT_EQUAL_UINT32(fry::kOtaHeapRetryMs, fry::otaNextCheckDelayMs(true, retries, kSixHours));
  TEST_ASSERT_EQUAL_UINT8(1, retries);
}

void test_the_retry_never_waits_longer_than_the_normal_cadence() {
  // The bench images run OTA_CHECK_MS = 45 s: a "retry" must not stretch that to 10 min.
  uint8_t retries = 0;
  TEST_ASSERT_EQUAL_UINT32(45000UL, fry::otaNextCheckDelayMs(true, retries, 45000UL));
  TEST_ASSERT_EQUAL_UINT32(45000UL, fry::otaNextCheckDelayMs(false, retries, 45000UL));
}

void test_a_whole_day_of_refusals_makes_at_most_six_extra_attempts() {
  // Six retries in the first hour, then one attempt per 6 h: 6 + (24 h - 1 h) / 6 h rounded up = 10 attempts in 24 h.
  uint8_t retries = 0;
  uint64_t t = 0;
  int attempts = 0;
  const uint64_t day = 24ULL * 3600ULL * 1000ULL;
  while (t < day) {
    attempts++;
    t += fry::otaNextCheckDelayMs(true, retries, kSixHours);
  }
  TEST_ASSERT_TRUE_MESSAGE(attempts <= 6 + 1 + 4, "bounded");
  TEST_ASSERT_TRUE_MESSAGE(attempts >= 7, "and not silently disabled");
}

// ---- call-site pins (source text; ota_client.cpp needs the Arduino core) --------------------------------------------------

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
  const std::string tail = "test/test_ota_retry/test_main.cpp";
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

void test_the_three_heap_refusals_mark_the_check_and_tick_applies_the_policy_on_esp8266_only() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/core/ota_client.cpp", src), "cannot read src/core/ota_client.cpp");
  TEST_ASSERT_EQUAL_INT_MESSAGE(3, countOf(src, "s_heapRefused = true;"),
                                "the manifest gate, the manifest begin() refusal and the download begin() refusal");
  TEST_ASSERT_EQUAL_INT_MESSAGE(
      1, countOf(src, "bool checkNow() {\n#if defined(ARDUINO_ARCH_ESP8266)\n  s_heapRefused = false;\n#endif"),
      "cleared at the top of every checkNow()");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "fry::otaNextCheckDelayMs(s_heapRefused, s_heapRetries, OTA_CHECK_MS)"),
                                "one place applies the policy");
  TEST_ASSERT_EQUAL_INT_MESSAGE(2, countOf(src, "afterCheck(now);"), "both tick() paths (first check and the 6 h one) use it");
  // The helper, its state and both uses sit inside ARDUINO_ARCH_ESP8266 guards: find the definition and require the guard
  // to open before it and close after it.
  const size_t def = src.find("void afterCheck(unsigned long now) {");
  TEST_ASSERT_TRUE_MESSAGE(def != std::string::npos, "afterCheck() defined");
  const size_t open = src.rfind("#if defined(ARDUINO_ARCH_ESP8266)", def);
  const size_t close = src.find("#endif", def);
  TEST_ASSERT_TRUE_MESSAGE(open != std::string::npos && close != std::string::npos && open < def && def < close,
                           "afterCheck() is ESP8266-only");
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_a_refusal_is_retried_in_ten_minutes);
  RUN_TEST(test_at_most_six_retries_then_the_normal_cadence);
  RUN_TEST(test_any_other_outcome_keeps_the_normal_cadence_and_resets_the_run);
  RUN_TEST(test_the_retry_never_waits_longer_than_the_normal_cadence);
  RUN_TEST(test_a_whole_day_of_refusals_makes_at_most_six_extra_attempts);
  RUN_TEST(test_the_three_heap_refusals_mark_the_check_and_tick_applies_the_policy_on_esp8266_only);
  return UNITY_END();
}
