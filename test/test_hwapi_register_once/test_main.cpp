// The boot-time registration is recorded, so tick() does not register a second time a second later (ESP8266).
//
// attemptWifiConnect() (src/main.cpp) registers through fry_trigger_register_now() as soon as Wi-Fi is up. tick() registers whenever
// s_lastRegisterAttemptMs is 0, and nothing recorded that first call, so the first tick registered AGAIN about a second later (bench
// lo/c1-p7d-170416.lines.txt: two "tls: low contiguous heap" lines before the first pre-check; the A2 heap map, c1/reports/heapmap-A2-decode.txt,
// shows each of them running an ~8 KB TLS session low in the heap and leaving small blocks above it). One session fewer at boot, and one
// TIME_WAIT pcb fewer.
//
// A success is recorded exactly as tick() records its own: the next attempt is due after the heartbeat (registerInstallation() sets
// s_nextRegisterDelayMs). A failure or a skipped call (no miner key yet) is NOT recorded, so tick() retries at once as it always did.
// The ESP32 family keeps calling registerInstallation() directly; its image is unchanged.
//
// hardwareapi_client.cpp needs the Arduino core, so these are source pins (same technique as test_hwapi_stack).
#include <unity.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

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
  const std::string tail = "test/test_hwapi_register_once/test_main.cpp";
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

// The text between `from` and the first `to` after it.
bool between(const std::string& src, const std::string& from, const std::string& to, std::string& out) {
  const size_t a = src.find(from);
  if (a == std::string::npos) return false;
  const size_t b = src.find(to, a + from.size());
  if (b == std::string::npos) return false;
  out = src.substr(a, b - a);
  return true;
}

bool hwapiSource(std::string& src) { return loadSource("src/core/hardwareapi_client.cpp", src); }

// True when `needle` is at `at` inside an `#if defined(ARDUINO_ARCH_ESP8266)` ... `#endif` that is not on the #else side.
bool onTheEsp8266Side(const std::string& src, size_t at) {
  const size_t guard = src.rfind("#if defined(ARDUINO_ARCH_ESP8266)", at);
  if (guard == std::string::npos) return false;
  const size_t other = src.find("#else", guard);
  const size_t end = src.find("#endif", guard);
  if (end == std::string::npos || end < at) return false;
  return other == std::string::npos || other > at || other > end;
}

void test_the_boot_trigger_goes_through_registerAtBoot_on_esp8266() {
  std::string src, fn;
  TEST_ASSERT_TRUE_MESSAGE(hwapiSource(src), "cannot read src/core/hardwareapi_client.cpp");
  TEST_ASSERT_TRUE_MESSAGE(between(src, "extern \"C\" void fry_trigger_register_now()", "extern \"C\" void fry_trigger_poc_now()", fn),
                           "cannot find fry_trigger_register_now()");
  const size_t viaBoot = fn.find("fry_hwapi::registerAtBoot();");
  const size_t direct = fn.find("fry_hwapi::registerInstallation();");
  TEST_ASSERT_TRUE_MESSAGE(viaBoot != std::string::npos, "the ESP8266 boot trigger calls registerAtBoot(), which records the attempt");
  TEST_ASSERT_TRUE_MESSAGE(direct != std::string::npos, "the ESP32 family still calls registerInstallation() directly");
  TEST_ASSERT_TRUE_MESSAGE(onTheEsp8266Side(fn, viaBoot), "registerAtBoot() is called under the ESP8266 guard");
  TEST_ASSERT_FALSE_MESSAGE(onTheEsp8266Side(fn, direct), "the direct call is the ESP32 side");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "registerInstallation()"), "no other registerInstallation() call in the trigger");
}

void test_registerAtBoot_records_a_success_only() {
  std::string src, fn;
  TEST_ASSERT_TRUE_MESSAGE(hwapiSource(src), "cannot read src/core/hardwareapi_client.cpp");
  TEST_ASSERT_TRUE_MESSAGE(between(src, "bool registerAtBoot() {", "\n}\n", fn), "cannot find registerAtBoot()");
  const size_t call = fn.find("registerInstallation()");
  const size_t record = fn.find("s_lastRegisterAttemptMs =");
  const size_t flag = fn.find("s_registered = true;");
  TEST_ASSERT_TRUE_MESSAGE(call != std::string::npos && record != std::string::npos && flag != std::string::npos,
                           "calls registerInstallation(), records the attempt time, sets s_registered");
  TEST_ASSERT_TRUE_MESSAGE(fn.find("return false;") < record && fn.find("return false;") > call,
                           "a failed or skipped registration returns before anything is recorded");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "s_lastRegisterAttemptMs ="), "recorded once");
  TEST_ASSERT_TRUE_MESSAGE(fn.find("started ? started : 1") != std::string::npos,
                           "never 0: tick() treats 0 as 'no attempt yet'");
}

void test_registerAtBoot_exists_on_the_esp8266_only() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(hwapiSource(src), "cannot read src/core/hardwareapi_client.cpp");
  const size_t at = src.find("bool registerAtBoot() {");
  TEST_ASSERT_TRUE_MESSAGE(at != std::string::npos, "registerAtBoot() is defined");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "bool registerAtBoot() {"), "once");
  TEST_ASSERT_TRUE_MESSAGE(onTheEsp8266Side(src, at), "inside an ARDUINO_ARCH_ESP8266 guard, so the ESP32 images do not change");
}

void test_tick_keeps_its_own_rule_for_the_first_attempt() {
  std::string src, fn;
  TEST_ASSERT_TRUE_MESSAGE(hwapiSource(src), "cannot read src/core/hardwareapi_client.cpp");
  TEST_ASSERT_TRUE_MESSAGE(between(src, "void tick() {", "}  // namespace fry_hwapi", fn), "cannot find tick()");
  TEST_ASSERT_TRUE_MESSAGE(fn.find("(s_lastRegisterAttemptMs == 0) || (now - s_lastRegisterAttemptMs) >= s_nextRegisterDelayMs") !=
                               std::string::npos,
                           "tick() still registers when nothing was recorded (a failed boot registration is retried at once)");
  TEST_ASSERT_TRUE_MESSAGE(fn.find("s_lastRegisterAttemptMs = now;") != std::string::npos, "and still records its own attempts");
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_boot_trigger_goes_through_registerAtBoot_on_esp8266);
  RUN_TEST(test_registerAtBoot_records_a_success_only);
  RUN_TEST(test_registerAtBoot_exists_on_the_esp8266_only);
  RUN_TEST(test_tick_keeps_its_own_rule_for_the_first_attempt);
  return UNITY_END();
}
