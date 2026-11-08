// ESP8266 registration: release the connection at once, and treat "clock not set yet" as a deferral.
//
// The registration and the stale-token heal ask for "Connection: close" (HTTPClient::setReuse(false)) so the server closes
// first, and wait a bounded time for that close before closing the board's side (lib/fry_core/reg_release.h). A registration
// the TLS layer refuses because SNTP has not set the clock is a deferral: no failure count, no backoff, bounded.
// hardwareapi_client.cpp needs the Arduino core, so the wiring tests are source pins (same technique as test_hwapi_register_once).
#include <unity.h>

#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "reg_release.h"

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
  const std::string tail = "test/test_reg_release/test_main.cpp";
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

// Drops // comments, so a comment cannot satisfy a pin.
std::string stripLineComments(const std::string& s) {
  std::string out;
  size_t i = 0;
  while (i < s.size()) {
    if (s.compare(i, 2, "//") == 0) {
      while (i < s.size() && s[i] != '\n') i++;
    } else {
      out += s[i++];
    }
  }
  return out;
}

bool between(const std::string& src, const std::string& from, const std::string& to, std::string& out) {
  const size_t a = src.find(from);
  if (a == std::string::npos) return false;
  const size_t b = src.find(to, a + from.size());
  if (b == std::string::npos) return false;
  out = src.substr(a, b - a);
  return true;
}

std::string squeeze(const std::string& s) {
  std::string out;
  for (size_t i = 0; i < s.size(); i++) {
    if (s[i] != ' ' && s[i] != '\n' && s[i] != '\t' && s[i] != '\r') out += s[i];
  }
  return out;
}

int countOf(const std::string& hay, const std::string& needle) {
  int n = 0;
  for (size_t pos = hay.find(needle); pos != std::string::npos; pos = hay.find(needle, pos + needle.size())) n++;
  return n;
}

// True when `at` is inside an `#if defined(ARDUINO_ARCH_ESP8266)` ... `#endif` and not on its #else side.
bool onTheEsp8266Side(const std::string& src, size_t at) {
  const size_t guard = src.rfind("#if defined(ARDUINO_ARCH_ESP8266)", at);
  if (guard == std::string::npos) return false;
  const size_t other = src.find("#else", guard);
  const size_t end = src.find("#endif", guard);
  if (end == std::string::npos || end < at) return false;
  return other == std::string::npos || other > at || other > end;
}

bool hwapiFunctions(std::string& regFn, std::string& healFn) {
  std::string src;
  if (!loadSource("src/core/hardwareapi_client.cpp", src)) return false;
  src = stripLineComments(src);
  return between(src, "bool registerInstallation() {", "bool renewLease() {", regFn) &&
         between(src, "bool healStaleTokenIfDue(", "bool registerInstallation() {", healFn);
}

// Every http.end() in `fn` is directly preceded by the bounded wait for the peer's close, inside an ESP8266 guard.
void expectWaitBeforeEveryEnd(const std::string& fn, int expectedEnds, const char* what) {
  int ends = 0;
  for (size_t pos = fn.find("http.end();"); pos != std::string::npos; pos = fn.find("http.end();", pos + 1)) {
    ends++;
    const std::string before = squeeze(fn.substr(pos > 80 ? pos - 80 : 0, pos > 80 ? 80 : pos));
    const std::string want = "waitRegPeerClose(sec);#endif";
    TEST_ASSERT_TRUE_MESSAGE(before.size() >= want.size() && before.compare(before.size() - want.size(), want.size(), want) == 0,
                             what);
  }
  TEST_ASSERT_EQUAL_INT_MESSAGE(expectedEnds, ends, what);
}

void test_registration_asks_for_connection_close_on_esp8266() {
  std::string regFn, healFn;
  TEST_ASSERT_TRUE_MESSAGE(hwapiFunctions(regFn, healFn), "cannot find registerInstallation() / healStaleTokenIfDue()");
  const size_t at = regFn.find("http.setReuse(false);");
  TEST_ASSERT_TRUE_MESSAGE(at != std::string::npos, "the registration HTTPClient must call setReuse(false) (Connection: close)");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(regFn, "http.setReuse(false);"), "once");
  TEST_ASSERT_TRUE_MESSAGE(onTheEsp8266Side(regFn, at), "inside an ARDUINO_ARCH_ESP8266 guard, so the ESP32 images do not change");
  TEST_ASSERT_TRUE_MESSAGE(at < regFn.find("http.POST(body)"), "set before the request is sent");
}

void test_registration_waits_for_the_peer_close_before_ending() {
  std::string regFn, healFn;
  TEST_ASSERT_TRUE_MESSAGE(hwapiFunctions(regFn, healFn), "cannot find registerInstallation() / healStaleTokenIfDue()");
  // success, 4xx (server's answer) and the quick-retry path
  expectWaitBeforeEveryEnd(regFn, 3, "registerInstallation(): every http.end() follows waitRegPeerClose(sec) inside an ESP8266 guard");
}

void test_heal_waits_for_the_peer_close_before_ending() {
  std::string regFn, healFn;
  TEST_ASSERT_TRUE_MESSAGE(hwapiFunctions(regFn, healFn), "cannot find registerInstallation() / healStaleTokenIfDue()");
  expectWaitBeforeEveryEnd(healFn, 1, "healStaleTokenIfDue(): http.end() follows waitRegPeerClose(sec) inside an ESP8266 guard");
}

void test_the_wait_is_bounded_by_the_shared_helper() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/core/hardwareapi_client.cpp", src), "cannot read hardwareapi_client.cpp");
  std::string fn;
  TEST_ASSERT_TRUE_MESSAGE(between(src, "void waitRegPeerClose(WiFiClientSecure& sec) {", "}\nbool s_regClockDeferring", fn),
                           "waitRegPeerClose() is defined");
  TEST_ASSERT_TRUE_MESSAGE(fn.find("fry::regPeerCloseKeepWaiting(sec.connected(), millis() - started)") != std::string::npos,
                           "loop condition is the bounded helper");
  TEST_ASSERT_TRUE_MESSAGE(fn.find("delay(fry::kRegPeerClosePollMs)") != std::string::npos, "and it yields while it waits");
}

void test_clock_refusal_defers_before_any_failure_bookkeeping() {
  std::string regFn, healFn;
  TEST_ASSERT_TRUE_MESSAGE(hwapiFunctions(regFn, healFn), "cannot find registerInstallation() / healStaleTokenIfDue()");
  const size_t act = regFn.find("fry::regClockAction(");
  TEST_ASSERT_TRUE_MESSAGE(act != std::string::npos, "registerInstallation() consults regClockAction()");
  TEST_ASSERT_TRUE_MESSAGE(onTheEsp8266Side(regFn, act), "ESP8266 only");
  const size_t noted = regFn.find("s_lastRegHttp = code;");
  const size_t failures = regFn.find("s_regFailures++");
  TEST_ASSERT_TRUE_MESSAGE(noted != std::string::npos && failures != std::string::npos, "failure bookkeeping present");
  TEST_ASSERT_TRUE_MESSAGE(act < noted && act < failures, "the deferral decision comes before any failure bookkeeping");
  const std::string tail = regFn.substr(act, noted - act);
  TEST_ASSERT_TRUE_MESSAGE(tail.find("s_nextRegisterDelayMs = fry::kRegClockRecheckMs;") != std::string::npos,
                           "a deferral re-checks after kRegClockRecheckMs");
  TEST_ASSERT_TRUE_MESSAGE(tail.find("return false;") != std::string::npos, "and returns without recording a failure");
  TEST_ASSERT_TRUE_MESSAGE(tail.find("s_regFailures") == std::string::npos, "and never touches the failure count");
}

void test_peer_close_wait_is_bounded() {
  TEST_ASSERT_TRUE(fry::regPeerCloseKeepWaiting(true, 0));
  TEST_ASSERT_TRUE(fry::regPeerCloseKeepWaiting(true, fry::kRegPeerCloseWaitMs - 1));
  TEST_ASSERT_FALSE(fry::regPeerCloseKeepWaiting(true, fry::kRegPeerCloseWaitMs));
  TEST_ASSERT_FALSE(fry::regPeerCloseKeepWaiting(false, 0));  // the peer already closed
  TEST_ASSERT_EQUAL_UINT32(1500, fry::kRegPeerCloseWaitMs);
}

void test_clock_not_set_defers_then_gives_up_after_the_bound() {
  using fry::RegClockAction;
  TEST_ASSERT_TRUE(fry::regClockAction(true, false, 0) == RegClockAction::Proceed);
  TEST_ASSERT_TRUE(fry::regClockAction(true, true, 999999) == RegClockAction::Proceed);  // clock set: always proceed
  TEST_ASSERT_TRUE(fry::regClockAction(false, false, 0) == RegClockAction::Defer);       // first refusal defers
  TEST_ASSERT_TRUE(fry::regClockAction(false, true, 0) == RegClockAction::Defer);
  TEST_ASSERT_TRUE(fry::regClockAction(false, true, fry::kRegClockDeferMaxMs - 1) == RegClockAction::Defer);
  TEST_ASSERT_TRUE(fry::regClockAction(false, true, fry::kRegClockDeferMaxMs) == RegClockAction::Proceed);  // bounded
  TEST_ASSERT_EQUAL_UINT32(2000, fry::kRegClockRecheckMs);
  TEST_ASSERT_EQUAL_UINT32(60000, fry::kRegClockDeferMaxMs);
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_registration_asks_for_connection_close_on_esp8266);
  RUN_TEST(test_registration_waits_for_the_peer_close_before_ending);
  RUN_TEST(test_heal_waits_for_the_peer_close_before_ending);
  RUN_TEST(test_the_wait_is_bounded_by_the_shared_helper);
  RUN_TEST(test_clock_refusal_defers_before_any_failure_bookkeeping);
  RUN_TEST(test_peer_close_wait_is_bounded);
  RUN_TEST(test_clock_not_set_defers_then_gives_up_after_the_bound);
  return UNITY_END();
}
