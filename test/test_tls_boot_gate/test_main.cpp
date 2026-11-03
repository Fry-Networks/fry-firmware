// fry::tlsBootWaitMs (lib/fry_core/tls_boot_gate.*): no TLS session starts while the boot's asynchronous 504 B heap
// allocation (7770..7779 ms after the Wi-Fi connect, lib/fry_core/ota_first_check.h) can still land inside it. A session
// that straddles it leaves that block in the middle of the free region and every later OTA manifest check is refused.
// The wiring tests are source pins: the callers need the Arduino core (same technique as test_hwapi_register_once).
#include <unity.h>

#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "ota_first_check.h"
#include "tls_boot_gate.h"

namespace {

bool loadSource(const std::string& rel, std::string& out) {
  const std::string self = __FILE__;
  const std::string tail = "test/test_tls_boot_gate/test_main.cpp";
  std::vector<std::string> prefixes;
  if (self.size() >= tail.size() && self.compare(self.size() - tail.size(), tail.size(), tail) == 0) {
    prefixes.push_back(self.substr(0, self.size() - tail.size()));
  }
  const char* ups[] = {"", "../", "../../", "../../../", "../../../../"};
  for (size_t i = 0; i < sizeof(ups) / sizeof(ups[0]); i++) prefixes.push_back(ups[i]);
  for (size_t i = 0; i < prefixes.size(); i++) {
    std::ifstream f((prefixes[i] + rel).c_str(), std::ios::in | std::ios::binary);
    if (!f) continue;
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    if (!out.empty()) return true;
  }
  return false;
}

// Text from the first occurrence of `from` up to (not including) the next `to` after it.
std::string slice(const std::string& s, const char* from, const char* to) {
  const size_t a = s.find(from);
  TEST_ASSERT_TRUE_MESSAGE(a != std::string::npos, from);
  const size_t b = s.find(to, a + 1);
  TEST_ASSERT_TRUE_MESSAGE(b != std::string::npos, to);
  return s.substr(a, b - a);
}

bool has(const std::string& s, const char* needle) { return s.find(needle) != std::string::npos; }

void test_the_gate_stays_closed_until_the_documented_event_has_passed() {
  TEST_ASSERT_EQUAL_UINT32(fry::kBootAsyncEventDoneMs, fry::tlsBootWaitMs(1000, 1000));
  TEST_ASSERT_EQUAL_UINT32(fry::kBootAsyncEventDoneMs - 7779, fry::tlsBootWaitMs(1000 + 7779, 1000));
  TEST_ASSERT_TRUE_MESSAGE(fry::tlsBootWaitMs(1000 + 7779, 1000) > 0, "still closed at the last measured landing time");
}

void test_the_gate_opens_exactly_at_the_end_of_the_window() {
  TEST_ASSERT_EQUAL_UINT32(1, fry::tlsBootWaitMs(1000 + fry::kBootAsyncEventDoneMs - 1, 1000));
  TEST_ASSERT_EQUAL_UINT32(0, fry::tlsBootWaitMs(1000 + fry::kBootAsyncEventDoneMs, 1000));
  TEST_ASSERT_EQUAL_UINT32(0, fry::tlsBootWaitMs(1000 + 600000, 1000));
}

void test_the_window_is_wrap_safe_on_the_32_bit_millisecond_counter() {
  const uint32_t first = 0xFFFFFF00u;
  TEST_ASSERT_EQUAL_UINT32(fry::kBootAsyncEventDoneMs - 512, fry::tlsBootWaitMs(first + 512u, first));
  TEST_ASSERT_EQUAL_UINT32(0, fry::tlsBootWaitMs(first + fry::kBootAsyncEventDoneMs, first));
}

void test_the_window_covers_the_measured_event_with_margin_and_is_not_longer_than_the_ota_wait() {
  TEST_ASSERT_TRUE_MESSAGE(fry::kBootAsyncEventDoneMs >= 7779 + 1000, "the measured 7.78 s plus at least 1 s");
  TEST_ASSERT_TRUE_MESSAGE(fry::kBootAsyncEventDoneMs <= fry::kOtaFirstCheckAfterFirstTickMs,
                           "never later than the first OTA check's own wait after the first tick");
}

// Registration: the gate is the first thing the function does on ESP8266 (before any allocation or client), and a closed gate
// is a deferral: it returns false without any failure bookkeeping.
void test_registration_defers_before_allocating_and_records_no_failure() {
  std::string src;
  TEST_ASSERT_TRUE(loadSource("src/core/hardwareapi_client.cpp", src));
  const std::string fn = slice(src, "bool registerInstallation() {", "int lastRegisterHttp()");
  const size_t gate = fn.find("fry_http::tlsStartDelayMs()");
  TEST_ASSERT_TRUE_MESSAGE(gate != std::string::npos, "registerInstallation asks the boot gate");
  TEST_ASSERT_TRUE_MESSAGE(gate < fn.find("new (std::nothrow) RegText()"), "gate precedes the first allocation");
  TEST_ASSERT_TRUE_MESSAGE(gate < fn.find("WiFiClientSecure"), "gate precedes every client");
  const std::string hunk = slice(fn, "fry_http::tlsStartDelayMs()", "std::unique_ptr<RegText>");
  TEST_ASSERT_TRUE(has(hunk, "s_nextRegisterDelayMs = gateMs"));
  TEST_ASSERT_TRUE(has(hunk, "return false;"));
  TEST_ASSERT_FALSE_MESSAGE(has(hunk, "s_regFailures"), "no failure count");
  TEST_ASSERT_FALSE_MESSAGE(has(hunk, "nextRegisterDelayMs("), "no backoff growth");
  TEST_ASSERT_FALSE_MESSAGE(has(hunk, "notifyApiFail"), "no provisioning error");
  TEST_ASSERT_FALSE_MESSAGE(has(hunk, "healStaleTokenIfDue"), "no heal trigger");
  TEST_ASSERT_FALSE_MESSAGE(has(hunk, "noteHeartbeat"), "no heartbeat note");
  // The gate call sits between an ESP8266 #if and its #endif: nothing but the gate block lies between them.
  const size_t ifPos = fn.rfind("#if defined(ARDUINO_ARCH_ESP8266)", gate);
  TEST_ASSERT_TRUE_MESSAGE(ifPos != std::string::npos, "an ESP8266 guard opens before the gate");
  TEST_ASSERT_TRUE_MESSAGE(fn.find("#endif", ifPos) > gate, "no #endif between the guard and the gate");
  TEST_ASSERT_TRUE_MESSAGE(fn.find("#if", ifPos + 1) > gate, "no nested #if between the guard and the gate");
}

// The quick retry and the heal path sit inside registerInstallation() below the gate, so they only start after it opened.
void test_retry_and_heal_sessions_are_reached_only_past_the_registration_gate() {
  std::string src;
  TEST_ASSERT_TRUE(loadSource("src/core/hardwareapi_client.cpp", src));
  const std::string fn = slice(src, "bool registerInstallation() {", "int lastRegisterHttp()");
  const size_t gate = fn.find("fry_http::tlsStartDelayMs()");
  TEST_ASSERT_TRUE(gate < fn.find("for (int attempt = 0; attempt < 2; attempt++)"));
  TEST_ASSERT_TRUE(gate < fn.find("healStaleTokenIfDue(http, sec"));
}

// PoC and lease: the report stays due (the timer is not advanced) while the gate is closed; direct callers get a plain
// "not sent" before any client exists.
void test_poc_and_lease_defer_without_advancing_the_timer() {
  std::string src;
  TEST_ASSERT_TRUE(loadSource("src/core/hardwareapi_client.cpp", src));
  const std::string tick = slice(src, "void tick() {", "bool registerAtBoot()");
  const size_t gate = tick.find("fry_http::tlsStartDelayMs() != 0) return;", tick.find("POC_INTERVAL_MS"));
  TEST_ASSERT_TRUE_MESSAGE(gate != std::string::npos, "tick() gates the PoC block");
  TEST_ASSERT_TRUE_MESSAGE(gate < tick.find("s_lastPocMs = now;"), "timer advanced only after the gate");
  const std::string poc = slice(src, "int putPoc() {", "WiFiClientSecure sec;");
  TEST_ASSERT_TRUE(has(poc, "tlsStartDelayMs() != 0) return -1;"));
  const std::string lease = slice(src, "bool renewLease() {", "WiFiClientSecure sec;");
  TEST_ASSERT_TRUE(has(lease, "tlsStartDelayMs() != 0) return false;"));
  const std::string ver = slice(src, "bool getVersions(String& outJson) {", "WiFiClientSecure sec;");
  TEST_ASSERT_TRUE(has(ver, "tlsStartDelayMs() != 0) return false;"));
}

// Telemetry: the gate comes before the interval timer is touched, so a deferred sample is still due on the next pass.
void test_telemetry_defers_without_advancing_its_interval_timer() {
  std::string src;
  TEST_ASSERT_TRUE(loadSource("src/core/telemetry.cpp", src));
  const std::string tick = slice(src, "void tick() {", "WiFiClientSecure sec;");
  const size_t gate = tick.find("fry_http::tlsStartDelayMs() != 0) return;");
  TEST_ASSERT_TRUE_MESSAGE(gate != std::string::npos, "telemetry asks the boot gate");
  TEST_ASSERT_TRUE_MESSAGE(gate < tick.find("s_lastMs = now;"), "interval timer untouched while deferred");
  TEST_ASSERT_TRUE_MESSAGE(gate < tick.find("waitForHeapGate"), "before any heap work");
}

// OTA: the first check additionally waits for the gate; the hold decision that follows is unchanged.
void test_ota_first_check_waits_for_the_gate_before_the_hold_decision() {
  std::string src;
  TEST_ASSERT_TRUE(loadSource("src/core/ota_client.cpp", src));
  const size_t wait = src.find("otaFirstCheckWaitMs(static_cast<uint32_t>(now)");
  const size_t gate = src.find("fry_http::tlsStartDelayMs() != 0) return;", wait);
  const size_t hold = src.find("if (holdForTimeWait(now)) return;", wait);
  TEST_ASSERT_TRUE(wait != std::string::npos && gate != std::string::npos && hold != std::string::npos);
  TEST_ASSERT_TRUE(wait < gate);
  TEST_ASSERT_TRUE_MESSAGE(gate < hold, "gate only delays the start of the first check");
}

// The out-of-schedule entry (the serial command) is gated before it calls checkNow(), ESP8266 only, and touches no state. checkNow()'s
// own prologue is pinned by other tests, and its only other caller, tick(), is gated.
void test_manual_ota_check_is_deferred_by_the_gate_before_any_state_change() {
  std::string src;
  TEST_ASSERT_TRUE(loadSource("src/core/ota_client.cpp", src));
  const std::string fn = src.substr(src.find("extern \"C\" void fry_trigger_ota_now() {"));
  const size_t gate = fn.find("fry_http::tlsStartDelayMs() != 0) {");
  TEST_ASSERT_TRUE_MESSAGE(gate != std::string::npos, "the manual OTA check asks the boot gate");
  TEST_ASSERT_TRUE_MESSAGE(gate < fn.find("fry_ota::checkNow();"), "before the check starts");
  const size_t ifPos = fn.rfind("#if defined(ARDUINO_ARCH_ESP8266)", gate);
  TEST_ASSERT_TRUE_MESSAGE(ifPos != std::string::npos && fn.find("#endif", ifPos) > gate, "inside the ESP8266 guard");
  TEST_ASSERT_TRUE_MESSAGE(fn.find("#endif", gate) < fn.find("fry_ota::checkNow();"), "the guard closes before the call");
  const std::string hunk = slice(fn, "fry_http::tlsStartDelayMs() != 0) {", "#endif");
  TEST_ASSERT_TRUE(has(hunk, "deferred until the boot window ends"));
  TEST_ASSERT_TRUE(has(hunk, "return;"));
  TEST_ASSERT_FALSE_MESSAGE(has(hunk, "s_"), "no retry, strike or flag state touched");
  const std::string tick = slice(src, "void tick() {", "extern \"C\" void fry_trigger_ota_now()");
  TEST_ASSERT_TRUE_MESSAGE(has(tick, "fry_http::tlsStartDelayMs() != 0) return;"), "scheduled first check stays gated");
}

// ESP8266 only: the gate is declared and defined only there, and its definition latches the first call.
void test_gate_is_esp8266_only_and_latches_the_first_call() {
  std::string h;
  TEST_ASSERT_TRUE(loadSource("src/core/http_tls.h", h));
  const size_t decl = h.find("uint32_t tlsStartDelayMs();");
  TEST_ASSERT_TRUE(decl != std::string::npos);
  TEST_ASSERT_TRUE_MESSAGE(h.rfind("#if defined(ARDUINO_ARCH_ESP8266)", decl) > h.rfind("#endif", decl) ||
                               h.rfind("#endif", decl) == std::string::npos,
                           "declaration sits inside the ESP8266 block");
  std::string c;
  TEST_ASSERT_TRUE(loadSource("src/esp8266/http_tls.cpp", c));
  const std::string def = slice(c, "uint32_t tlsStartDelayMs() {", "bool beginHttpsUrl(HTTPClient& http, WiFiClientSecure& sec, const String& url, bool mflnProbeWorthwhile) {");
  TEST_ASSERT_TRUE(has(def, "if (!started)"));
  TEST_ASSERT_TRUE(has(def, "fry::tlsBootWaitMs(nowMs, firstMs)"));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_gate_stays_closed_until_the_documented_event_has_passed);
  RUN_TEST(test_the_gate_opens_exactly_at_the_end_of_the_window);
  RUN_TEST(test_the_window_is_wrap_safe_on_the_32_bit_millisecond_counter);
  RUN_TEST(test_the_window_covers_the_measured_event_with_margin_and_is_not_longer_than_the_ota_wait);
  RUN_TEST(test_registration_defers_before_allocating_and_records_no_failure);
  RUN_TEST(test_retry_and_heal_sessions_are_reached_only_past_the_registration_gate);
  RUN_TEST(test_poc_and_lease_defer_without_advancing_the_timer);
  RUN_TEST(test_telemetry_defers_without_advancing_its_interval_timer);
  RUN_TEST(test_ota_first_check_waits_for_the_gate_before_the_hold_decision);
  RUN_TEST(test_manual_ota_check_is_deferred_by_the_gate_before_any_state_change);
  RUN_TEST(test_gate_is_esp8266_only_and_latches_the_first_call);
  return UNITY_END();
}
