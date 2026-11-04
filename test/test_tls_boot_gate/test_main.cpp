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

// ESP8266 only: the gate is declared and defined only there, and its definition is keyed off the Wi-Fi connect.
void test_gate_is_esp8266_only_and_is_keyed_off_the_connect() {
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
  TEST_ASSERT_TRUE(has(def, "fry_wifi::connectAnchorMs("));
  TEST_ASSERT_TRUE(has(def, "fry::tlsConnectWaitMs("));
  TEST_ASSERT_FALSE_MESSAGE(has(def, "started"), "no first-call latch");
  TEST_ASSERT_FALSE_MESSAGE(has(def, "firstMs"), "no first-call stamp");
}

// Connect-keyed window, pure part.
uint32_t waitAt(uint32_t now, uint32_t detect, bool haveDetect, uint32_t assoc, bool haveAssoc) {
  uint32_t anchor = 0;
  const bool have = fry::connectAnchorMs(detect, haveDetect, assoc, haveAssoc, &anchor);
  return fry::tlsConnectWaitMs(now, anchor, have);
}

void test_no_connect_keeps_the_gate_closed_for_the_full_window_at_any_time() {
  const uint32_t times[] = {0, 5000, 9000, 21000, 600000, 0xFFFFFFFFu};
  for (size_t i = 0; i < sizeof(times) / sizeof(times[0]); i++) {
    TEST_ASSERT_EQUAL_UINT32(fry::kBootAsyncEventDoneMs, fry::tlsConnectWaitMs(times[i], 0, false));
    TEST_ASSERT_EQUAL_UINT32(fry::kBootAsyncEventDoneMs, waitAt(times[i], 0, false, 0, false));
  }
}

void test_a_late_connect_moves_the_window_with_it() {
  // A boot-keyed gate would open at 9000.
  TEST_ASSERT_EQUAL_UINT32(fry::kBootAsyncEventDoneMs, waitAt(12000, 12000, true, 0, false));
  TEST_ASSERT_EQUAL_UINT32(fry::kBootAsyncEventDoneMs, waitAt(9000, 0, false, 0, false));  // no connect yet: full window
  TEST_ASSERT_EQUAL_UINT32(fry::kBootAsyncEventDoneMs + 2500, waitAt(40000, 0, false, 40000, true));
  TEST_ASSERT_TRUE(waitAt(12000, 12000, true, 0, false) > 0);
  TEST_ASSERT_TRUE(waitAt(20999, 12000, true, 0, false) > 0);
  TEST_ASSERT_EQUAL_UINT32(1, waitAt(20999, 12000, true, 0, false));
  TEST_ASSERT_EQUAL_UINT32(0, waitAt(21000, 12000, true, 0, false));
  TEST_ASSERT_EQUAL_UINT32(0, fry::tlsConnectWaitMs(21000, 12000, true));
  TEST_ASSERT_TRUE(fry::tlsConnectWaitMs(20999, 12000, true) > 0);
}

void test_the_association_anchor_dominates_when_the_address_comes_fast() {
  uint32_t a = 0;
  TEST_ASSERT_TRUE(fry::connectAnchorMs(4500, true, 4000, true, &a));
  TEST_ASSERT_EQUAL_UINT32(6500, a);
  TEST_ASSERT_TRUE(waitAt(15499, 4500, true, 4000, true) > 0);
  TEST_ASSERT_EQUAL_UINT32(0, waitAt(15500, 4500, true, 4000, true));
}

void test_the_address_anchor_dominates_when_dhcp_is_slow() {
  uint32_t a = 0;
  TEST_ASSERT_TRUE(fry::connectAnchorMs(10600, true, 4000, true, &a));
  TEST_ASSERT_EQUAL_UINT32(10600, a);
  TEST_ASSERT_EQUAL_UINT32(0, waitAt(10600 + fry::kBootAsyncEventDoneMs, 10600, true, 4000, true));
  TEST_ASSERT_TRUE(waitAt(10600 + fry::kBootAsyncEventDoneMs - 1, 10600, true, 4000, true) > 0);
}

// Only one stamp known: never a permanent close while the link is up.
void test_only_the_association_known_uses_the_association_anchor() {
  uint32_t a = 0;
  TEST_ASSERT_TRUE(fry::connectAnchorMs(0, false, 30000, true, &a));
  TEST_ASSERT_EQUAL_UINT32(30000 + fry::kAssocToDetectLeadMs, a);
  TEST_ASSERT_TRUE(waitAt(30000 + fry::kAssocToDetectLeadMs + fry::kBootAsyncEventDoneMs - 1, 0, false, 30000, true) > 0);
  TEST_ASSERT_EQUAL_UINT32(0, waitAt(30000 + fry::kAssocToDetectLeadMs + fry::kBootAsyncEventDoneMs, 0, false, 30000, true));
}

void test_only_the_address_known_uses_the_address_anchor() {
  uint32_t a = 0;
  TEST_ASSERT_TRUE(fry::connectAnchorMs(8000, true, 0, false, &a));
  TEST_ASSERT_EQUAL_UINT32(8000, a);
  TEST_ASSERT_EQUAL_UINT32(0, waitAt(8000 + fry::kBootAsyncEventDoneMs, 8000, true, 0, false));
}

void test_neither_stamp_known_reports_no_connect() {
  uint32_t a = 77;
  TEST_ASSERT_FALSE(fry::connectAnchorMs(5, false, 6, false, &a));
  TEST_ASSERT_EQUAL_UINT32(77, a);
}

void test_every_link_up_re_arms_the_gate() {
  // First link up at 6500 (detect), open at 15500; a second association at 40000 with no detect seen yet closes it again.
  TEST_ASSERT_EQUAL_UINT32(0, waitAt(40000, 6500, true, 4000, true));
  TEST_ASSERT_TRUE(waitAt(40000, 0, false, 40000, true) > 0);
  TEST_ASSERT_TRUE(waitAt(40000 + fry::kAssocToDetectLeadMs + fry::kBootAsyncEventDoneMs - 1, 0, false, 40000, true) > 0);
  TEST_ASSERT_EQUAL_UINT32(0, waitAt(40000 + fry::kAssocToDetectLeadMs + fry::kBootAsyncEventDoneMs, 0, false, 40000, true));
  // And the detect that follows moves the anchor later again.
  TEST_ASSERT_TRUE(waitAt(52500, 50000, true, 40000, true) > 0);
}

void test_the_connect_window_is_wrap_safe() {
  const uint32_t assoc = 0xFFFFFC00u;                       // 1024 ms before the wrap
  const uint32_t detect = assoc + 3000u;                    // wrapped, later than assoc + 2500
  uint32_t a = 0;
  TEST_ASSERT_TRUE(fry::connectAnchorMs(detect, true, assoc, true, &a));
  TEST_ASSERT_EQUAL_UINT32(detect, a);
  TEST_ASSERT_TRUE(fry::connectAnchorMs(assoc + 1000u, true, assoc, true, &a));
  TEST_ASSERT_EQUAL_UINT32(assoc + 2500u, a);
  TEST_ASSERT_TRUE(waitAt(detect + fry::kBootAsyncEventDoneMs - 1, detect, true, assoc, true) > 0);
  TEST_ASSERT_EQUAL_UINT32(0, waitAt(detect + fry::kBootAsyncEventDoneMs, detect, true, assoc, true));
}

// An anchor that is more than half the counter range old must read as long past, not as lying ahead of now.
void test_a_long_uptime_never_re_closes_the_gate() {
  const uint32_t anchor = 1000u;
  const uint32_t xs[] = {0u, 1u, 1000u, 100000u, 2000000000u};
  for (size_t i = 0; i < sizeof(xs) / sizeof(xs[0]); i++) {
    const uint32_t now = anchor + 0x80000000u + xs[i];
    TEST_ASSERT_EQUAL_UINT32(0, fry::tlsConnectWaitMs(now, anchor, true));
  }
  // A recent anchor just before the counter wraps: closed inside the window, open at its end.
  const uint32_t near = 0xFFFFF000u;
  TEST_ASSERT_TRUE(fry::tlsConnectWaitMs(near + 100u, near, true) > 0);
  TEST_ASSERT_EQUAL_UINT32(1, fry::tlsConnectWaitMs(near + fry::kBootAsyncEventDoneMs - 1u, near, true));
  TEST_ASSERT_EQUAL_UINT32(0, fry::tlsConnectWaitMs(near + fry::kBootAsyncEventDoneMs, near, true));
}

// The only legitimate anchor in the future is association + lead.
void test_an_anchor_ahead_is_honoured_only_up_to_the_association_lead() {
  TEST_ASSERT_EQUAL_UINT32(fry::kAssocToDetectLeadMs + fry::kBootAsyncEventDoneMs,
                           fry::tlsConnectWaitMs(5000u, 5000u + fry::kAssocToDetectLeadMs, true));
  TEST_ASSERT_EQUAL_UINT32(0, fry::tlsConnectWaitMs(5000u, 5000u + fry::kAssocToDetectLeadMs + 1u, true));
}

// The stamps live in the Wi-Fi connect code without adding any heap object, and no path leaves the gate without an anchor.
void test_wifi_connect_stamps_the_link_up_without_new_heap_and_keeps_an_anchor() {
  std::string w;
  TEST_ASSERT_TRUE(loadSource("src/esp8266/wifi_connect.cpp", w));
  TEST_ASSERT_FALSE_MESSAGE(has(w, "onStationModeGotIP"), "no extra persistent event handler");
  TEST_ASSERT_FALSE_MESSAGE(has(w, "std::function"), "no std::function growth");
  const std::string lam = slice(w, "s_evtConn = WiFi.onStationModeConnected(", "s_evtDhcpTo");
  TEST_ASSERT_TRUE(has(lam, "s_assocMs = millis();"));
  TEST_ASSERT_TRUE(has(lam, "s_haveAssoc = true;"));
  TEST_ASSERT_TRUE(has(lam, "s_haveDetect = false;"));
  TEST_ASSERT_TRUE_MESSAGE(lam.find("s_haveAssoc = true;") != std::string::npos, "association stamped with the clear");
  // Every statement that clears haveDetect sits in the callback that sets haveAssoc; nothing ever clears haveAssoc.
  size_t pos = 0, clears = 0;
  while ((pos = w.find("s_haveDetect = false;  //", pos)) != std::string::npos) { clears++; pos++; }
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(1, clears, "one place clears the address stamp: the association callback");
  TEST_ASSERT_FALSE_MESSAGE(has(w, "  s_haveAssoc = false"), "the association anchor is never withdrawn");
  const std::string conn = slice(w, "if (WiFi.status() == WL_CONNECTED) {\n      s_everConnected = true;", "FRY_PRINTF(");
  TEST_ASSERT_TRUE(has(conn, "s_detectMs = millis();"));
  TEST_ASSERT_TRUE(has(conn, "s_haveDetect = true;"));
  const std::string maint = w.substr(w.find("void maintain() {"));
  TEST_ASSERT_TRUE(has(maint, "if (s_lost) {"));
  TEST_ASSERT_TRUE(has(maint, "s_detectMs = now;"));
  const std::string anchor = w.substr(w.find("bool connectAnchorMs("));
  TEST_ASSERT_TRUE_MESSAGE(has(anchor, "const bool haveDetect = s_haveDetect;"), "stamps copied into locals");
  TEST_ASSERT_TRUE(has(anchor, "fry::connectAnchorMs(detectMs, haveDetect, assocMs, haveAssoc, anchorOut)"));
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
  RUN_TEST(test_gate_is_esp8266_only_and_is_keyed_off_the_connect);
  RUN_TEST(test_no_connect_keeps_the_gate_closed_for_the_full_window_at_any_time);
  RUN_TEST(test_a_late_connect_moves_the_window_with_it);
  RUN_TEST(test_the_association_anchor_dominates_when_the_address_comes_fast);
  RUN_TEST(test_the_address_anchor_dominates_when_dhcp_is_slow);
  RUN_TEST(test_only_the_association_known_uses_the_association_anchor);
  RUN_TEST(test_only_the_address_known_uses_the_address_anchor);
  RUN_TEST(test_neither_stamp_known_reports_no_connect);
  RUN_TEST(test_every_link_up_re_arms_the_gate);
  RUN_TEST(test_the_connect_window_is_wrap_safe);
  RUN_TEST(test_a_long_uptime_never_re_closes_the_gate);
  RUN_TEST(test_an_anchor_ahead_is_honoured_only_up_to_the_association_lead);
  RUN_TEST(test_wifi_connect_stamps_the_link_up_without_new_heap_and_keeps_an_anchor);
  return UNITY_END();
}
