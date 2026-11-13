// Source pins for the early-confirm / install-attempt / probation wiring (lib/fry_core/ota_confirm.*
// holds the decisions; src/core/ota_client.cpp does the I/O). The firmware sources need the
// Arduino core, so these read the text, like test_vpn_start_order and test_hwapi_register_once.
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
  const std::string tail = "test/test_ota_confirm_wiring/test_main.cpp";
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

// The text of `fn` up to its closing brace at column 0 ("\n}\n").
bool bodyOf(const std::string& src, const std::string& header, std::string& body) {
  const size_t a = src.find(header);
  if (a == std::string::npos) return false;
  const size_t b = src.find("\n}\n", a);
  if (b == std::string::npos) return false;
  body = src.substr(a, b - a);
  return true;
}

const char* kIfNot8266 = "#if !defined(ARDUINO_ARCH_ESP8266)";

}  // namespace

void setUp() {}
void tearDown() {}

// The tunnel bring-up attempt is over before the image may confirm: main.cpp tells the OTA client
// right after the ESP32 branch's fry_trigger_start_vpn().
void test_main_reports_the_end_of_the_startup_after_the_tunnel_start() {
  std::string src, body;
  TEST_ASSERT_TRUE(loadSource("src/main.cpp", src));
  TEST_ASSERT_TRUE(bodyOf(src, "void attemptWifiConnect() {", body));
  TEST_ASSERT_EQUAL_INT(1, countOf(body, "fry_ota::noteStartupDone();"));
  const size_t lastVpn = body.rfind("fry_trigger_start_vpn();");
  const size_t note = body.find("fry_ota::noteStartupDone();");
  TEST_ASSERT_TRUE(lastVpn != std::string::npos && note != std::string::npos && note > lastVpn);
  // inside the non-ESP8266 branch: the open #if !defined(...) precedes the last start, the #endif follows the note
  const size_t open = body.rfind(kIfNot8266, lastVpn);
  TEST_ASSERT_TRUE_MESSAGE(open != std::string::npos, "the note must sit in the non-ESP8266 branch");
  const size_t close = body.find("#endif", note);
  TEST_ASSERT_TRUE(close != std::string::npos);
  TEST_ASSERT_TRUE(body.find("#if", open + 1) > close);  // no nested #if between
  TEST_ASSERT_TRUE(body.find("setPhase(BootPhase::Ready);") > close);
}

void test_the_client_declares_the_startup_note() {
  std::string hdr;
  TEST_ASSERT_TRUE(loadSource("src/core/ota_client.h", hdr));
  TEST_ASSERT_EQUAL_INT(1, countOf(hdr, "void noteStartupDone();"));
}

void test_the_early_confirm_runs_in_the_loop_guard_and_keeps_the_old_rules() {
  std::string src, guard, mark;
  TEST_ASSERT_TRUE(loadSource("src/core/ota_client.cpp", src));
  TEST_ASSERT_TRUE(bodyOf(src, "\nvoid loopGuard() {", guard));
  TEST_ASSERT_EQUAL_INT(1, countOf(guard, "fry::decideEarlyConfirm("));
  // the settle-window fallback and the no-answer rollback are still there, with their old inputs
  TEST_ASSERT_EQUAL_INT(1, countOf(guard, "fry::decideMarkValid(true, s_heartbeat.anyResponse(), now, kMarkValidSettleMs)"));
  TEST_ASSERT_EQUAL_INT(1, countOf(guard, "fry::decideRollbackGuard(s_pendingVerify, s_heartbeat.anyResponse(), s_verifyMs,"));
  TEST_ASSERT_EQUAL_INT(1, countOf(guard, "FRY_OTA_VERIFY_DEADLINE_MS"));
  TEST_ASSERT_TRUE(bodyOf(src, "\nvoid tryMarkValid(const char* why) {", mark));
  TEST_ASSERT_EQUAL_INT(1, countOf(mark, "fry::decideMarkValid(true, s_heartbeat.anyResponse(), millis(), kMarkValidSettleMs)"));
  TEST_ASSERT_TRUE(src.find("const uint32_t kMarkValidSettleMs = POC_INTERVAL_MS + 60000UL;") != std::string::npos);
}

void test_the_early_confirm_needs_a_2xx_not_any_status() {
  std::string src, guard;
  TEST_ASSERT_TRUE(loadSource("src/core/ota_client.cpp", src));
  TEST_ASSERT_TRUE(bodyOf(src, "\nvoid loopGuard() {", guard));
  TEST_ASSERT_TRUE(guard.find("s_heartbeat.ageS(") != std::string::npos);  // ageS() >= 0 only after a 2xx
  TEST_ASSERT_TRUE(guard.find("fry_wifi::isConnected()") != std::string::npos);
  TEST_ASSERT_TRUE(guard.find("HEAP_GATE_OTA") != std::string::npos);
}

void test_init_decides_the_boot_before_the_pending_check_and_only_on_the_esp32_family() {
  std::string src, init;
  TEST_ASSERT_TRUE(loadSource("src/core/ota_client.cpp", src));
  TEST_ASSERT_TRUE(bodyOf(src, "\nvoid init() {", init));
  TEST_ASSERT_EQUAL_INT(1, countOf(init, "fry::decideBoot("));
  const size_t decide = init.find("fry::decideBoot(");
  const size_t pendingRead = init.find("String pending = fry_config::getOtaPending();");
  TEST_ASSERT_TRUE(decide != std::string::npos && pendingRead != std::string::npos && decide < pendingRead);
  // the call sits in a block opened by #if !defined(ARDUINO_ARCH_ESP8266) that is closed before the pending read
  const size_t open = init.rfind(kIfNot8266, decide);
  TEST_ASSERT_TRUE_MESSAGE(open != std::string::npos, "decideBoot must be ESP32-family only");
  const size_t close = init.find("\n#endif", decide);
  TEST_ASSERT_TRUE(close != std::string::npos && close < pendingRead);
  // the probation rollback reuses manualRollback() and the boot-fail counter
  TEST_ASSERT_TRUE(init.find("manualRollback();") != std::string::npos);
  TEST_ASSERT_TRUE(init.find("OtaBootCounter") != std::string::npos);
}

void test_the_policy_library_is_not_referenced_by_the_esp8266_paths() {
  std::string src;
  TEST_ASSERT_TRUE(loadSource("src/core/ota_client.cpp", src));
  // every use of the new decisions is inside a block that excludes the ESP8266: walk each one back to
  // the nearest preceding preprocessor line and require that it opens the ESP32-family branch
  const char* names[] = {"fry::decideEarlyConfirm(", "fry::decideBoot(", "fry::decideProbationProgress("};
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
    for (size_t pos = src.find(names[i]); pos != std::string::npos; pos = src.find(names[i], pos + 1)) {
      // count #if/#endif between the start of the file and pos on lines that mention ARDUINO_ARCH_ESP8266
      int depthNot = 0, depthIs = 0;
      std::vector<int> stack;  // 1 = ESP32 branch, 0 = ESP8266 branch, -1 = other
      size_t line = 0;
      while (line < pos) {
        size_t eol = src.find('\n', line);
        if (eol == std::string::npos || eol > pos) eol = pos;
        const std::string l = src.substr(line, eol - line);
        if (l.rfind("#if defined(ARDUINO_ARCH_ESP8266)", 0) == 0) stack.push_back(0);
        else if (l.rfind("#if !defined(ARDUINO_ARCH_ESP8266)", 0) == 0) stack.push_back(1);
        else if (l.rfind("#if", 0) == 0) stack.push_back(-1);
        else if (l.rfind("#else", 0) == 0 && !stack.empty()) {
          if (stack.back() == 0) stack.back() = 1;
          else if (stack.back() == 1) stack.back() = 0;
        } else if (l.rfind("#endif", 0) == 0 && !stack.empty()) stack.pop_back();
        line = eol + 1;
      }
      for (size_t k = 0; k < stack.size(); k++) {
        if (stack[k] == 1) depthNot++;
        if (stack[k] == 0) depthIs++;
      }
      TEST_ASSERT_TRUE_MESSAGE(depthNot > 0 && depthIs == 0, names[i]);
    }
  }
}

void test_config_has_the_attempts_record() {
  std::string hdr, cpp;
  TEST_ASSERT_TRUE(loadSource("src/core/fry_config.h", hdr));
  TEST_ASSERT_TRUE(loadSource("src/core/fry_config.cpp", cpp));
  TEST_ASSERT_TRUE(hdr.find("getOtaAttempts") != std::string::npos);
  TEST_ASSERT_TRUE(hdr.find("setOtaAttempts") != std::string::npos);
  TEST_ASSERT_TRUE(hdr.find("clearOtaAttempts") != std::string::npos);
  TEST_ASSERT_TRUE(cpp.find("\"att\"") != std::string::npos);
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_main_reports_the_end_of_the_startup_after_the_tunnel_start);
  RUN_TEST(test_the_client_declares_the_startup_note);
  RUN_TEST(test_the_early_confirm_runs_in_the_loop_guard_and_keeps_the_old_rules);
  RUN_TEST(test_the_early_confirm_needs_a_2xx_not_any_status);
  RUN_TEST(test_init_decides_the_boot_before_the_pending_check_and_only_on_the_esp32_family);
  RUN_TEST(test_the_policy_library_is_not_referenced_by_the_esp8266_paths);
  RUN_TEST(test_config_has_the_attempts_record);
  return UNITY_END();
}
