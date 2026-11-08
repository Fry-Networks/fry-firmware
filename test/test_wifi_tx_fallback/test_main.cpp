// ESP32-C3 reduced-TX join fallback: the pure decision (lib/fry_core/wifi_tx_fallback.h) and a source
// pin that src/esp32/wifi_connect.cpp wires it, bounded, behind the C3 target macro only.
#include <unity.h>

#include <fstream>
#include <sstream>
#include <string>

#include "wifi_tx_fallback.h"

namespace {

void test_handshake_class_after_association_retries() {
  const uint8_t reasons[] = {2, 15, 202, 203, 204};
  for (uint8_t r : reasons) TEST_ASSERT_TRUE(fry::shouldRetryLowTx(r, true, false));
}

void test_no_retry_without_association() {
  const uint8_t reasons[] = {2, 15, 201, 202, 203, 204, 0};
  for (uint8_t r : reasons) TEST_ASSERT_FALSE(fry::shouldRetryLowTx(r, false, false));
}

void test_no_retry_for_other_reasons() {
  // 0 undiagnosed, 1 UNSPECIFIED, 8 ASSOC_LEAVE, 200 BEACON_TIMEOUT, 201 NO_AP_FOUND, 205 CONNECTION_FAIL
  const uint8_t reasons[] = {0, 1, 8, 200, 201, 205};
  for (uint8_t r : reasons) TEST_ASSERT_FALSE(fry::shouldRetryLowTx(r, true, false));
}

void test_retry_is_bounded() {
  TEST_ASSERT_FALSE(fry::shouldRetryLowTx(2, true, true));
  TEST_ASSERT_FALSE(fry::shouldRetryLowTx(202, true, true));
}

void test_retry_timeout_is_bounded() {
  TEST_ASSERT_EQUAL_UINT32(10000, fry::kLowTxRetryTimeoutMs);
  TEST_ASSERT_EQUAL_UINT32(10000, fry::lowTxRetryTimeoutMs(20000));
  TEST_ASSERT_EQUAL_UINT32(10000, fry::lowTxRetryTimeoutMs(10000));
  TEST_ASSERT_EQUAL_UINT32(5000, fry::lowTxRetryTimeoutMs(5000));
  TEST_ASSERT_EQUAL_UINT32(0, fry::lowTxRetryTimeoutMs(0));
}

bool readFile(const std::string& path, std::string& out) {
  std::ifstream f(path.c_str(), std::ios::in | std::ios::binary);
  if (!f) return false;
  std::stringstream ss;
  ss << f.rdbuf();
  out = ss.str();
  return true;
}

bool loadSource(std::string& out) {
  const char* prefixes[] = {"", "./", "../", "../../", "../../../"};
  for (const char* p : prefixes) {
    if (readFile(std::string(p) + "src/esp32/wifi_connect.cpp", out)) return true;
  }
  return false;
}

void test_source_has_the_c3_fallback_guarded_to_c3() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource(src), "cannot read src/esp32/wifi_connect.cpp");
  const size_t retry = src.find("join retry at reduced tx power");
  TEST_ASSERT_TRUE_MESSAGE(retry != std::string::npos, "C3 reduced-TX retry is missing");
  TEST_ASSERT_TRUE(src.find("fry::shouldRetryLowTx(") != std::string::npos);
  // Every use of the low power, and the retry itself, sits inside a C3 #if ... #endif block.
  const std::string guardTxt = "#if defined(CONFIG_IDF_TARGET_ESP32C3)";
  size_t pos = src.find("WIFI_POWER_8_5dBm");
  TEST_ASSERT_TRUE_MESSAGE(pos != std::string::npos, "WIFI_POWER_8_5dBm is missing");
  std::string::size_type marks[2] = {retry, pos};
  for (size_t m : marks) {
    const size_t g = src.rfind(guardTxt, m);
    TEST_ASSERT_TRUE_MESSAGE(g != std::string::npos, "not under a C3 guard");
    const size_t e = src.find("#endif", g);
    TEST_ASSERT_TRUE_MESSAGE(e != std::string::npos && e > m, "not under a C3 guard");
  }
  while (pos != std::string::npos) {
    const size_t g = src.rfind(guardTxt, pos);
    TEST_ASSERT_TRUE_MESSAGE(g != std::string::npos, "low TX used outside a C3 guard");
    const size_t e = src.find("#endif", g);
    TEST_ASSERT_TRUE_MESSAGE(e != std::string::npos && e > pos, "low TX used outside a C3 guard");
    pos = src.find("WIFI_POWER_8_5dBm", pos + 1);
  }
}

// Once per boot, bounded timeout, no stale leave event: pinned on the source order.
void test_source_retry_is_once_per_boot_and_bounded() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource(src), "cannot read src/esp32/wifi_connect.cpp");
  const size_t decide = src.find("fry::shouldRetryLowTx(s_lastDiscReason, s_l2Associated, s_lowTxTried)");
  TEST_ASSERT_TRUE_MESSAGE(decide != std::string::npos, "retry decision must use s_lowTxTried (once per boot)");
  const size_t tried = src.find("s_lowTxTried = true;", decide);
  TEST_ASSERT_TRUE_MESSAGE(tried != std::string::npos, "s_lowTxTried must be set when the retry starts");
  const size_t bounded = src.find("joinOnce(ssid, pass, fry::lowTxRetryTimeoutMs(timeoutMs))", tried);
  TEST_ASSERT_TRUE_MESSAGE(bounded != std::string::npos, "retry must use the bounded timeout, after s_lowTxTried is set");
  // The flag is never cleared, so a failed retry is not repeated by a later connect().
  const size_t init = src.find("bool s_lowTxTried = false;");
  TEST_ASSERT_TRUE_MESSAGE(init != std::string::npos, "s_lowTxTried initialiser missing");
  TEST_ASSERT_TRUE_MESSAGE(src.find("s_lowTxTried = false", init + 10) == std::string::npos,
                           "s_lowTxTried must never be reset");
  // The stale-leave guard brackets our own disconnect.
  const size_t ig = src.find("s_ignoreLeave = true;", tried);
  TEST_ASSERT_TRUE_MESSAGE(ig != std::string::npos, "leave guard missing");
  const size_t dis = src.find("WiFi.disconnect(true);", ig);
  const size_t clr = src.find("s_ignoreLeave = false;", dis);
  TEST_ASSERT_TRUE_MESSAGE(dis != std::string::npos && clr != std::string::npos && clr < bounded,
                           "leave guard must wrap disconnect and clear before the retry join");
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_handshake_class_after_association_retries);
  RUN_TEST(test_no_retry_without_association);
  RUN_TEST(test_no_retry_for_other_reasons);
  RUN_TEST(test_retry_is_bounded);
  RUN_TEST(test_retry_timeout_is_bounded);
  RUN_TEST(test_source_retry_is_once_per_boot_and_bounded);
  RUN_TEST(test_source_has_the_c3_fallback_guarded_to_c3);
  return UNITY_END();
}
