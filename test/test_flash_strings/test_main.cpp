// The log text of the OTA-path sources stays in flash on the ESP8266 (src/core/flash_print.h).
//
// The ESP8266 keeps a plain string literal in DRAM, and the heap is whatever static RAM leaves: 1380 B of ota_client's Serial text alone
// were 1380 B the image download's TLS session did not have (c1 census, X2 Problem 2). A `Serial.println("...")` / `Serial.printf("...")`
// / `Serial.print("...")` with the literal as the first argument puts it back in DRAM, so the files below must not contain one: the call is
// FRY_PRINTLN / FRY_PRINTF / FRY_PRINT (shared with the ESP32 family, where it expands to the call it always was) or, in an ESP8266-only
// file, println(F()) / printf_P(PSTR()).
//
// The sources need the Arduino core, so these are source pins (same technique as test_ota_release / test_ota_stack).
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
  const std::string tail = "test/test_flash_strings/test_main.cpp";
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

// `Serial.<name>(` followed (after any whitespace, newlines included) by a string literal.
int dramLiteralPrints(const std::string& src) {
  const char* calls[] = {"Serial.printf(", "Serial.println(", "Serial.print("};
  int n = 0;
  for (size_t c = 0; c < sizeof(calls) / sizeof(calls[0]); c++) {
    const std::string call = calls[c];
    for (size_t pos = src.find(call); pos != std::string::npos; pos = src.find(call, pos + call.size())) {
      size_t i = pos + call.size();
      while (i < src.size() && (src[i] == ' ' || src[i] == '\t' || src[i] == '\n' || src[i] == '\r')) i++;
      if (i < src.size() && src[i] == '"') n++;
    }
  }
  return n;
}

void expectNoDramLiteralPrints(const char* rel) {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource(rel, src), rel);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, dramLiteralPrints(src), rel);
}

}  // namespace

void test_the_macros_read_from_flash_on_the_esp8266_and_keep_the_old_call_elsewhere() {
  std::string h;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/core/flash_print.h", h), "cannot read src/core/flash_print.h");
  const size_t esp8266 = h.find("#if defined(ARDUINO_ARCH_ESP8266)");
  const size_t other = h.find("#else");
  TEST_ASSERT_TRUE_MESSAGE(esp8266 != std::string::npos && other != std::string::npos && esp8266 < other, "ESP8266 branch, then the rest");
  const std::string a = h.substr(esp8266, other - esp8266);
  const std::string b = h.substr(other);
  TEST_ASSERT_EQUAL_INT(1, countOf(a, "#define FRY_PRINTF(fmt, ...) Serial.printf_P(PSTR(fmt), ##__VA_ARGS__)"));
  TEST_ASSERT_EQUAL_INT(1, countOf(a, "#define FRY_PRINTLN(text) Serial.println(F(text))"));
  TEST_ASSERT_EQUAL_INT(1, countOf(a, "#define FRY_PRINT(text) Serial.print(F(text))"));
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(b, "#define FRY_PRINTF(fmt, ...) Serial.printf(fmt, ##__VA_ARGS__)"), "the ESP32 family keeps the call it had");
  TEST_ASSERT_EQUAL_INT(1, countOf(b, "#define FRY_PRINTLN(text) Serial.println(text)"));
  TEST_ASSERT_EQUAL_INT(1, countOf(b, "#define FRY_PRINT(text) Serial.print(text)"));
}

void test_ota_client_prints_its_text_from_flash() { expectNoDramLiteralPrints("src/core/ota_client.cpp"); }
void test_telemetry_prints_its_text_from_flash() { expectNoDramLiteralPrints("src/core/telemetry.cpp"); }
void test_hardwareapi_prints_its_text_from_flash() { expectNoDramLiteralPrints("src/core/hardwareapi_client.cpp"); }
void test_wifi_provisioning_prints_its_text_from_flash() { expectNoDramLiteralPrints("src/esp8266/wifi_provisioning.cpp"); }

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_macros_read_from_flash_on_the_esp8266_and_keep_the_old_call_elsewhere);
  RUN_TEST(test_ota_client_prints_its_text_from_flash);
  RUN_TEST(test_telemetry_prints_its_text_from_flash);
  RUN_TEST(test_hardwareapi_prints_its_text_from_flash);
  RUN_TEST(test_wifi_provisioning_prints_its_text_from_flash);
  return UNITY_END();
}
