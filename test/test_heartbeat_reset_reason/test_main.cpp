// The installation heartbeat carries `reset_reason`, why the chip last reset, as one small unsigned integer
// (lib/fry_core/heartbeat_fields.h addResetReasonField). It is appended AFTER buildInstallationDoc() and after the heap and relay
// fields, so the 13-member body that test_heartbeat_fields pins, the heap keys and the relay keys are untouched. The value is
// chip-specific (esp_reset_reason_t on the ESP32 family, rst_info.reason on the ESP8266; PROTOCOL.md 11.10) and is clamped to 0..255.
#include <unity.h>

#include <ArduinoJson.h>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "heartbeat_fields.h"

namespace {

fry::InstallationFields sample() {
  fry::InstallationFields f{};
  f.minerKey = "FEM-TEST-0001";
  f.installId = "0123456789abcdef0123456789abcdef";
  f.minerCode = "IOTVPN";
  f.softwareVersion = "0.4.15";
  f.pocVersion = "1.0.0";
  f.hostname = "fry-abc123";
  f.os = "esp32";
  f.deviceName = "fry-abc123";
  f.flash = {4194304, 4194304, 1044464, 400000};
  return f;
}

std::string serialized(const JsonDocument& doc) {
  std::string out;
  serializeJson(doc, out);
  return out;
}

void test_reset_reason_is_one_integer_key_with_the_agreed_name() {
  JsonDocument doc;
  fry::buildInstallationDoc(doc, sample());
  TEST_ASSERT_EQUAL_UINT32(13, doc.size());
  fry::addResetReasonField(doc, 3);
  TEST_ASSERT_EQUAL_UINT32(14, doc.size());
  TEST_ASSERT_TRUE(doc["reset_reason"].is<uint32_t>());
  TEST_ASSERT_FALSE(doc["reset_reason"].is<const char*>());
  TEST_ASSERT_EQUAL_UINT32(3, doc["reset_reason"].as<uint32_t>());
}

void test_zero_is_present_not_omitted() {
  JsonDocument doc;
  fry::buildInstallationDoc(doc, sample());
  fry::addResetReasonField(doc, 0);  // ESP8266 power-on is 0; ESP32 "unknown" is 0
  TEST_ASSERT_NOT_EQUAL(std::string::npos, serialized(doc).find("\"reset_reason\":0"));
}

void test_it_comes_last_after_heap_and_relay_and_the_base_body_is_a_prefix() {
  JsonDocument base;
  fry::buildInstallationDoc(base, sample());
  const std::string b = serialized(base);
  JsonDocument doc;
  fry::buildInstallationDoc(doc, sample());
  fry::addHeapFields(doc, {37672, 29080, 22, 944});
  fry::addRelayLatencyFields(doc, {12, 40, 7});
  fry::addResetReasonField(doc, 1);
  const std::string s = serialized(doc);
  TEST_ASSERT_EQUAL_INT(0, s.compare(0, b.size() - 1, b.substr(0, b.size() - 1)));
  const size_t relay = s.find("\"relay_samples\":7");
  const size_t rr = s.find("\"reset_reason\":1");
  TEST_ASSERT_TRUE(relay != std::string::npos && rr != std::string::npos && relay < rr);
  TEST_ASSERT_EQUAL_UINT32(21, doc.size());  // 13 base + 4 heap + 3 relay + reset_reason
}

void test_the_value_is_clamped_to_one_byte() {
  const uint32_t in[] = {0, 1, 3, 4, 255, 256, 1000, 0xFFFFFFFFu};
  const uint32_t want[] = {0, 1, 3, 4, 255, 255, 255, 255};
  for (size_t i = 0; i < sizeof(in) / sizeof(in[0]); i++) {
    JsonDocument doc;
    fry::addResetReasonField(doc, in[i]);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(want[i], doc["reset_reason"].as<uint32_t>(), "clamped to 0..255");
  }
}

void test_the_body_stays_small() {
  JsonDocument doc;
  fry::buildInstallationDoc(doc, sample());
  fry::addHeapFields(doc, {0xFFFFFFFFu, 0xFFFFFFFFu, 100, 0xFFFFFFFFu});
  fry::addRelayLatencyFields(doc, {0xFFFFFFFFu, 0xFFFFFFFFu, 60});
  fry::addResetReasonField(doc, 0xFFFFFFFFu);
  TEST_ASSERT_TRUE_MESSAGE(serialized(doc).size() < 640, "heartbeat body must stay small");
}

// ---- wiring pins (source text) ---------------------------------------------------------------------------------------------

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
  const std::string tail = "test/test_heartbeat_reset_reason/test_main.cpp";
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

void test_the_shim_reads_each_chips_own_source_once_and_is_called_after_the_relay_block() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/core/hardwareapi_client.cpp", src), "cannot read src/core/hardwareapi_client.cpp");
  TEST_ASSERT_EQUAL_INT(1, countOf(src, "ESP.getResetInfoPtr()->reason"));
  TEST_ASSERT_EQUAL_INT(1, countOf(src, "esp_reset_reason()"));
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "__attribute__((noinline)) void addHeartbeatResetReason(JsonDocument& doc) {"),
                                "own frame so registerInstallation()'s stack does not grow");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "  addHeartbeatRelayLatency(doc);\n#endif\n  addHeartbeatResetReason(doc);\n"),
                                "called once, unconditionally, right after the relay block and before the body is serialized");
}

void test_the_boot_line_prints_the_same_value_the_heartbeat_sends() {
  std::string main;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/main.cpp", main), "cannot read src/main.cpp");
  TEST_ASSERT_EQUAL_INT(1, countOf(main, "FRY_PRINTF(\"[boot] reset_reason=%u\\n\", static_cast<unsigned>(fry_hwapi::resetReason()));"));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_reset_reason_is_one_integer_key_with_the_agreed_name);
  RUN_TEST(test_zero_is_present_not_omitted);
  RUN_TEST(test_it_comes_last_after_heap_and_relay_and_the_base_body_is_a_prefix);
  RUN_TEST(test_the_value_is_clamped_to_one_byte);
  RUN_TEST(test_the_body_stays_small);
  RUN_TEST(test_the_shim_reads_each_chips_own_source_once_and_is_called_after_the_relay_block);
  RUN_TEST(test_the_boot_line_prints_the_same_value_the_heartbeat_sends);
  return UNITY_END();
}
