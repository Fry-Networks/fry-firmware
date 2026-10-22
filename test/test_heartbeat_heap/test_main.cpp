// The installation heartbeat of the ESP8266 image carries the heap and loop-stack headroom: free_heap, max_free_block, heap_frag,
// stack_high_water. They are appended AFTER buildInstallationDoc() (lib/fry_core/heartbeat_fields.h addHeapFields), so the 13-member
// body that test_heartbeat_fields pins, and the 0.4.7 prefix, are untouched; only the ESP8266 platform shim calls it
// (-DFRY_HEARTBEAT_HEAP=1 in [env:esp8266]), so the ESP32 family never builds the call.
#include <unity.h>

#include <ArduinoJson.h>

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
  f.softwareVersion = "0.4.10";
  f.pocVersion = "1.0.0";
  f.hostname = "fry-abc123";
  f.os = "esp8266";
  f.deviceName = "fry-abc123";
  f.flash = {4194304, 4194304, 1044464, 400000};
  return f;
}

std::string serialized(const JsonDocument& doc) {
  std::string out;
  serializeJson(doc, out);
  return out;
}

void test_the_builder_alone_still_makes_the_13_member_body() {
  JsonDocument doc;
  fry::buildInstallationDoc(doc, sample());
  TEST_ASSERT_EQUAL_UINT32(13, doc.size());
  TEST_ASSERT_TRUE(doc["free_heap"].isNull());
  TEST_ASSERT_TRUE(doc["stack_high_water"].isNull());
}

void test_four_heap_keys_are_appended_as_integers_with_the_agreed_names() {
  JsonDocument doc;
  fry::buildInstallationDoc(doc, sample());
  fry::addHeapFields(doc, {37672, 29080, 22, 944});
  TEST_ASSERT_EQUAL_UINT32(17, doc.size());
  const char* keys[] = {"free_heap", "max_free_block", "heap_frag", "stack_high_water"};
  const uint32_t want[] = {37672, 29080, 22, 944};
  for (int i = 0; i < 4; i++) {
    TEST_ASSERT_TRUE_MESSAGE(doc[keys[i]].is<uint32_t>(), keys[i]);
    TEST_ASSERT_FALSE_MESSAGE(doc[keys[i]].is<const char*>(), keys[i]);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(want[i], doc[keys[i]].as<uint32_t>(), keys[i]);
  }
}

void test_the_existing_keys_keep_their_order_and_the_new_ones_come_last() {
  JsonDocument plain;
  fry::buildInstallationDoc(plain, sample());
  const std::string base = serialized(plain);
  JsonDocument doc;
  fry::buildInstallationDoc(doc, sample());
  fry::addHeapFields(doc, {1, 2, 3, 4});
  const std::string full = serialized(doc);
  // everything up to the closing brace of the 13-member body is byte-identical...
  TEST_ASSERT_EQUAL_INT(0, full.compare(0, base.size() - 1, base, 0, base.size() - 1));
  // ...and the four new members follow, in this order.
  const size_t a = full.find("\"free_heap\":1"), b = full.find("\"max_free_block\":2"), c = full.find("\"heap_frag\":3"),
               d = full.find("\"stack_high_water\":4");
  TEST_ASSERT_TRUE(a != std::string::npos && a >= base.size() - 1);
  TEST_ASSERT_TRUE(a < b && b < c && c < d);
}

void test_extreme_values_stay_integers_and_the_body_stays_small() {
  JsonDocument doc;
  fry::buildInstallationDoc(doc, sample());
  fry::addHeapFields(doc, {0xFFFFFFFFu, 0xFFFFFFFFu, 100, 0xFFFFFFFFu});
  const std::string b = serialized(doc);
  TEST_ASSERT_NOT_EQUAL(std::string::npos, b.find("\"max_free_block\":4294967295"));
  TEST_ASSERT_TRUE_MESSAGE(b.size() < 640, "heartbeat body must stay small");
  JsonDocument z;
  fry::buildInstallationDoc(z, sample());
  fry::addHeapFields(z, {0, 0, 0, 0});  // a failed platform read is 0, still an integer
  TEST_ASSERT_NOT_EQUAL(std::string::npos, serialized(z).find("\"heap_frag\":0"));
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
  const std::string tail = "test/test_heartbeat_heap/test_main.cpp";
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

std::string iniSection(const std::string& ini, const std::string& header) {
  const size_t at = ini.find("\n" + header + "\n");
  if (at == std::string::npos) return "";
  const size_t next = ini.find("\n[", at + 1);
  return ini.substr(at + 1, next == std::string::npos ? std::string::npos : next - at - 1);
}

void test_the_flag_is_on_in_env_esp8266_and_nowhere_else() {
  std::string ini;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("platformio.ini", ini), "cannot read platformio.ini");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(ini, "-DFRY_HEARTBEAT_HEAP=1"), "set once in the whole file");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(iniSection(ini, "[env:esp8266]"), "-DFRY_HEARTBEAT_HEAP=1"),
                                "...in [env:esp8266], which every ESP8266 env extends: ON in the shipped image");
  TEST_ASSERT_EQUAL_INT(0, countOf(iniSection(ini, "[embedded]"), "FRY_HEARTBEAT_HEAP"));
  TEST_ASSERT_EQUAL_INT(0, countOf(iniSection(ini, "[esp32common]"), "FRY_HEARTBEAT_HEAP"));
}

void test_the_shim_samples_on_esp8266_only_and_adds_the_fields_after_the_builder() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/core/hardwareapi_client.cpp", src), "cannot read src/core/hardwareapi_client.cpp");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "#if defined(FRY_HEARTBEAT_HEAP) && defined(ARDUINO_ARCH_ESP8266)\n"
                                                "__attribute__((noinline)) void addHeartbeatHeap(JsonDocument& doc) {"),
                                "one ESP8266-only helper, noinline so registerInstallation()'s frame does not grow");
  TEST_ASSERT_EQUAL_INT(1, countOf(src, "ESP.getHeapStats(&freeHeap, &maxBlock, &frag);"));
  TEST_ASSERT_EQUAL_INT(1, countOf(src, "ESP.getFreeContStack()"));
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "fry::buildInstallationDoc(doc, fields);\n"
                                                "#if defined(FRY_HEARTBEAT_HEAP) && defined(ARDUINO_ARCH_ESP8266)\n"
                                                "  addHeartbeatHeap(doc);\n#endif\n"),
                                "called once, right after the builder, under the same guard");
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_builder_alone_still_makes_the_13_member_body);
  RUN_TEST(test_four_heap_keys_are_appended_as_integers_with_the_agreed_names);
  RUN_TEST(test_the_existing_keys_keep_their_order_and_the_new_ones_come_last);
  RUN_TEST(test_extreme_values_stay_integers_and_the_body_stays_small);
  RUN_TEST(test_the_flag_is_on_in_env_esp8266_and_nowhere_else);
  RUN_TEST(test_the_shim_samples_on_esp8266_only_and_adds_the_fields_after_the_builder);
  return UNITY_END();
}
