// Installation heartbeat body (lib/fry_core/heartbeat_fields.h): the 0.4.7 keys are unchanged
// (same order and values) and the four flash/OTA-room integers are appended.
#include <unity.h>

#include <ArduinoJson.h>

#include <cstring>
#include <string>

#include "heartbeat_fields.h"

namespace {

fry::InstallationFields sample(uint32_t real, uint32_t ide, uint32_t freeB, uint32_t sketch) {
  fry::InstallationFields f{};
  f.minerKey = "FEM-TEST-0001";
  f.installId = "0123456789abcdef0123456789abcdef";
  f.minerCode = "IOTVPN";
  f.softwareVersion = "0.4.7";
  f.pocVersion = "1.0.0";
  f.hostname = "fry-abc123";
  f.os = "esp8266";
  f.deviceName = "fry-abc123";
  f.flash = {real, ide, freeB, sketch};
  return f;
}

std::string bodyOf(const fry::InstallationFields& f) {
  JsonDocument doc;
  fry::buildInstallationDoc(doc, f);
  std::string out;
  serializeJson(doc, out);
  return out;
}

// What registerInstallation() sent in 0.4.7, character for character (src/core/hardwareapi_client.cpp
// at 25b7b7b:118-127), for the same inputs.
const char kLegacyPrefix[] =
    "{\"miner_key\":\"FEM-TEST-0001\",\"install_id\":\"0123456789abcdef0123456789abcdef\","
    "\"minerCode\":\"IOTVPN\",\"software_version_installed\":\"0.4.7\",\"poc_version_installed\":\"1.0.0\","
    "\"hostname\":\"fry-abc123\",\"os\":\"esp8266\",\"is_installed\":true,\"device_name\":\"fry-abc123\"";

void test_legacy_keys_are_an_unchanged_prefix() {
  const std::string b = bodyOf(sample(4194304, 4194304, 1044464, 400000));
  TEST_ASSERT_EQUAL_INT(0, b.compare(0, strlen(kLegacyPrefix), kLegacyPrefix));
}

void test_four_new_keys_present_as_integers() {
  JsonDocument doc;
  fry::buildInstallationDoc(doc, sample(4194304, 4194304, 1044464, 400000));
  const char* keys[] = {"flash_real_size", "flash_ide_size", "ota_free_bytes", "sketch_size"};
  const uint32_t want[] = {4194304, 4194304, 1044464, 400000};
  for (int i = 0; i < 4; i++) {
    TEST_ASSERT_TRUE_MESSAGE(doc[keys[i]].is<uint32_t>(), keys[i]);
    TEST_ASSERT_FALSE_MESSAGE(doc[keys[i]].is<const char*>(), keys[i]);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(want[i], doc[keys[i]].as<uint32_t>(), keys[i]);
  }
  TEST_ASSERT_EQUAL_UINT32(13, doc.size());  // 9 legacy + 4 new, nothing else
}

void test_distinct_values_do_not_cross() {
  JsonDocument doc;
  fry::buildInstallationDoc(doc, sample(1, 2, 3, 4));
  TEST_ASSERT_EQUAL_UINT32(1, doc["flash_real_size"].as<uint32_t>());
  TEST_ASSERT_EQUAL_UINT32(2, doc["flash_ide_size"].as<uint32_t>());
  TEST_ASSERT_EQUAL_UINT32(3, doc["ota_free_bytes"].as<uint32_t>());
  TEST_ASSERT_EQUAL_UINT32(4, doc["sketch_size"].as<uint32_t>());
}

void test_extreme_values_stay_integers_and_body_is_bounded() {
  const std::string b = bodyOf(sample(0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu));
  TEST_ASSERT_NOT_EQUAL(std::string::npos, b.find("\"flash_real_size\":4294967295"));
  TEST_ASSERT_NOT_EQUAL(std::string::npos, b.find("\"sketch_size\":4294967295"));
  TEST_ASSERT_TRUE_MESSAGE(b.size() < 512, "heartbeat body must stay small");
  const std::string z = bodyOf(sample(0, 0, 0, 0));  // a failed platform read is 0, still an integer
  TEST_ASSERT_NOT_EQUAL(std::string::npos, z.find("\"ota_free_bytes\":0"));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_legacy_keys_are_an_unchanged_prefix);
  RUN_TEST(test_four_new_keys_present_as_integers);
  RUN_TEST(test_distinct_values_do_not_cross);
  RUN_TEST(test_extreme_values_stay_integers_and_body_is_bounded);
  return UNITY_END();
}
