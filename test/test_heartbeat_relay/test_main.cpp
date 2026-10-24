// lib/fry_core/heartbeat_fields.h addRelayLatencyFields: the three relay-latency keys the ESP32
// heartbeat appends (src/core/hardwareapi_client.cpp addHeartbeatRelayLatency).
//
// The 13-member body built by buildInstallationDoc is pinned by test_heartbeat_fields and must not
// move: these fields are appended AFTER it, the same way the ESP8266's four heap fields are
// (addHeapFields). So the checks here are (a) the 13 keys and values are byte-identical to what
// buildInstallationDoc alone produces, (b) exactly three integers follow, in that order, (c) they
// carry the ring's numbers and are always present, zero included.
#include <unity.h>

#include <ArduinoJson.h>

#include <cstring>
#include <string>

#include "heartbeat_fields.h"

namespace {

fry::InstallationFields sample() {
  fry::InstallationFields f{};
  f.minerKey = "FEM-TEST-0001";
  f.installId = "0123456789abcdef0123456789abcdef";
  f.minerCode = "IOTVPN";
  f.softwareVersion = "0.4.11";
  f.pocVersion = "1.0.0";
  f.hostname = "fry-abc123";
  f.os = "esp32";
  f.deviceName = "fry-abc123";
  f.flash = {4194304, 4194304, 1044464, 400000};
  return f;
}

std::string baseBody() {
  JsonDocument doc;
  fry::buildInstallationDoc(doc, sample());
  std::string out;
  serializeJson(doc, out);
  return out;
}

std::string relayBody(uint32_t p50, uint32_t p95, uint32_t samples) {
  JsonDocument doc;
  fry::buildInstallationDoc(doc, sample());
  fry::addRelayLatencyFields(doc, {p50, p95, samples});
  std::string out;
  serializeJson(doc, out);
  return out;
}

void test_the_thirteen_existing_keys_are_an_unchanged_prefix() {
  const std::string base = baseBody();
  const std::string withRelay = relayBody(12, 40, 7);
  TEST_ASSERT_EQUAL_INT(0, withRelay.compare(0, base.size() - 1, base.substr(0, base.size() - 1)));
}

void test_exactly_three_integer_keys_are_appended() {
  JsonDocument doc;
  fry::buildInstallationDoc(doc, sample());
  const uint32_t before = doc.size();
  TEST_ASSERT_EQUAL_UINT32(13, before);
  fry::addRelayLatencyFields(doc, {12, 40, 7});
  TEST_ASSERT_EQUAL_UINT32(16, doc.size());
  const char* keys[] = {"relay_p50_ms", "relay_p95_ms", "relay_samples"};
  const uint32_t want[] = {12, 40, 7};
  for (int i = 0; i < 3; i++) {
    TEST_ASSERT_TRUE_MESSAGE(doc[keys[i]].is<uint32_t>(), keys[i]);
    TEST_ASSERT_FALSE_MESSAGE(doc[keys[i]].is<const char*>(), keys[i]);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(want[i], doc[keys[i]].as<uint32_t>(), keys[i]);
  }
}

void test_the_three_keys_are_serialized_after_the_base_body() {
  const std::string b = relayBody(12, 40, 7);
  const size_t p50 = b.find("\"relay_p50_ms\":12");
  const size_t p95 = b.find("\"relay_p95_ms\":40");
  const size_t n = b.find("\"relay_samples\":7");
  TEST_ASSERT_NOT_EQUAL(std::string::npos, p50);
  TEST_ASSERT_NOT_EQUAL(std::string::npos, p95);
  TEST_ASSERT_NOT_EQUAL(std::string::npos, n);
  // Appended in this order, after every base key.
  TEST_ASSERT_TRUE(p50 < p95 && p95 < n);
  TEST_ASSERT_TRUE(b.find("\"sketch_size\"") < p50);
}

void test_no_samples_is_present_as_zero_not_omitted() {
  const std::string b = relayBody(0, 0, 0);
  TEST_ASSERT_NOT_EQUAL(std::string::npos, b.find("\"relay_samples\":0"));
  TEST_ASSERT_NOT_EQUAL(std::string::npos, b.find("\"relay_p50_ms\":0"));
  JsonDocument doc;
  fry::buildInstallationDoc(doc, sample());
  fry::addRelayLatencyFields(doc, {0, 0, 0});
  TEST_ASSERT_EQUAL_UINT32(16, doc.size());  // relay_samples == 0 is how "no data" is read
}

void test_extreme_values_stay_integers_and_the_body_stays_small() {
  const std::string b = relayBody(0xFFFFFFFFu, 0xFFFFFFFFu, 60);
  TEST_ASSERT_NOT_EQUAL(std::string::npos, b.find("\"relay_p50_ms\":4294967295"));
  TEST_ASSERT_NOT_EQUAL(std::string::npos, b.find("\"relay_p95_ms\":4294967295"));
  TEST_ASSERT_NOT_EQUAL(std::string::npos, b.find("\"relay_samples\":60"));
  TEST_ASSERT_TRUE_MESSAGE(b.size() < 640, "heartbeat body must stay small");
}

void test_distinct_values_do_not_cross_between_the_keys() {
  JsonDocument doc;
  fry::buildInstallationDoc(doc, sample());
  fry::addRelayLatencyFields(doc, {1, 2, 3});
  TEST_ASSERT_EQUAL_UINT32(1, doc["relay_p50_ms"].as<uint32_t>());
  TEST_ASSERT_EQUAL_UINT32(2, doc["relay_p95_ms"].as<uint32_t>());
  TEST_ASSERT_EQUAL_UINT32(3, doc["relay_samples"].as<uint32_t>());
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_thirteen_existing_keys_are_an_unchanged_prefix);
  RUN_TEST(test_exactly_three_integer_keys_are_appended);
  RUN_TEST(test_the_three_keys_are_serialized_after_the_base_body);
  RUN_TEST(test_no_samples_is_present_as_zero_not_omitted);
  RUN_TEST(test_extreme_values_stay_integers_and_the_body_stays_small);
  RUN_TEST(test_distinct_values_do_not_cross_between_the_keys);
  return UNITY_END();
}
