// The installation heartbeat of the new boards: exactly the 13 PROTOCOL.md keys, os = the build env value.
#include <unity.h>

#include <ArduinoJson.h>

#include <cstring>
#include <string>

#include "board_presets.h"
#include "heartbeat_fields.h"

void setUp() {}
void tearDown() {}

namespace {
std::string bodyFor(const char* env) {
  const fry::boards::Preset* p = fry::boards::presetForEnv(env);
  fry::InstallationFields f{};
  f.minerKey = "FEM-0123456789ABCDEF0123456789ABCDEF";
  f.installId = "0123456789abcdef0123456789abcdef";
  f.minerCode = "IOTVPN";
  f.softwareVersion = "0.4.31";
  f.pocVersion = "1.0.0";
  f.hostname = "FRY-X-AB0CDE";
  f.os = p ? p->os : "?";
  f.deviceName = "FRY-X-AB0CDE";
  f.flash = {2u * 1024 * 1024, 2u * 1024 * 1024, 1048576, 480000};
  JsonDocument doc;
  fry::buildInstallationDoc(doc, f);
  std::string out;
  serializeJson(doc, out);
  return out;
}
}  // namespace

void test_each_new_board_sends_exactly_13_keys() {
  const char* envs[] = {"rpipicow", "rpipico2w", "bk7231n"};
  for (const char* e : envs) {
    JsonDocument doc;
    TEST_ASSERT_TRUE(deserializeJson(doc, bodyFor(e)) == DeserializationError::Ok);
    TEST_ASSERT_EQUAL_UINT32(13, doc.as<JsonObject>().size());
  }
}

void test_os_value_is_the_preset_os() {
  const char* envs[] = {"rpipicow", "rpipico2w", "bk7231n"};
  const char* want[] = {"rp2040", "rp2350", "bk7231n"};
  for (int i = 0; i < 3; i++) {
    JsonDocument doc;
    deserializeJson(doc, bodyFor(envs[i]));
    TEST_ASSERT_EQUAL_STRING(want[i], doc["os"].as<const char*>());
  }
}

void test_no_heap_relay_or_reset_keys_unless_appended() {
  JsonDocument doc;
  deserializeJson(doc, bodyFor("rpipicow"));
  TEST_ASSERT_TRUE(doc["free_heap"].isNull());
  TEST_ASSERT_TRUE(doc["relay_p50_ms"].isNull());
  TEST_ASSERT_TRUE(doc["reset_reason"].isNull());
  TEST_ASSERT_TRUE(doc["is_installed"].as<bool>());
  TEST_ASSERT_EQUAL_STRING("IOTVPN", doc["minerCode"].as<const char*>());
}

void test_reset_reason_is_the_only_allowed_append_for_boards() {
  JsonDocument doc;
  deserializeJson(doc, bodyFor("bk7231n"));
  fry::addResetReasonField(doc, 3);
  TEST_ASSERT_EQUAL_UINT32(14, doc.as<JsonObject>().size());
  TEST_ASSERT_EQUAL_UINT32(3, doc["reset_reason"].as<uint32_t>());
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_each_new_board_sends_exactly_13_keys);
  RUN_TEST(test_os_value_is_the_preset_os);
  RUN_TEST(test_no_heap_relay_or_reset_keys_unless_appended);
  RUN_TEST(test_reset_reason_is_the_only_allowed_append_for_boards);
  return UNITY_END();
}
