// Manifest kill-switch parse (lib/fry_core/olostep_kill.h): only a JSON boolean true kills.
#include <unity.h>

#include <ArduinoJson.h>

#include "olostep_kill.h"

namespace {

bool killFor(const char* json) {
  JsonDocument doc;
  TEST_ASSERT_TRUE(deserializeJson(doc, json) == DeserializationError::Ok);
  return fry::manifestOlostepKill(doc);
}

}  // namespace

void setUp() {}
void tearDown() {}

void test_true_kills() { TEST_ASSERT_TRUE(killFor("{\"olostep_kill\":true}")); }
void test_false_does_not_kill() { TEST_ASSERT_FALSE(killFor("{\"olostep_kill\":false}")); }
void test_absent_key_does_not_kill() {
  TEST_ASSERT_FALSE(killFor("{\"firmware_version\":\"0.4.1\",\"channel\":\"prod\",\"builds\":{}}"));
}
void test_string_true_does_not_kill() { TEST_ASSERT_FALSE(killFor("{\"olostep_kill\":\"true\"}")); }
void test_number_one_does_not_kill() { TEST_ASSERT_FALSE(killFor("{\"olostep_kill\":1}")); }
void test_null_does_not_kill() { TEST_ASSERT_FALSE(killFor("{\"olostep_kill\":null}")); }
void test_key_next_to_a_real_manifest_still_kills() {
  TEST_ASSERT_TRUE(killFor(
      "{\"firmware_version\":\"0.4.1\",\"channel\":\"prod\",\"builds\":{\"esp32\":{\"url\":\"u\"}},\"olostep_kill\":true}"));
}
void test_nested_key_is_not_top_level() {
  TEST_ASSERT_FALSE(killFor("{\"builds\":{\"olostep_kill\":true}}"));
}
void test_non_object_manifest_does_not_kill() {
  JsonDocument doc;
  TEST_ASSERT_TRUE(deserializeJson(doc, "[true]") == DeserializationError::Ok);
  TEST_ASSERT_FALSE(fry::manifestOlostepKill(doc));
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_true_kills);
  RUN_TEST(test_false_does_not_kill);
  RUN_TEST(test_absent_key_does_not_kill);
  RUN_TEST(test_string_true_does_not_kill);
  RUN_TEST(test_number_one_does_not_kill);
  RUN_TEST(test_null_does_not_kill);
  RUN_TEST(test_key_next_to_a_real_manifest_still_kills);
  RUN_TEST(test_nested_key_is_not_top_level);
  RUN_TEST(test_non_object_manifest_does_not_kill);
  return UNITY_END();
}
