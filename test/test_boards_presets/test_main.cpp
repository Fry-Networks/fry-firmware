// Board preset table (lib/fry_core/board_presets.h): the three non-ESP builds, their os values and identity.
#include <unity.h>

#include <cstring>

#include "board_presets.h"
#include "miner_identity.h"

void setUp() {}
void tearDown() {}

void test_three_presets_exist_with_expected_os() {
  TEST_ASSERT_EQUAL_UINT32(3, fry::boards::presetCount());
  const fry::boards::Preset* a = fry::boards::presetForEnv("rpipicow");
  const fry::boards::Preset* b = fry::boards::presetForEnv("rpipico2w");
  const fry::boards::Preset* c = fry::boards::presetForEnv("bk7231n");
  TEST_ASSERT_NOT_NULL(a);
  TEST_ASSERT_NOT_NULL(b);
  TEST_ASSERT_NOT_NULL(c);
  TEST_ASSERT_EQUAL_STRING("rp2040", a->os);
  TEST_ASSERT_EQUAL_STRING("rp2350", b->os);
  TEST_ASSERT_EQUAL_STRING("bk7231n", c->os);
  TEST_ASSERT_EQUAL_STRING("RP2040", a->chipTag);
  TEST_ASSERT_EQUAL_STRING("RP2350", b->chipTag);
  TEST_ASSERT_EQUAL_STRING("BK7231N", c->chipTag);
}

void test_unknown_env_is_null_and_os_lookup_works() {
  TEST_ASSERT_NULL(fry::boards::presetForEnv("esp32"));
  TEST_ASSERT_NULL(fry::boards::presetForEnv(nullptr));
  TEST_ASSERT_NOT_NULL(fry::boards::presetForOs("rp2350"));
  TEST_ASSERT_NULL(fry::boards::presetForOs("esp8266"));
}

void test_os_values_are_lowercase_and_unique() {
  for (size_t i = 0; i < fry::boards::presetCount(); i++) {
    const fry::boards::Preset& p = fry::boards::presetAt(i);
    for (const char* s = p.os; *s; s++) TEST_ASSERT_TRUE((*s >= 'a' && *s <= 'z') || (*s >= '0' && *s <= '9'));
    for (size_t j = i + 1; j < fry::boards::presetCount(); j++) {
      TEST_ASSERT_TRUE(strcmp(p.os, fry::boards::presetAt(j).os) != 0);
    }
  }
}

void test_storage_and_ota_per_family() {
  using namespace fry::boards;
  TEST_ASSERT_EQUAL(KvBackend::LittleFs, presetForEnv("rpipicow")->kv);
  TEST_ASSERT_EQUAL(KvBackend::LittleFs, presetForEnv("rpipico2w")->kv);
  TEST_ASSERT_EQUAL(KvBackend::FlashDb, presetForEnv("bk7231n")->kv);
  TEST_ASSERT_EQUAL(ImageKind::PicoBin, presetForEnv("rpipicow")->image);
  TEST_ASSERT_EQUAL(ImageKind::BkUf2, presetForEnv("bk7231n")->image);
  TEST_ASSERT_TRUE(presetForEnv("rpipicow")->resetButtonPin >= 0);
}

void test_device_name_for_new_chips_follows_the_grammar() {
  const uint8_t mac6[3] = {0xAB, 0x0C, 0xDE};
  char name[32];
  fry::formatDeviceName("RP2040", mac6, name, sizeof(name));
  TEST_ASSERT_EQUAL_STRING("FRY-RP2040-AB0CDE", name);
  TEST_ASSERT_TRUE(fry::boards::isValidBoardDeviceName(name));
  fry::formatDeviceName("BK7231N", mac6, name, sizeof(name));
  TEST_ASSERT_TRUE(fry::boards::isValidBoardDeviceName(name));
  TEST_ASSERT_TRUE(fry::boards::isValidBoardDeviceName("FRY-ESP32-S3-AB0CDE") == false);  // not an ESP tag path: "ESP32-S3" is
  TEST_ASSERT_TRUE(fry::boards::isValidBoardDeviceName("FRY-RP2350-AB0CDE"));
  TEST_ASSERT_FALSE(fry::boards::isValidBoardDeviceName("FRY-RP2040-ab0cde"));
  TEST_ASSERT_FALSE(fry::boards::isValidBoardDeviceName("FRY-RP2041-AB0CDE"));
  TEST_ASSERT_FALSE(fry::boards::isValidBoardDeviceName(nullptr));
  // The closed ESP grammar is untouched.
  TEST_ASSERT_FALSE(fry::isValidDeviceName("FRY-RP2040-AB0CDE"));
}

void test_reset_reason_tokens_map_to_the_esp32_numbering() {
  TEST_ASSERT_EQUAL(1, fry::boards::resetReasonCode("poweron"));
  TEST_ASSERT_EQUAL(2, fry::boards::resetReasonCode("external"));
  TEST_ASSERT_EQUAL(3, fry::boards::resetReasonCode("software"));
  TEST_ASSERT_EQUAL(4, fry::boards::resetReasonCode("panic"));
  TEST_ASSERT_EQUAL(7, fry::boards::resetReasonCode("wdt"));
  TEST_ASSERT_EQUAL(9, fry::boards::resetReasonCode("brownout"));
  TEST_ASSERT_EQUAL(0, fry::boards::resetReasonCode("unknown"));
  TEST_ASSERT_EQUAL(0, fry::boards::resetReasonCode("nonsense"));
  TEST_ASSERT_EQUAL(0, fry::boards::resetReasonCode(nullptr));
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_three_presets_exist_with_expected_os);
  RUN_TEST(test_unknown_env_is_null_and_os_lookup_works);
  RUN_TEST(test_os_values_are_lowercase_and_unique);
  RUN_TEST(test_storage_and_ota_per_family);
  RUN_TEST(test_device_name_for_new_chips_follows_the_grammar);
  RUN_TEST(test_reset_reason_tokens_map_to_the_esp32_numbering);
  return UNITY_END();
}
