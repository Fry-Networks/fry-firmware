// Namespace/key -> flat key mapping and value codec used by the Pico (LittleFS) and BK7231N (FlashDB) KV stores.
#include <unity.h>

#include <cstring>

#include "kv_map.h"

void setUp() {}
void tearDown() {}

void test_flat_key_joins_ns_and_key_with_a_dot() {
  char out[48];
  TEST_ASSERT_TRUE(fry::kv::flatKey("fry", "minerKey", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("fry.minerKey", out);
  TEST_ASSERT_TRUE(fry::kv::flatKey("fry_wifi", "ssid", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("fry_wifi.ssid", out);
}

void test_every_fry_config_key_fits_nvs_parity_limits() {
  // The longest names fry_config / hardwareapi use (NVS caps both at 15 characters).
  const char* keys[] = {"shdwInstallId", "shdwDevToken", "deviceToken", "wgProvAt", "bootfails", "healAt", "keyOk", "keySrc"};
  char out[48];
  for (const char* k : keys) TEST_ASSERT_TRUE(fry::kv::flatKey("fry", k, out, sizeof(out)));
}

void test_rejects_overlong_empty_or_bad_characters() {
  char out[48];
  TEST_ASSERT_FALSE(fry::kv::flatKey("fry", "abcdefghijklmnop", out, sizeof(out)));  // 16 chars
  TEST_ASSERT_FALSE(fry::kv::flatKey("abcdefghijklmnop", "k", out, sizeof(out)));
  TEST_ASSERT_FALSE(fry::kv::flatKey("", "k", out, sizeof(out)));
  TEST_ASSERT_FALSE(fry::kv::flatKey("fry", "", out, sizeof(out)));
  TEST_ASSERT_FALSE(fry::kv::flatKey("fr.y", "k", out, sizeof(out)));   // a dot would make the join ambiguous
  TEST_ASSERT_FALSE(fry::kv::flatKey("fry", "a/b", out, sizeof(out)));  // no path separators
  TEST_ASSERT_FALSE(fry::kv::flatKey(nullptr, "k", out, sizeof(out)));
  TEST_ASSERT_FALSE(fry::kv::flatKey("fry", "k", out, 4));  // too small for the result
}

void test_distinct_pairs_never_collide() {
  char a[48], b[48];
  fry::kv::flatKey("fry", "ssid", a, sizeof(a));
  fry::kv::flatKey("fry_wifi", "ssid", b, sizeof(b));
  TEST_ASSERT_TRUE(strcmp(a, b) != 0);
  fry::kv::flatKey("fry_ota", "url", a, sizeof(a));
  fry::kv::flatKey("fry", "ota_url", b, sizeof(b));
  TEST_ASSERT_TRUE(strcmp(a, b) != 0);
}

void test_namespace_membership_for_clear() {
  TEST_ASSERT_TRUE(fry::kv::inNamespace("fry.minerKey", "fry"));
  TEST_ASSERT_FALSE(fry::kv::inNamespace("fry_wifi.ssid", "fry"));
  TEST_ASSERT_TRUE(fry::kv::inNamespace("fry_wifi.ssid", "fry_wifi"));
  TEST_ASSERT_FALSE(fry::kv::inNamespace("fry", "fry"));
  TEST_ASSERT_EQUAL_STRING("ssid", fry::kv::keyPart("fry_wifi.ssid", "fry_wifi"));
  TEST_ASSERT_NULL(fry::kv::keyPart("fry_wifi.ssid", "fry"));
}

void test_file_name_for_littlefs() {
  char out[64];
  TEST_ASSERT_TRUE(fry::kv::fileName("fry", "salt", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("/kv_fry.salt", out);
  TEST_ASSERT_FALSE(fry::kv::fileName("fry", "salt", out, 6));
}

void test_u32_codec_roundtrip_and_defaults() {
  uint8_t b[4];
  fry::kv::encodeU32(0x01020304u, b);
  TEST_ASSERT_EQUAL_UINT8(4, b[0]);  // little endian
  TEST_ASSERT_EQUAL_UINT32(0x01020304u, fry::kv::decodeU32(b, 4, 7));
  TEST_ASSERT_EQUAL_UINT32(7, fry::kv::decodeU32(b, 3, 7));      // wrong length -> default
  TEST_ASSERT_EQUAL_UINT32(7, fry::kv::decodeU32(nullptr, 0, 7));
}

void test_string_codec_is_nul_terminated_and_bounded() {
  uint8_t blob[8];
  size_t n = fry::kv::encodeString("abc", blob, sizeof(blob));
  TEST_ASSERT_EQUAL_UINT32(4, n);  // includes the NUL, as NVS does
  char out[8];
  size_t got = fry::kv::decodeString(blob, n, out, sizeof(out));
  TEST_ASSERT_EQUAL_UINT32(3, got);
  TEST_ASSERT_EQUAL_STRING("abc", out);
  char tiny[3];
  got = fry::kv::decodeString(blob, n, tiny, sizeof(tiny));  // truncates, still NUL terminated
  TEST_ASSERT_EQUAL_UINT32(2, got);
  TEST_ASSERT_EQUAL_STRING("ab", tiny);
  TEST_ASSERT_EQUAL_UINT32(0, fry::kv::encodeString("toolongforthis", blob, 4));  // refuses to truncate a write
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_flat_key_joins_ns_and_key_with_a_dot);
  RUN_TEST(test_every_fry_config_key_fits_nvs_parity_limits);
  RUN_TEST(test_rejects_overlong_empty_or_bad_characters);
  RUN_TEST(test_distinct_pairs_never_collide);
  RUN_TEST(test_namespace_membership_for_clear);
  RUN_TEST(test_file_name_for_littlefs);
  RUN_TEST(test_u32_codec_roundtrip_and_defaults);
  RUN_TEST(test_string_codec_is_nul_terminated_and_bounded);
  return UNITY_END();
}
