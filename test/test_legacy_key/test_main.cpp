// A real board on the bench is running v0.3.1 with a key generated before the 2026-09-18 prefix
// change, and isValidMinerKey now rejects that prefix outright. Boards in that state must be
// carried over rather than re-keyed: the hex digits ARE the device's identity on the dashboard,
// so migration may only rewrite the four-character prefix and must never invent a new key.
// These tests pin the pure half of that (src/core/miner_key.cpp does the persisting).
#ifdef ARDUINO
#include <Arduino.h>
#endif
#include <unity.h>

#include <cstring>

#include "miner_identity.h"

using fry::isLegacyMinerKey;
using fry::isValidMinerKey;
using fry::migrateLegacyMinerKey;

namespace {

const char kLegacyUpper[] = "IOT-3A4500E6501DE12F2BFDEF0507B5E87C";  // the key on the bench board
const char kLegacyLower[] = "IOT-3a4500e6501de12f2bfdef0507b5e87c";

// Fills a buffer with a sentinel so "left untouched" is an assertion and not an assumption.
void poison(char* buf, size_t len) { memset(buf, '?', len - 1); buf[len - 1] = 0; }

bool untouched(const char* buf, size_t len) {
  for (size_t i = 0; i + 1 < len; i++) {
    if (buf[i] != '?') return false;
  }
  return buf[len - 1] == 0;
}

void test_legacy_key_is_recognised(void) {
  TEST_ASSERT_TRUE(isLegacyMinerKey(kLegacyUpper));
  TEST_ASSERT_TRUE(isLegacyMinerKey(kLegacyLower));
  TEST_ASSERT_FALSE(isLegacyMinerKey("FEM-3A4500E6501DE12F2BFDEF0507B5E87C"));
  TEST_ASSERT_FALSE(isLegacyMinerKey(nullptr));
}

void test_migrates_the_prefix_and_keeps_the_hex(void) {
  char out[40];
  poison(out, sizeof(out));
  TEST_ASSERT_TRUE(migrateLegacyMinerKey(kLegacyUpper, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("FEM-3A4500E6501DE12F2BFDEF0507B5E87C", out);
  // Same 32 hex digits, only the prefix moved.
  TEST_ASSERT_EQUAL_STRING(kLegacyUpper + 4, out + 4);
  // And the result is a key the rest of the firmware will accept.
  TEST_ASSERT_TRUE(isValidMinerKey(out));
}

void test_an_already_migrated_key_is_refused_and_out_is_untouched(void) {
  char out[40];
  poison(out, sizeof(out));
  TEST_ASSERT_FALSE(migrateLegacyMinerKey("FEM-3A4500E6501DE12F2BFDEF0507B5E87C", out, sizeof(out)));
  TEST_ASSERT_TRUE(untouched(out, sizeof(out)));
}

void test_lowercase_hex_is_accepted_with_its_case_preserved(void) {
  char out[40];
  poison(out, sizeof(out));
  TEST_ASSERT_TRUE(migrateLegacyMinerKey(kLegacyLower, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("FEM-3a4500e6501de12f2bfdef0507b5e87c", out);
  TEST_ASSERT_EQUAL_STRING(kLegacyLower + 4, out + 4);
}

void test_wrong_length_hex_is_rejected(void) {
  char out[40];
  poison(out, sizeof(out));
  TEST_ASSERT_FALSE(migrateLegacyMinerKey("IOT-3A4500E6501DE12F2BFDEF0507B5E87", out, sizeof(out)));   // 31
  TEST_ASSERT_FALSE(migrateLegacyMinerKey("IOT-3A4500E6501DE12F2BFDEF0507B5E87CD", out, sizeof(out)));  // 33
  TEST_ASSERT_FALSE(migrateLegacyMinerKey("IOT-", out, sizeof(out)));
  TEST_ASSERT_TRUE(untouched(out, sizeof(out)));
}

void test_non_hex_and_null_are_rejected(void) {
  char out[40];
  poison(out, sizeof(out));
  TEST_ASSERT_FALSE(migrateLegacyMinerKey("IOT-3A4500E6501DE12F2BFDEF0507B5E87G", out, sizeof(out)));
  TEST_ASSERT_FALSE(migrateLegacyMinerKey("IOT-3A4500E6501DE12F2BFDEF0507B5E87 ", out, sizeof(out)));
  TEST_ASSERT_FALSE(migrateLegacyMinerKey("XXX-3A4500E6501DE12F2BFDEF0507B5E87C", out, sizeof(out)));
  TEST_ASSERT_FALSE(migrateLegacyMinerKey(nullptr, out, sizeof(out)));
  TEST_ASSERT_TRUE(untouched(out, sizeof(out)));
}

void test_a_buffer_one_byte_short_is_refused(void) {
  char out[40];
  poison(out, sizeof(out));
  // 37 = "FEM-" + 32 hex + NUL. 36 would produce an unterminated or truncated key, so it fails
  // rather than writing anything.
  TEST_ASSERT_FALSE(migrateLegacyMinerKey(kLegacyUpper, out, 36));
  TEST_ASSERT_TRUE(untouched(out, sizeof(out)));
  TEST_ASSERT_TRUE(migrateLegacyMinerKey(kLegacyUpper, out, 37));
  TEST_ASSERT_EQUAL_STRING("FEM-3A4500E6501DE12F2BFDEF0507B5E87C", out);
}

void test_migration_is_not_repeatable(void) {
  // Boot-loop safety: the second pass over an already-migrated key must refuse, so a board that
  // reboots mid-migration converges instead of rewriting its identity again.
  char once[40];
  char twice[40];
  poison(once, sizeof(once));
  poison(twice, sizeof(twice));
  TEST_ASSERT_TRUE(migrateLegacyMinerKey(kLegacyUpper, once, sizeof(once)));
  TEST_ASSERT_FALSE(migrateLegacyMinerKey(once, twice, sizeof(twice)));
  TEST_ASSERT_TRUE(untouched(twice, sizeof(twice)));
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}

void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_legacy_key_is_recognised);
  RUN_TEST(test_migrates_the_prefix_and_keeps_the_hex);
  RUN_TEST(test_an_already_migrated_key_is_refused_and_out_is_untouched);
  RUN_TEST(test_lowercase_hex_is_accepted_with_its_case_preserved);
  RUN_TEST(test_wrong_length_hex_is_rejected);
  RUN_TEST(test_non_hex_and_null_are_rejected);
  RUN_TEST(test_a_buffer_one_byte_short_is_refused);
  RUN_TEST(test_migration_is_not_repeatable);
  return UNITY_END();
}
