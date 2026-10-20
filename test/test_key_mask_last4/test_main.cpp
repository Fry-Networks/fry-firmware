// maskMinerKeyLast4 (lib/fry_core/key_policy.*): the only form of the miner key any LOG line may
// show - "FEM-" + U+2026 + the last 4 characters. The boot banner and the [identity] log lines use
// it; the older maskMinerKey (6 characters, pinned by test_key_policy) stays for the non-log
// surfaces. Every key below is SYNTHETIC - never a real miner key.
#include <unity.h>

#include <cstring>

#include "key_policy.h"

namespace {

// U+2026 HORIZONTAL ELLIPSIS in UTF-8, spliced between adjacent literals so a following hex digit
// is never swallowed by the \x escape.
#define ELL "\xE2\x80\xA6"

const char kFakeKey[] = "FEM-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";    // the operator's example, 36 chars
const char kBase36Key[] = "FEM-TESTKEY0000000000000000000000001";
const char kUpperHexKey[] = "FEM-0123456789ABCDEF0123456789ABCDEF";
const char kLowerHexKey[] = "FEM-0123456789abcdef0123456789abcdef";
const char kMixedKey[] = "FEM-TestKey0000000000000000000000002";
const char kLegacyKey[] = "IOT-0123456789ABCDEF0123456789ABCDEF";

constexpr size_t kFullCap = 12;  // "FEM-" 4 + U+2026 3 + last 4 = 11 bytes + NUL

// ---- a checker for "does this text leak more of the key than the last 4 characters" -----------
// True if `text` contains ANY 5-character substring of `key` (so the key's first 5 characters, a
// run through the middle and the 5 characters ending at the tail all count as leaks; only the last
// 4 characters on their own can never form a 5-character run).
bool leaksMoreThanLast4(const char* key, const char* text) {
  const size_t n = strlen(key);
  for (size_t i = 0; i + 5 <= n; i++) {
    char window[6];
    memcpy(window, key + i, 5);
    window[5] = 0;
    if (strstr(text, window)) return true;
  }
  return false;
}

// ---- exact shapes ------------------------------------------------------------------------------

void test_the_example_key_masks_to_fem_ellipsis_last4() {
  char out[kFullCap];
  TEST_ASSERT_EQUAL_size_t(11, fry::maskMinerKeyLast4(kFakeKey, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("FEM-" ELL "2345", out);
}

void test_every_minted_key_shape_masks_the_same_way() {
  char out[kFullCap];
  TEST_ASSERT_EQUAL_size_t(11, fry::maskMinerKeyLast4(kBase36Key, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("FEM-" ELL "0001", out);
  TEST_ASSERT_EQUAL_size_t(11, fry::maskMinerKeyLast4(kUpperHexKey, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("FEM-" ELL "CDEF", out);
  TEST_ASSERT_EQUAL_size_t(11, fry::maskMinerKeyLast4(kLowerHexKey, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("FEM-" ELL "cdef", out);
  TEST_ASSERT_EQUAL_size_t(11, fry::maskMinerKeyLast4(kMixedKey, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("FEM-" ELL "0002", out);
}

void test_a_legacy_key_keeps_its_public_prefix_and_last4() {
  char out[kFullCap];
  TEST_ASSERT_EQUAL_size_t(11, fry::maskMinerKeyLast4(kLegacyKey, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("IOT-" ELL "CDEF", out);
}

void test_a_dash_in_the_last4_is_printed_as_it_is() {
  // 36 characters, "FEM-" prefix, the tail is "-a-b".
  const char key[] = "FEM-ABCDEFGHIJKLMNOPQRSTUVWXYZ01-a-b";
  TEST_ASSERT_EQUAL_size_t(36, strlen(key));
  char out[kFullCap];
  TEST_ASSERT_EQUAL_size_t(11, fry::maskMinerKeyLast4(key, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("FEM-" ELL "-a-b", out);
}

void test_any_fem_prefixed_key_of_another_length_still_prints_the_same_form() {
  char out[kFullCap];
  TEST_ASSERT_EQUAL_size_t(11, fry::maskMinerKeyLast4("FEM-0123456789ABCDEF", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("FEM-" ELL "CDEF", out);
  TEST_ASSERT_EQUAL_size_t(
      11, fry::maskMinerKeyLast4("FEM-0123456789ABCDEF0123456789ABCDEF0123456789", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("FEM-" ELL "6789", out);
}

// ---- non-key / short / odd shapes --------------------------------------------------------------

void test_a_short_value_prints_only_an_ellipsis() {
  char out[kFullCap];
  TEST_ASSERT_EQUAL_size_t(3, fry::maskMinerKeyLast4("ABC", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING(ELL, out);
  TEST_ASSERT_EQUAL_size_t(3, fry::maskMinerKeyLast4("A", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING(ELL, out);
  // the compiled-in "FEM-PENDING" placeholder is 11 characters: the helper hides it like any short
  // value; the boot banner prints that exact placeholder itself (src/main.cpp)
  TEST_ASSERT_EQUAL_size_t(3, fry::maskMinerKeyLast4("FEM-PENDING", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING(ELL, out);
}

void test_eleven_and_twelve_characters_are_the_boundary() {
  char out[kFullCap];
  // 11 characters: ellipsis only; 12 characters: the last 4 appear
  TEST_ASSERT_EQUAL_size_t(3, fry::maskMinerKeyLast4("ABCDEFGHIJK", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING(ELL, out);
  TEST_ASSERT_EQUAL_size_t(7, fry::maskMinerKeyLast4("ABCDEFGHIJKL", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING(ELL "IJKL", out);
  // same boundary for a prefixed value
  TEST_ASSERT_EQUAL_size_t(3, fry::maskMinerKeyLast4("FEM-1234567", out, sizeof(out)));   // 11
  TEST_ASSERT_EQUAL_STRING(ELL, out);
  TEST_ASSERT_EQUAL_size_t(11, fry::maskMinerKeyLast4("FEM-12345678", out, sizeof(out)));  // 12
  TEST_ASSERT_EQUAL_STRING("FEM-" ELL "5678", out);
}

void test_a_value_without_a_known_prefix_never_shows_its_first_characters() {
  char out[kFullCap];
  TEST_ASSERT_EQUAL_size_t(7, fry::maskMinerKeyLast4("abcdEFGHIJKLMNOP", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING(ELL "MNOP", out);
  TEST_ASSERT_NULL(strstr(out, "abcd"));
}

void test_unprintable_bytes_in_the_last4_become_question_marks() {
  // a corrupt stored value must not be able to inject a line break or control byte into the log
  const char key[] = "FEM-ABCDEFGHIJKLMNOPQRSTUVWXYZ01\n\x01\xFF ";
  TEST_ASSERT_EQUAL_size_t(36, strlen(key));
  char out[kFullCap];
  TEST_ASSERT_EQUAL_size_t(11, fry::maskMinerKeyLast4(key, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("FEM-" ELL "????", out);
}

// ---- empty / NULL ------------------------------------------------------------------------------

void test_null_or_empty_key_writes_an_empty_string_and_returns_zero() {
  char out[kFullCap];
  memset(out, 'x', sizeof(out));
  TEST_ASSERT_EQUAL_size_t(0, fry::maskMinerKeyLast4(nullptr, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("", out);
  memset(out, 'x', sizeof(out));
  TEST_ASSERT_EQUAL_size_t(0, fry::maskMinerKeyLast4("", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("", out);
}

void test_a_null_output_buffer_is_harmless() {
  TEST_ASSERT_EQUAL_size_t(0, fry::maskMinerKeyLast4(kFakeKey, nullptr, 12));
  TEST_ASSERT_EQUAL_size_t(0, fry::maskMinerKeyLast4(nullptr, nullptr, 0));
}

// ---- output capacity ---------------------------------------------------------------------------

// A buffer of `cap` usable bytes followed by guard bytes; the helper must never touch the guards
// and, for cap > 0, must leave a NUL-terminated string.
struct Guarded {
  char buf[40];
};

void expectNoOverrun(const Guarded& g, size_t cap) {
  for (size_t i = cap; i < sizeof(g.buf); i++) {
    TEST_ASSERT_EQUAL_HEX8(0x5A, static_cast<unsigned char>(g.buf[i]));
  }
}

void test_capacity_zero_writes_nothing() {
  Guarded g;
  memset(g.buf, 0x5A, sizeof(g.buf));
  TEST_ASSERT_EQUAL_size_t(0, fry::maskMinerKeyLast4(kFakeKey, g.buf, 0));
  expectNoOverrun(g, 0);
}

void test_too_small_capacities_give_an_empty_string_and_never_truncate() {
  const size_t caps[] = {1, 2, 9, 10, 11};  // the full form needs 12
  for (size_t cap : caps) {
    Guarded g;
    memset(g.buf, 0x5A, sizeof(g.buf));
    TEST_ASSERT_EQUAL_size_t(0, fry::maskMinerKeyLast4(kFakeKey, g.buf, cap));
    TEST_ASSERT_EQUAL_STRING("", g.buf);  // terminated, and no half-written "FEM-" or split U+2026
    expectNoOverrun(g, cap);
  }
}

void test_the_exact_capacity_fits_and_one_more_is_fine() {
  Guarded g;
  memset(g.buf, 0x5A, sizeof(g.buf));
  TEST_ASSERT_EQUAL_size_t(11, fry::maskMinerKeyLast4(kFakeKey, g.buf, 12));
  TEST_ASSERT_EQUAL_STRING("FEM-" ELL "2345", g.buf);
  expectNoOverrun(g, 12);
  memset(g.buf, 0x5A, sizeof(g.buf));
  TEST_ASSERT_EQUAL_size_t(11, fry::maskMinerKeyLast4(kFakeKey, g.buf, 13));
  TEST_ASSERT_EQUAL_STRING("FEM-" ELL "2345", g.buf);
  expectNoOverrun(g, 13);
}

void test_the_short_forms_have_their_own_exact_capacity() {
  Guarded g;
  memset(g.buf, 0x5A, sizeof(g.buf));
  TEST_ASSERT_EQUAL_size_t(0, fry::maskMinerKeyLast4("ABC", g.buf, 3));  // ellipsis needs 4
  TEST_ASSERT_EQUAL_STRING("", g.buf);
  expectNoOverrun(g, 3);
  memset(g.buf, 0x5A, sizeof(g.buf));
  TEST_ASSERT_EQUAL_size_t(3, fry::maskMinerKeyLast4("ABC", g.buf, 4));
  TEST_ASSERT_EQUAL_STRING(ELL, g.buf);
  expectNoOverrun(g, 4);
  memset(g.buf, 0x5A, sizeof(g.buf));
  TEST_ASSERT_EQUAL_size_t(0, fry::maskMinerKeyLast4("abcdEFGHIJKLMNOP", g.buf, 7));  // needs 8
  TEST_ASSERT_EQUAL_STRING("", g.buf);
  expectNoOverrun(g, 7);
  memset(g.buf, 0x5A, sizeof(g.buf));
  TEST_ASSERT_EQUAL_size_t(7, fry::maskMinerKeyLast4("abcdEFGHIJKLMNOP", g.buf, 8));
  TEST_ASSERT_EQUAL_STRING(ELL "MNOP", g.buf);
  expectNoOverrun(g, 8);
}

// ---- the grep test: nothing but the last 4 characters of the key survives ----------------------

void test_the_checker_is_live_on_a_raw_key_and_on_the_old_six_char_mask() {
  // controls: a zero from the checker only means something if it can say "leak"
  TEST_ASSERT_TRUE(leaksMoreThanLast4(kFakeKey, kFakeKey));
  TEST_ASSERT_TRUE(leaksMoreThanLast4(kFakeKey, "FRY boot v0.4.8 chip=ESP32 mac=x minerkey=FEM-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"));
  char old6[16];
  TEST_ASSERT_EQUAL_size_t(9, fry::maskMinerKey(kFakeKey, old6, sizeof(old6)));  // "FEM-AB" + U+2026
  TEST_ASSERT_TRUE(leaksMoreThanLast4(kFakeKey, old6));  // "FEM-A" is a 5-char run of the key
  TEST_ASSERT_FALSE(leaksMoreThanLast4(kFakeKey, "2345"));  // the last 4 alone never form a run of 5
}

void test_no_five_char_run_of_any_key_survives_the_mask() {
  const char* keys[] = {kFakeKey,      kBase36Key,  kUpperHexKey,
                        kLowerHexKey,  kMixedKey,   kLegacyKey,
                        "FEM-0123456789ABCDEF0123456789ABCDEF0123456789",
                        "abcdEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                        "ABCDEFGHIJKL"};
  for (const char* key : keys) {
    char out[kFullCap];
    fry::maskMinerKeyLast4(key, out, sizeof(out));
    TEST_ASSERT_TRUE_MESSAGE(strlen(out) > 0, key);
    TEST_ASSERT_TRUE_MESSAGE(strlen(out) <= 11, key);
    TEST_ASSERT_FALSE_MESSAGE(leaksMoreThanLast4(key, out), key);
    // and the last 4 are exactly what is shown
    const size_t n = strlen(key);
    TEST_ASSERT_EQUAL_STRING(key + n - 4, out + strlen(out) - 4);
  }
}

void test_the_old_six_char_mask_is_unchanged() {
  // non-log surfaces (status snapshot, Improv key-write result, 8266 /status) keep using it
  char out[16];
  TEST_ASSERT_EQUAL_size_t(9, fry::maskMinerKey(kFakeKey, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("FEM-AB" ELL, out);
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_example_key_masks_to_fem_ellipsis_last4);
  RUN_TEST(test_every_minted_key_shape_masks_the_same_way);
  RUN_TEST(test_a_legacy_key_keeps_its_public_prefix_and_last4);
  RUN_TEST(test_a_dash_in_the_last4_is_printed_as_it_is);
  RUN_TEST(test_any_fem_prefixed_key_of_another_length_still_prints_the_same_form);
  RUN_TEST(test_a_short_value_prints_only_an_ellipsis);
  RUN_TEST(test_eleven_and_twelve_characters_are_the_boundary);
  RUN_TEST(test_a_value_without_a_known_prefix_never_shows_its_first_characters);
  RUN_TEST(test_unprintable_bytes_in_the_last4_become_question_marks);
  RUN_TEST(test_null_or_empty_key_writes_an_empty_string_and_returns_zero);
  RUN_TEST(test_a_null_output_buffer_is_harmless);
  RUN_TEST(test_capacity_zero_writes_nothing);
  RUN_TEST(test_too_small_capacities_give_an_empty_string_and_never_truncate);
  RUN_TEST(test_the_exact_capacity_fits_and_one_more_is_fine);
  RUN_TEST(test_the_short_forms_have_their_own_exact_capacity);
  RUN_TEST(test_the_checker_is_live_on_a_raw_key_and_on_the_old_six_char_mask);
  RUN_TEST(test_no_five_char_run_of_any_key_survives_the_mask);
  RUN_TEST(test_the_old_six_char_mask_is_unchanged);
  return UNITY_END();
}
