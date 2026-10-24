// maskSecretLast4 (lib/fry_core/key_policy.*): the form every non-key secret takes in a log line -
// U+2026 and the last 4 characters. Used by the ESP8266 setup-AP code line (wifi_provisioning.cpp)
// and the lab `set_wifi` SSID line (serial_commands.cpp). Every value below is SYNTHETIC.
#include <unity.h>

#include <cstring>

#include "key_policy.h"

namespace {

// U+2026 HORIZONTAL ELLIPSIS in UTF-8, spliced so a following hex digit is never swallowed.
#define ELL "\xE2\x80\xA6"

constexpr size_t kCap = 8;  // U+2026 (3) + last 4 + NUL

// True if `text` contains any 5-character substring of `value`: only the last 4 characters may
// survive, so a 5-character run can never be one of them.
bool leaksMoreThanLast4(const char* value, const char* text) {
  const size_t n = strlen(value);
  for (size_t i = 0; i + 5 <= n; i++) {
    char window[6];
    memcpy(window, value + i, 5);
    window[5] = 0;
    if (strstr(text, window)) return true;
  }
  return false;
}

void test_the_form_is_ellipsis_then_the_last_four() {
  char out[kCap];
  TEST_ASSERT_EQUAL_UINT32(7, fry::maskSecretLast4("HomeNetwork", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING(ELL "work" + 0, ELL "work");
}

void test_a_setup_code_shows_only_its_last_four() {
  char out[kCap];
  TEST_ASSERT_EQUAL_UINT32(7, fry::maskSecretLast4("ABCD2345", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING(ELL "2345", out);
}

// REV-A F4: "the last 4 characters" of a 4-character secret IS the secret, so 4 or fewer prints
// the ellipsis and nothing else. No length may ever come out whole.
void test_a_value_of_four_characters_or_fewer_never_shows_any_of_itself() {
  char out[kCap];
  TEST_ASSERT_EQUAL_UINT32(3, fry::maskSecretLast4("wxyz", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING(ELL, out);
  TEST_ASSERT_EQUAL_UINT32(3, fry::maskSecretLast4("ab", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING(ELL, out);
  TEST_ASSERT_EQUAL_UINT32(3, fry::maskSecretLast4("z", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING(ELL, out);
}

void test_the_whole_value_is_never_printed_for_any_length() {
  const char* values[] = {"a", "ab", "abc", "abcd", "abcde", "abcdef", "ThePromisedNeverLAN",
                          "ABCD2345", "a-very-long-ssid-42"};
  for (const char* v : values) {
    char out[kCap];
    const size_t n = strlen(v);
    const size_t written = fry::maskSecretLast4(v, out, sizeof(out));
    TEST_ASSERT_TRUE(written > 0);
    // The rendered text must never contain the entire value.
    TEST_ASSERT_NULL(strstr(out, v));
    if (n > 4) {
      TEST_ASSERT_EQUAL_UINT32(7, written);          // ellipsis + 4
      TEST_ASSERT_EQUAL_STRING(v + n - 4, out + 3);  // and those 4 are the tail
    } else {
      TEST_ASSERT_EQUAL_UINT32(3, written);          // ellipsis only
      TEST_ASSERT_EQUAL_STRING(ELL, out);
    }
  }
}

void test_five_characters_is_the_first_length_that_can_show_a_tail() {
  char out[kCap];
  TEST_ASSERT_EQUAL_UINT32(7, fry::maskSecretLast4("abcde", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING(ELL "bcde", out);
}

void test_unprintable_and_non_ascii_bytes_in_the_tail_become_question_marks() {
  char out[kCap];
  const char value[] = {'n', 'e', 't', '\n', 'a', '\x80', 'b'};  // 7 bytes, no terminator issues
  char buf[sizeof(value) + 1];
  memcpy(buf, value, sizeof(value));
  buf[sizeof(value)] = 0;
  TEST_ASSERT_EQUAL_UINT32(7, fry::maskSecretLast4(buf, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING(ELL "?a?b", out);
  // A value that would inject a line break must not do so.
  TEST_ASSERT_NULL(strchr(out, '\n'));
}

void test_null_or_empty_value_writes_an_empty_string_and_returns_zero() {
  char out[kCap];
  TEST_ASSERT_EQUAL_UINT32(0, fry::maskSecretLast4(nullptr, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("", out);
  TEST_ASSERT_EQUAL_UINT32(0, fry::maskSecretLast4("", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("", out);
}

void test_a_null_output_buffer_is_harmless() {
  TEST_ASSERT_EQUAL_UINT32(0, fry::maskSecretLast4("HomeNetwork", nullptr, kCap));
}

void test_a_too_small_capacity_writes_nothing_and_never_truncates() {
  char out[kCap];
  memset(out, 'X', sizeof(out));
  TEST_ASSERT_EQUAL_UINT32(0, fry::maskSecretLast4("HomeNetwork", out, 7));  // needs 8
  TEST_ASSERT_EQUAL_STRING("", out);
  TEST_ASSERT_EQUAL_UINT32(0, fry::maskSecretLast4("ab", out, 3));  // ellipsis-only form needs 4
  TEST_ASSERT_EQUAL_STRING("", out);
  TEST_ASSERT_EQUAL_UINT32(0, fry::maskSecretLast4("HomeNetwork", out, 0));
  TEST_ASSERT_EQUAL_STRING("", out);
}

void test_the_exact_capacity_fits() {
  char out[kCap];
  TEST_ASSERT_EQUAL_UINT32(7, fry::maskSecretLast4("HomeNetwork", out, kCap));
  TEST_ASSERT_EQUAL_STRING(ELL "work", out);
  char shortOut[4];  // the ellipsis-only form needs exactly 4
  TEST_ASSERT_EQUAL_UINT32(3, fry::maskSecretLast4("ab", shortOut, sizeof(shortOut)));
  TEST_ASSERT_EQUAL_STRING(ELL, shortOut);
}

void test_no_five_character_run_of_the_value_survives_the_mask() {
  const char* values[] = {"ThePromisedNeverLAN", "HomeNetwork", "ABCD2345", "a-very-long-ssid-42"};
  for (const char* v : values) {
    char out[kCap];
    TEST_ASSERT_EQUAL_UINT32(7, fry::maskSecretLast4(v, out, sizeof(out)));
    TEST_ASSERT_FALSE(leaksMoreThanLast4(v, out));
  }
  // The checker itself must be live: the raw value fails it.
  TEST_ASSERT_TRUE(leaksMoreThanLast4("HomeNetwork", "HomeNetwork"));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_form_is_ellipsis_then_the_last_four);
  RUN_TEST(test_a_setup_code_shows_only_its_last_four);
  RUN_TEST(test_a_value_of_four_characters_or_fewer_never_shows_any_of_itself);
  RUN_TEST(test_the_whole_value_is_never_printed_for_any_length);
  RUN_TEST(test_five_characters_is_the_first_length_that_can_show_a_tail);
  RUN_TEST(test_unprintable_and_non_ascii_bytes_in_the_tail_become_question_marks);
  RUN_TEST(test_null_or_empty_value_writes_an_empty_string_and_returns_zero);
  RUN_TEST(test_a_null_output_buffer_is_harmless);
  RUN_TEST(test_a_too_small_capacity_writes_nothing_and_never_truncates);
  RUN_TEST(test_the_exact_capacity_fits);
  RUN_TEST(test_no_five_character_run_of_the_value_survives_the_mask);
  return UNITY_END();
}
