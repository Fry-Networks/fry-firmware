// sanitizeServerDetailLast4 (lib/fry_core/reg_result.*): the server's own "detail"/"error" words as
// the registration log line quotes them (src/core/hardwareapi_client.cpp readServerDetail). Same
// rules as sanitizeServerDetail - 120-byte cap, printable ASCII, quote/backslash/control mapping -
// but every key-shaped token becomes FEM-<U+2026>last4 (key_policy.h maskMinerKeyLast4), so the log
// never shows more of a key than its last 4 characters. sanitizeServerDetail itself is pinned by
// test_reg_error_map and stays as it is. Every key below is SYNTHETIC - never a real miner key.
#include <unity.h>

#include <cstdio>
#include <cstring>

#include "reg_result.h"

namespace {

// U+2026 HORIZONTAL ELLIPSIS in UTF-8; spliced between adjacent literals so a following hex digit
// is never swallowed by the \x escape.
#define ELL "\xE2\x80\xA6"

const char kFakeKey[] = "FEM-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
const char kBase36Key[] = "FEM-TESTKEY0000000000000000000000001";
const char kUpperHexKey[] = "FEM-0123456789ABCDEF0123456789ABCDEF";
const char kLegacyKey[] = "IOT-0123456789abcdef0123456789abcdef";

// True if `text` holds ANY 5-character run of `key` (only the last 4 characters alone never do).
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

// The only bytes the log line may carry: printable ASCII, and the complete 3-byte U+2026. A cut
// ellipsis (E2, E2 80, ...) or any stray high byte fails.
bool isCleanLogText(const char* s) {
  for (size_t i = 0; s[i];) {
    const unsigned char c = static_cast<unsigned char>(s[i]);
    if (c >= 0x20 && c <= 0x7E) {
      i++;
    } else if (c == 0xE2 && static_cast<unsigned char>(s[i + 1]) == 0x80 &&
               static_cast<unsigned char>(s[i + 2]) == 0xA6) {
      i += 3;
    } else {
      return false;
    }
  }
  return true;
}

// ---- same rules as sanitizeServerDetail --------------------------------------------------------

void test_plain_text_passes_through_like_the_original() {
  char out[160];
  const size_t n = fry::sanitizeServerDetailLast4("key not registered", "", out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("key not registered", out);
  TEST_ASSERT_EQUAL_size_t(18, n);
}

void test_quotes_backslashes_and_control_bytes_are_mapped_like_the_original() {
  char out[160];
  fry::sanitizeServerDetailLast4("bad \"x\"\\\n\ty\xC3\xA9", "", out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("bad 'x'/??y??", out);
}

void test_a_short_prefixed_word_is_not_key_shaped() {
  // FEM-/IOT- followed by fewer than 8 alphanumerics is not a key: left alone, as in the original
  char out[160];
  fry::sanitizeServerDetailLast4("FEM-ABC and IOT-1234567", "", out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("FEM-ABC and IOT-1234567", out);
}

void test_null_input_and_degenerate_buffers_are_safe() {
  char out[8];
  memset(out, 'x', sizeof(out));
  TEST_ASSERT_EQUAL_size_t(0, fry::sanitizeServerDetailLast4(nullptr, "", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("", out);
  TEST_ASSERT_EQUAL_size_t(0, fry::sanitizeServerDetailLast4("abc", "", nullptr, 8));
  memset(out, 'x', sizeof(out));
  TEST_ASSERT_EQUAL_size_t(0, fry::sanitizeServerDetailLast4("abc", "", out, 0));
  TEST_ASSERT_EQUAL_HEX8('x', out[0]);  // capacity 0: nothing written
  TEST_ASSERT_EQUAL_size_t(0, fry::sanitizeServerDetailLast4("abc", "", out, 1));
  TEST_ASSERT_EQUAL_STRING("", out);
  TEST_ASSERT_EQUAL_size_t(2, fry::sanitizeServerDetailLast4("abc", "", out, 3));
  TEST_ASSERT_EQUAL_STRING("ab", out);
}

void test_plain_text_is_cut_at_120_bytes() {
  char longIn[300];
  memset(longIn, 'a', sizeof(longIn) - 1);
  longIn[sizeof(longIn) - 1] = 0;
  char out[300];
  TEST_ASSERT_EQUAL_size_t(120, fry::sanitizeServerDetailLast4(longIn, "", out, sizeof(out)));
  TEST_ASSERT_EQUAL_size_t(120, strlen(out));
}

// ---- key-shaped tokens become FEM-<U+2026>last4 ------------------------------------------------

void test_the_devices_own_key_is_masked_to_last4() {
  char out[160];
  fry::sanitizeServerDetailLast4("FEM-TESTKEY0000000000000000000000001 is active elsewhere",
                                 kBase36Key, out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("FEM-" ELL "0001 is active elsewhere", out);
  fry::sanitizeServerDetailLast4("key FEM-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345.", kFakeKey, out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("key FEM-" ELL "2345.", out);
}

void test_a_fem_token_that_is_not_the_devices_key_is_masked_the_same_way() {
  char out[160];
  fry::sanitizeServerDetailLast4("owner FEM-0123456789ABCDEF0123456789ABCDEF holds it", kBase36Key, out,
                                 sizeof(out));
  TEST_ASSERT_EQUAL_STRING("owner FEM-" ELL "CDEF holds it", out);
  fry::sanitizeServerDetailLast4(kUpperHexKey, "", out, sizeof(out));  // no own key known at all
  TEST_ASSERT_EQUAL_STRING("FEM-" ELL "CDEF", out);
}

void test_a_legacy_iot_token_is_masked_to_last4() {
  char out[160];
  fry::sanitizeServerDetailLast4("legacy IOT-0123456789abcdef0123456789abcdef refused", "", out,
                                 sizeof(out));
  TEST_ASSERT_EQUAL_STRING("legacy IOT-" ELL "cdef refused", out);
}

void test_every_token_in_one_detail_is_masked() {
  char out[160];
  const char in[] = "FEM-0123456789ABCDEF0123456789ABCDEF vs IOT-0123456789abcdef0123456789abcdef";
  fry::sanitizeServerDetailLast4(in, "", out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("FEM-" ELL "CDEF vs IOT-" ELL "cdef", out);
}

void test_a_key_of_an_unknown_shape_is_masked_without_its_first_characters() {
  char out[160];
  const char odd[] = "abcdEFGHIJKLMNOP";  // the stored key, whatever its shape, is masked wherever it appears
  fry::sanitizeServerDetailLast4("echo abcdEFGHIJKLMNOP end", odd, out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("echo " ELL "MNOP end", out);
  const char eight[] = "abcdefgh";  // the original treats a stored key of 8+ characters as a token
  fry::sanitizeServerDetailLast4("echo abcdefgh end", eight, out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("echo " ELL " end", out);
}

void test_the_original_is_unchanged_and_would_fail_the_leak_check() {
  // control: the original keeps 2 characters of the key body, which the 5-character-run check flags
  char out[160];
  fry::sanitizeServerDetail("FEM-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", kFakeKey, out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("FEM-AB...", out);
  TEST_ASSERT_TRUE(leaksMoreThanLast4(kFakeKey, out));
  fry::sanitizeServerDetailLast4("FEM-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", kFakeKey, out, sizeof(out));
  TEST_ASSERT_FALSE(leaksMoreThanLast4(kFakeKey, out));
  TEST_ASSERT_TRUE(isCleanLogText(out));
}

void test_no_five_char_run_of_any_key_survives() {
  const char* keys[] = {kFakeKey, kBase36Key, kUpperHexKey, kLegacyKey};
  for (const char* key : keys) {
    char in[200];
    snprintf(in, sizeof(in), "registration refused for %s, retry with another key (%s)", key, key);
    char out[200];
    fry::sanitizeServerDetailLast4(in, key, out, sizeof(out));
    TEST_ASSERT_FALSE_MESSAGE(leaksMoreThanLast4(key, out), key);
    TEST_ASSERT_TRUE_MESSAGE(isCleanLogText(out), key);
  }
}

// ---- the cap: the 3-byte ellipsis is never split -----------------------------------------------

void test_a_mask_that_fits_exactly_at_the_cap_is_kept_whole() {
  // 109 plain bytes + the 11-byte mask = 120 = the cap
  char in[200];
  memset(in, 'a', 109);
  strcpy(in + 109, kFakeKey);
  char out[200];
  const size_t n = fry::sanitizeServerDetailLast4(in, kFakeKey, out, sizeof(out));
  TEST_ASSERT_EQUAL_size_t(120, n);
  TEST_ASSERT_EQUAL_size_t(120, strlen(out));
  TEST_ASSERT_EQUAL_STRING("FEM-" ELL "2345", out + 109);
}

void test_a_mask_that_does_not_fit_ends_the_output_before_it() {
  // 110 plain bytes leave 10 of 120: the 11-byte mask is dropped whole, never cut to "FEM-<E2 80>"
  char in[200];
  memset(in, 'a', 110);
  strcpy(in + 110, kFakeKey);
  char out[200];
  const size_t n = fry::sanitizeServerDetailLast4(in, kFakeKey, out, sizeof(out));
  TEST_ASSERT_EQUAL_size_t(110, n);
  TEST_ASSERT_EQUAL_size_t(110, strlen(out));
  TEST_ASSERT_NULL(strchr(out, '\xE2'));
  TEST_ASSERT_NULL(strstr(out, "FEM"));
}

void test_every_cut_position_leaves_clean_text_and_no_key() {
  // Slide the key across the 120-byte cap (output buffer big enough), then across a small buffer
  // (outCap 21 -> cap 20, 19, ...): at every offset the output is printable ASCII plus whole
  // ellipses only, within the cap, and holds no 5-character run of the key.
  const size_t outCaps[] = {200, 21, 12, 13, 14, 15};
  for (size_t outCap : outCaps) {
    const size_t cap = (outCap - 1) < 120 ? (outCap - 1) : 120;
    for (size_t pad = 0; pad <= 125; pad++) {
      char in[300];
      memset(in, 'a', pad);
      snprintf(in + pad, sizeof(in) - pad, "%s tail", kFakeKey);
      char out[200];
      const size_t n = fry::sanitizeServerDetailLast4(in, kFakeKey, out, outCap);
      TEST_ASSERT_EQUAL_size_t(strlen(out), n);
      TEST_ASSERT_TRUE(n <= cap);
      TEST_ASSERT_TRUE(isCleanLogText(out));
      TEST_ASSERT_FALSE(leaksMoreThanLast4(kFakeKey, out));
      // the mask is either whole or absent
      const bool hasEll = strstr(out, ELL) != nullptr;
      const bool hasPrefix = strstr(out, "FEM-") != nullptr;
      TEST_ASSERT_EQUAL(hasEll, hasPrefix);
      if (hasEll) TEST_ASSERT_NOT_NULL(strstr(out, "FEM-" ELL "2345"));
    }
  }
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_plain_text_passes_through_like_the_original);
  RUN_TEST(test_quotes_backslashes_and_control_bytes_are_mapped_like_the_original);
  RUN_TEST(test_a_short_prefixed_word_is_not_key_shaped);
  RUN_TEST(test_null_input_and_degenerate_buffers_are_safe);
  RUN_TEST(test_plain_text_is_cut_at_120_bytes);
  RUN_TEST(test_the_devices_own_key_is_masked_to_last4);
  RUN_TEST(test_a_fem_token_that_is_not_the_devices_key_is_masked_the_same_way);
  RUN_TEST(test_a_legacy_iot_token_is_masked_to_last4);
  RUN_TEST(test_every_token_in_one_detail_is_masked);
  RUN_TEST(test_a_key_of_an_unknown_shape_is_masked_without_its_first_characters);
  RUN_TEST(test_the_original_is_unchanged_and_would_fail_the_leak_check);
  RUN_TEST(test_no_five_char_run_of_any_key_survives);
  RUN_TEST(test_a_mask_that_fits_exactly_at_the_cap_is_kept_whole);
  RUN_TEST(test_a_mask_that_does_not_fit_ends_the_output_before_it);
  RUN_TEST(test_every_cut_position_leaves_clean_text_and_no_key);
  return UNITY_END();
}
