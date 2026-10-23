// The ESP8266 download's sha256 compare must not depend on an allocation (lib/fry_core/ota_sha_match.h).
//
// Before this change downloadAndApply() built two Strings and compared them. A String whose copy cannot get a buffer is the empty string, and two empty
// Strings are equal, so with the heap exhausted at the end of a stream (the sweeps passed with min_free down to 512 B) "got == want" held for ANY
// image and the Updater was committed. These tests model the core's String as far as that compare used it, show the old sequence accepting a wrong
// image, and show sha256HexMatches() rejecting it, accepting the right one, and holding its own contract over a grid of inputs. The source pins that
// ota_client.cpp calls it (and no longer builds the Strings on the ESP8266) are in test_ota_stage_guard (inspect()).
#include <unity.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include "ota_sha_match.h"

namespace {

// A model of the core's String (framework-arduinoespressif8266 3.30102.0, cores/esp8266/WString.cpp), only what the old compare used.
// A copy needing more than the SSO capacity (SSOSIZE 12 - 1 = 11 characters, WString.h:316,330) fails while the heap is full: copy() :273-277 sees
// reserve() fail and calls invalidate() :183-186, which leaves the empty string. equals() :542-544 is equal lengths and compareTo() == 0, and
// compareTo() :531-540 returns 0 for two empty strings.
bool g_heapFull = false;
constexpr size_t kSsoCapacity = 11;

class ModelString {
 public:
  ModelString() = default;
  explicit ModelString(const char* cstr) { copy(cstr, std::strlen(cstr)); }
  ModelString(const ModelString& v) { copy(v.v_.c_str(), v.v_.size()); }
  ModelString& operator=(const ModelString& rhs) {
    if (this != &rhs) copy(rhs.v_.c_str(), rhs.v_.size());
    return *this;
  }
  void toLowerCase() {
    for (char& c : v_) c = fry::asciiLowerChar(c);
  }
  bool operator!=(const ModelString& rhs) const { return !(v_.size() == rhs.v_.size() && v_ == rhs.v_); }
  size_t length() const { return v_.size(); }
  const char* c_str() const { return v_.c_str(); }

 private:
  void copy(const char* cstr, size_t n) {
    if (n > kSsoCapacity && g_heapFull) {
      v_.clear();  // invalidate()
      return;
    }
    v_.assign(cstr, n);
  }
  std::string v_;
};

// ota_client.cpp before this change, from `String got = hex;` to `if (got != want)`: true when the image would be accepted.
bool oldAccepts(const char* hexUpper, const ModelString& shaExpect) {
  ModelString got(hexUpper);
  got.toLowerCase();
  ModelString want = shaExpect;
  want.toLowerCase();
  return !(got != want);
}

// What the new code does with the same inputs (ota_client.cpp, ESP8266 view): hex is lowercased in place, then compared in place.
bool newAccepts(const char* hexUpper, const ModelString& shaExpect) {
  char hex[65];
  std::strncpy(hex, hexUpper, sizeof(hex) - 1);
  hex[64] = '\0';
  fry::asciiLowerInPlace(hex);
  return fry::sha256HexMatches(hex, shaExpect.c_str(), shaExpect.length());
}

// Two different 64-character digests (the foreign ESP32 image's digest from the field logs, and a made-up one), and the first in the manifest's case.
const char* const kDigestA_upper = "77F551EC0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234567";
const char* const kDigestA_lower = "77f551ec0123456789abcdef0123456789abcdef0123456789abcdef01234567";
const char* const kDigestB_lower = "9c5af7010123456789abcdef0123456789abcdef0123456789abcdef01234567";

// CONTROL: with the heap intact the old sequence is right (so the model is not what makes it fail below).
void test_old_compare_is_right_while_the_heap_holds() {
  const ModelString manifest(kDigestB_lower);
  TEST_ASSERT_FALSE_MESSAGE(oldAccepts(kDigestA_upper, manifest), "a wrong image is rejected while both copies succeed");
  const ModelString same(kDigestA_lower);
  TEST_ASSERT_TRUE_MESSAGE(oldAccepts(kDigestA_upper, same), "the right image is accepted");
}

// THE DEFECT: the manifest's digest String already exists (plan.sha); the heap is gone when the stream ends. Both copies fail, both are empty.
void test_old_compare_accepts_a_wrong_image_when_both_copies_fail() {
  const ModelString manifest(kDigestB_lower);  // allocated early (reserveEarly), long before the end of the stream
  g_heapFull = true;
  TEST_ASSERT_TRUE_MESSAGE(oldAccepts(kDigestA_upper, manifest), "the old sequence compares two empty Strings and calls a wrong image right");
}

// THE FIX, same inputs: a wrong image is rejected whether or not the heap is full, the right one is accepted either way.
void test_new_compare_rejects_the_same_wrong_image_with_the_heap_full() {
  const ModelString manifest(kDigestB_lower);
  const ModelString same(kDigestA_lower);  // both allocated while the heap still had room
  TEST_ASSERT_FALSE(newAccepts(kDigestA_upper, manifest));
  g_heapFull = true;
  TEST_ASSERT_FALSE_MESSAGE(newAccepts(kDigestA_upper, manifest), "no allocation, so no empty-String match");
  TEST_ASSERT_TRUE_MESSAGE(newAccepts(kDigestA_upper, same), "the right image is still accepted with the heap full");
}

// An expected String that is itself empty (its own allocation failed, or the manifest had no sha256) is a mismatch even if the digest copy fails too.
void test_new_compare_never_matches_an_empty_expected_digest() {
  const ModelString empty;
  TEST_ASSERT_FALSE(newAccepts(kDigestA_upper, empty));
  g_heapFull = true;
  const ModelString invalid(kDigestB_lower);  // built with the heap full: the empty String
  TEST_ASSERT_EQUAL_UINT32(0, static_cast<uint32_t>(invalid.length()));
  TEST_ASSERT_FALSE(newAccepts(kDigestA_upper, invalid));
  TEST_ASSERT_FALSE(fry::sha256HexMatches(kDigestA_lower, "", 0));
  TEST_ASSERT_FALSE(fry::sha256HexMatches(kDigestA_lower, nullptr, 0));
  TEST_ASSERT_FALSE(fry::sha256HexMatches(nullptr, kDigestA_lower, 64));
}

// The helper's contract: exactly 64 characters, equal ignoring ASCII case.
void test_helper_ignores_case_and_nothing_else() {
  TEST_ASSERT_TRUE(fry::sha256HexMatches(kDigestA_lower, kDigestA_lower, 64));
  TEST_ASSERT_TRUE(fry::sha256HexMatches(kDigestA_upper, kDigestA_lower, 64));
  TEST_ASSERT_TRUE(fry::sha256HexMatches(kDigestA_lower, kDigestA_upper, 64));
  // mixed case: every other hex letter upper
  std::string mixed = kDigestA_lower;
  for (size_t i = 0; i < mixed.size(); i += 2) {
    if (mixed[i] >= 'a' && mixed[i] <= 'f') mixed[i] = static_cast<char>(mixed[i] - ('a' - 'A'));
  }
  TEST_ASSERT_TRUE(fry::sha256HexMatches(kDigestA_lower, mixed.c_str(), 64));
  TEST_ASSERT_TRUE(fry::sha256HexMatches(kDigestA_upper, mixed.c_str(), 64));
}

void test_helper_rejects_a_difference_at_every_position() {
  for (size_t i = 0; i < 64; ++i) {
    std::string bad = kDigestA_lower;
    bad[i] = bad[i] == '0' ? '1' : '0';
    TEST_ASSERT_FALSE_MESSAGE(fry::sha256HexMatches(kDigestA_lower, bad.c_str(), 64), "one differing character");
    TEST_ASSERT_FALSE_MESSAGE(fry::sha256HexMatches(kDigestA_upper, bad.c_str(), 64), "one differing character, other case");
  }
}

void test_helper_needs_exactly_64_characters_on_both_sides() {
  const std::string longer = std::string(kDigestA_lower) + "0";
  TEST_ASSERT_FALSE_MESSAGE(fry::sha256HexMatches(kDigestA_lower, longer.c_str(), 65), "65 characters whose first 64 match");
  const std::string shorter = std::string(kDigestA_lower).substr(0, 63);
  TEST_ASSERT_FALSE_MESSAGE(fry::sha256HexMatches(kDigestA_lower, shorter.c_str(), 63), "63 characters that are a prefix");
  TEST_ASSERT_FALSE_MESSAGE(fry::sha256HexMatches(kDigestA_lower, shorter.c_str(), 62), "62 characters that are a prefix");
  // the computed side: a 63- or 65-character 'digest' is never accepted
  TEST_ASSERT_FALSE(fry::sha256HexMatches(shorter.c_str(), kDigestA_lower, 64));
  TEST_ASSERT_FALSE(fry::sha256HexMatches(longer.c_str(), kDigestA_lower, 64));
  // an embedded NUL in the expected digest is a difference, not an end of string
  std::string nul = kDigestA_lower;
  nul[10] = '\0';
  TEST_ASSERT_FALSE(fry::sha256HexMatches(kDigestA_lower, nul.data(), 64));
  // ...and a computed 'digest' that ends early is not a digest even when the expected one has a NUL at the same place
  TEST_ASSERT_FALSE(fry::sha256HexMatches(nul.c_str(), nul.data(), 64));
  // only A-Z fold: a high-bit byte is not the letter it is 0x80 away from, and '@' (0x40) is not '`' (0x60)
  std::string hi = kDigestA_lower;
  hi[8] = static_cast<char>(hi[8] ^ 0x80);
  TEST_ASSERT_FALSE(fry::sha256HexMatches(kDigestA_lower, hi.c_str(), 64));
  std::string at = kDigestA_lower;
  at[0] = '@';
  std::string tick = kDigestA_lower;
  tick[0] = '`';
  TEST_ASSERT_FALSE(fry::sha256HexMatches(at.c_str(), tick.c_str(), 64));
}

}  // namespace

// Unity's hooks must be at global scope; the heap model is off at the start and the end of every test.
void setUp() { g_heapFull = false; }
void tearDown() { g_heapFull = false; }

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_old_compare_is_right_while_the_heap_holds);
  RUN_TEST(test_old_compare_accepts_a_wrong_image_when_both_copies_fail);
  RUN_TEST(test_new_compare_rejects_the_same_wrong_image_with_the_heap_full);
  RUN_TEST(test_new_compare_never_matches_an_empty_expected_digest);
  RUN_TEST(test_helper_ignores_case_and_nothing_else);
  RUN_TEST(test_helper_rejects_a_difference_at_every_position);
  RUN_TEST(test_helper_needs_exactly_64_characters_on_both_sides);
  return UNITY_END();
}
