// Consent rule for the Olostep opt-in write (lib/fry_core/olostep_optin.*): ON only from an
// encrypted link, OFF from any link, everything else ignored.
#ifdef ARDUINO
#include <Arduino.h>
#endif
#include <unity.h>

#include <initializer_list>

#include "olostep_optin.h"

using fry_olostep::olostepOptInWrite;
using fry_olostep::OptInWrite;

namespace {
const uint8_t kOn[] = {0x01};
const uint8_t kOff[] = {0x00};
}  // namespace

void test_on_from_an_encrypted_link_sets_on() {
  TEST_ASSERT_EQUAL((int)OptInWrite::SetOn, (int)olostepOptInWrite(kOn, 1, true));
}

void test_on_from_an_unencrypted_link_is_ignored() {
  TEST_ASSERT_EQUAL((int)OptInWrite::Ignore, (int)olostepOptInWrite(kOn, 1, false));
}

void test_off_is_accepted_on_any_link() {
  TEST_ASSERT_EQUAL((int)OptInWrite::SetOff, (int)olostepOptInWrite(kOff, 1, false));
  TEST_ASSERT_EQUAL((int)OptInWrite::SetOff, (int)olostepOptInWrite(kOff, 1, true));
}

void test_malformed_writes_are_ignored_on_both_links() {
  const uint8_t two[] = {0x01, 0x01};
  const uint8_t bad2[] = {0x02};
  const uint8_t badff[] = {0xFF};
  for (bool enc : {true, false}) {
    TEST_ASSERT_EQUAL((int)OptInWrite::Ignore, (int)olostepOptInWrite(kOn, 0, enc));
    TEST_ASSERT_EQUAL((int)OptInWrite::Ignore, (int)olostepOptInWrite(nullptr, 1, enc));
    TEST_ASSERT_EQUAL((int)OptInWrite::Ignore, (int)olostepOptInWrite(two, 2, enc));
    TEST_ASSERT_EQUAL((int)OptInWrite::Ignore, (int)olostepOptInWrite(bad2, 1, enc));
    TEST_ASSERT_EQUAL((int)OptInWrite::Ignore, (int)olostepOptInWrite(badff, 1, enc));
  }
}

void setUp() {}

void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_on_from_an_encrypted_link_sets_on);
  RUN_TEST(test_on_from_an_unencrypted_link_is_ignored);
  RUN_TEST(test_off_is_accepted_on_any_link);
  RUN_TEST(test_malformed_writes_are_ignored_on_both_links);
  return UNITY_END();
}
