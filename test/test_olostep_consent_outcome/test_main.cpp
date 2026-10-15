// Fail-closed decision for the Olostep opt-in write (lib/fry_core/olostep_consent_outcome.*).
#ifdef ARDUINO
#include <Arduino.h>
#endif
#include <unity.h>

#include <initializer_list>

#include "olostep_consent_outcome.h"

using fry_olostep::consentWriteOutcome;

void setUp() {}
void tearDown() {}

void test_successful_write_is_persisted_and_not_forced() {
  for (bool requested : {true, false}) {
    const auto o = consentWriteOutcome(true, 1, requested);
    TEST_ASSERT_TRUE(o.persisted);
    TEST_ASSERT_FALSE(o.mustForceDormant);
  }
}

void test_failed_off_write_when_storage_wont_open_forces_dormant() {
  const auto o = consentWriteOutcome(false, 0, false);
  TEST_ASSERT_FALSE(o.persisted);
  TEST_ASSERT_TRUE(o.mustForceDormant);
}

void test_failed_off_write_when_put_returns_zero_forces_dormant() {
  const auto o = consentWriteOutcome(true, 0, false);
  TEST_ASSERT_FALSE(o.persisted);
  TEST_ASSERT_TRUE(o.mustForceDormant);
}

void test_failed_on_write_is_not_persisted_and_needs_no_latch() {
  for (bool beginOk : {true, false}) {
    const auto o = consentWriteOutcome(beginOk, 0, true);
    TEST_ASSERT_FALSE(o.persisted);
    TEST_ASSERT_FALSE(o.mustForceDormant);
  }
}

void test_put_bytes_without_open_store_is_not_persisted() {
  const auto o = consentWriteOutcome(false, 1, false);
  TEST_ASSERT_FALSE(o.persisted);
  TEST_ASSERT_TRUE(o.mustForceDormant);
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_successful_write_is_persisted_and_not_forced);
  RUN_TEST(test_failed_off_write_when_storage_wont_open_forces_dormant);
  RUN_TEST(test_failed_off_write_when_put_returns_zero_forces_dormant);
  RUN_TEST(test_failed_on_write_is_not_persisted_and_needs_no_latch);
  RUN_TEST(test_put_bytes_without_open_store_is_not_persisted);
  return UNITY_END();
}
