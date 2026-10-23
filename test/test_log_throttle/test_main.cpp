// shouldLogState (lib/fry_core/log_throttle.*): one line when a polled state CHANGES, otherwise at
// most one line per interval. Pins the rule that replaced the per-attempt "wg: no VPN config -
// skipping" print (9 lines in 54 s, capture e32-a3b-224212) and caps the WG deferral line.
#include <unity.h>

#include <cstdint>

#include "log_throttle.h"

namespace {

void test_the_first_observation_always_logs() {
  fry::LogThrottle t;
  TEST_ASSERT_TRUE(fry::shouldLogState(t, /*state=*/1, /*nowMs=*/0, fry::kLogStateMinIntervalMs));
}

void test_the_same_state_within_the_interval_is_silent() {
  fry::LogThrottle t;
  TEST_ASSERT_TRUE(fry::shouldLogState(t, 1, 1000, fry::kLogStateMinIntervalMs));
  TEST_ASSERT_FALSE(fry::shouldLogState(t, 1, 2000, fry::kLogStateMinIntervalMs));
  TEST_ASSERT_FALSE(fry::shouldLogState(t, 1, 1000 + fry::kLogStateMinIntervalMs - 1,
                                        fry::kLogStateMinIntervalMs));
}

void test_the_interval_itself_logs() {
  fry::LogThrottle t;
  TEST_ASSERT_TRUE(fry::shouldLogState(t, 1, 1000, fry::kLogStateMinIntervalMs));
  TEST_ASSERT_TRUE(fry::shouldLogState(t, 1, 1000 + fry::kLogStateMinIntervalMs,
                                       fry::kLogStateMinIntervalMs));
  // And the new line restarts the interval.
  TEST_ASSERT_FALSE(fry::shouldLogState(t, 1, 2000 + fry::kLogStateMinIntervalMs,
                                        fry::kLogStateMinIntervalMs));
}

void test_a_state_change_logs_immediately_even_inside_the_interval() {
  fry::LogThrottle t;
  TEST_ASSERT_TRUE(fry::shouldLogState(t, 1, 1000, fry::kLogStateMinIntervalMs));
  TEST_ASSERT_FALSE(fry::shouldLogState(t, 1, 1500, fry::kLogStateMinIntervalMs));
  TEST_ASSERT_TRUE(fry::shouldLogState(t, 2, 1600, fry::kLogStateMinIntervalMs));
  TEST_ASSERT_TRUE(fry::shouldLogState(t, 1, 1700, fry::kLogStateMinIntervalMs));  // and back
}

void test_the_interval_is_wrap_safe_on_a_32_bit_millisecond_counter() {
  fry::LogThrottle t;
  const uint32_t nearMax = 0xFFFFFFFFu - 1000u;  // millis() wraps ~49.7 days after boot
  TEST_ASSERT_TRUE(fry::shouldLogState(t, 7, nearMax, fry::kLogStateMinIntervalMs));
  // 2000 ms later, wrapped: the elapsed time is 2000, still inside the interval.
  TEST_ASSERT_FALSE(fry::shouldLogState(t, 7, static_cast<uint32_t>(nearMax + 2000u),
                                        fry::kLogStateMinIntervalMs));
  // A full interval later, wrapped: elapsed == interval, so it logs.
  TEST_ASSERT_TRUE(fry::shouldLogState(t, 7,
                                       static_cast<uint32_t>(nearMax + fry::kLogStateMinIntervalMs),
                                       fry::kLogStateMinIntervalMs));
}

void test_the_ten_minute_default_is_ten_minutes() {
  TEST_ASSERT_EQUAL_UINT32(600000u, fry::kLogStateMinIntervalMs);
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_first_observation_always_logs);
  RUN_TEST(test_the_same_state_within_the_interval_is_silent);
  RUN_TEST(test_the_interval_itself_logs);
  RUN_TEST(test_a_state_change_logs_immediately_even_inside_the_interval);
  RUN_TEST(test_the_interval_is_wrap_safe_on_a_32_bit_millisecond_counter);
  RUN_TEST(test_the_ten_minute_default_is_ten_minutes);
  return UNITY_END();
}
