// fry::ntpRestartDue (lib/fry_core/ntp_kick.*): configTime() RESTARTS the SNTP request, so a
// caller that polls for the clock (the WireGuard client retries every 5-60 s while NTP is out)
// must not re-issue it on every poll - that keeps resetting the sync it is waiting for.
//
// REV-A F6. The bounded retry itself is unchanged; only the restart cadence is gated.
#include <unity.h>

#include <cstdint>

#include "ntp_kick.h"

namespace {

void test_the_first_call_always_starts_the_sync() {
  TEST_ASSERT_TRUE(fry::ntpRestartDue(/*started=*/false, /*nowMs=*/0, /*startedMs=*/0));
  TEST_ASSERT_TRUE(fry::ntpRestartDue(false, 123456, 0));
}

void test_a_start_within_the_interval_is_not_reissued() {
  const uint32_t startedMs = 10000;
  TEST_ASSERT_FALSE(fry::ntpRestartDue(true, startedMs, startedMs));
  TEST_ASSERT_FALSE(fry::ntpRestartDue(true, startedMs + 59999, startedMs));
}

void test_the_interval_itself_allows_a_reissue() {
  const uint32_t startedMs = 10000;
  TEST_ASSERT_TRUE(fry::ntpRestartDue(true, startedMs + fry::kNtpRestartIntervalMs, startedMs));
  TEST_ASSERT_TRUE(fry::ntpRestartDue(true, startedMs + fry::kNtpRestartIntervalMs + 1, startedMs));
}

void test_the_wireguard_retry_cadence_never_restarts_the_sync() {
  // The NoClock retry is 5, 10, 20, 40, then 60 s: none of those may re-issue configTime().
  const uint32_t startedMs = 7000;
  const uint32_t retries[] = {5000, 10000, 20000, 40000, 60000, 60000, 60000};
  uint32_t now = startedMs;
  for (uint32_t delay : retries) {
    now += delay;
    TEST_ASSERT_FALSE(fry::ntpRestartDue(true, now, startedMs));
  }
  // ... but after ten minutes a stuck sync is re-issued.
  TEST_ASSERT_TRUE(fry::ntpRestartDue(true, startedMs + fry::kNtpRestartIntervalMs, startedMs));
}

void test_the_interval_is_wrap_safe_on_a_32_bit_millisecond_counter() {
  const uint32_t startedMs = 0xFFFFFFFFu - 1000u;
  TEST_ASSERT_FALSE(fry::ntpRestartDue(true, static_cast<uint32_t>(startedMs + 2000u), startedMs));
  TEST_ASSERT_TRUE(fry::ntpRestartDue(true, static_cast<uint32_t>(startedMs + fry::kNtpRestartIntervalMs),
                                      startedMs));
}

void test_the_default_interval_is_ten_minutes() {
  TEST_ASSERT_EQUAL_UINT32(600000u, fry::kNtpRestartIntervalMs);
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_first_call_always_starts_the_sync);
  RUN_TEST(test_a_start_within_the_interval_is_not_reissued);
  RUN_TEST(test_the_interval_itself_allows_a_reissue);
  RUN_TEST(test_the_wireguard_retry_cadence_never_restarts_the_sync);
  RUN_TEST(test_the_interval_is_wrap_safe_on_a_32_bit_millisecond_counter);
  RUN_TEST(test_the_default_interval_is_ten_minutes);
  return UNITY_END();
}
