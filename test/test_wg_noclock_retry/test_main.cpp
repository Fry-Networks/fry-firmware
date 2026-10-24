// The bounded NTP wait in fry::wgRetryDelayMs (lib/fry_core/wg_provision.*).
//
// At HEAD the NoClock outcome deferred the WireGuard peer fetch by a flat 300,000 ms: a board
// whose NTP landed seconds after Wi-Fi still waited five minutes for its peer, because the client
// asks ensureNtpSynced(1) (non-blocking) and the schedule was the only thing that decided when to
// look again. The retry is now 5,000 * 2^attemptNumber capped at 60,000 ms. The clock gate itself
// is NOT relaxed - classifyWgFetch still returns NoClock and no request is sent until the clock is
// plausible; only the retry cadence changed.
#include <unity.h>

#include <cstdint>

#include "wg_provision.h"

namespace {

void test_noclock_backs_off_exponentially_and_is_capped_at_sixty_seconds() {
  TEST_ASSERT_EQUAL_UINT32(5000, fry::wgRetryDelayMs(fry::WgFetchOutcome::NoClock, 0, 0).delayMs);
  TEST_ASSERT_EQUAL_UINT32(10000, fry::wgRetryDelayMs(fry::WgFetchOutcome::NoClock, 1, 0).delayMs);
  TEST_ASSERT_EQUAL_UINT32(20000, fry::wgRetryDelayMs(fry::WgFetchOutcome::NoClock, 2, 0).delayMs);
  TEST_ASSERT_EQUAL_UINT32(40000, fry::wgRetryDelayMs(fry::WgFetchOutcome::NoClock, 3, 0).delayMs);
  TEST_ASSERT_EQUAL_UINT32(60000, fry::wgRetryDelayMs(fry::WgFetchOutcome::NoClock, 4, 0).delayMs);
  TEST_ASSERT_EQUAL_UINT32(60000, fry::wgRetryDelayMs(fry::WgFetchOutcome::NoClock, 5, 0).delayMs);
}

void test_noclock_never_exceeds_sixty_seconds_whatever_the_attempt_number() {
  // A very large attempt number must saturate, never overflow into a short or huge delay.
  TEST_ASSERT_EQUAL_UINT32(60000,
                           fry::wgRetryDelayMs(fry::WgFetchOutcome::NoClock, 4000000000u, 0).delayMs);
  for (uint32_t attempt = 0; attempt < 64; attempt++) {
    TEST_ASSERT_LESS_OR_EQUAL_UINT32(
        60000, fry::wgRetryDelayMs(fry::WgFetchOutcome::NoClock, attempt, 0).delayMs);
    TEST_ASSERT_GREATER_OR_EQUAL_UINT32(
        5000, fry::wgRetryDelayMs(fry::WgFetchOutcome::NoClock, attempt, 0).delayMs);
  }
}

void test_the_clock_check_itself_is_still_enforced() {
  // Time checks stay on: an unsynced clock classifies as NoClock and a plausible one does not.
  TEST_ASSERT_EQUAL(fry::WgFetchOutcome::NoClock, fry::classifyWgFetch(true, true, false, 201));
  TEST_ASSERT_EQUAL(fry::WgFetchOutcome::Ok, fry::classifyWgFetch(true, true, true, 201));
}

void test_the_other_flat_outcomes_are_unchanged() {
  TEST_ASSERT_EQUAL_UINT32(60000, fry::wgRetryDelayMs(fry::WgFetchOutcome::NoToken, 0, 0).delayMs);
  TEST_ASSERT_EQUAL_UINT32(60000, fry::wgRetryDelayMs(fry::WgFetchOutcome::NoHeap, 9, 0).delayMs);
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_noclock_backs_off_exponentially_and_is_capped_at_sixty_seconds);
  RUN_TEST(test_noclock_never_exceeds_sixty_seconds_whatever_the_attempt_number);
  RUN_TEST(test_the_clock_check_itself_is_still_enforced);
  RUN_TEST(test_the_other_flat_outcomes_are_unchanged);
  return UNITY_END();
}
