// Retry-After on a 403 from the WireGuard peer fetch (fry::wgRetryDelayMs, lib/fry_core/wg_provision.*).
//
// Before this change the Forbidden403 outcome ignored the Retry-After header and always waited a
// flat 21,600,000 ms (6 h), although the client already collects the header on every non-2xx
// response. A board whose server answered "try again in ten minutes" therefore waited six hours.
//
// The header is honoured for a 403 only when it is shorter than one hour (0 < header < 3600 s), and
// is then raised to the 60 s floor. Anything else keeps the flat 6 h wait: no header (0), a header of
// one hour or more (the server's generic hourly window for a request that can never succeed), a
// value that wrapped around after a negative parse, or an HTTP-date form that parses to 0. The wait
// never grows with the attempt number for this outcome.
#include <unity.h>

#include <cstdint>

#include "wg_provision.h"

namespace {

using fry::WgFetchOutcome;

uint32_t forbidden(uint32_t attempt, uint32_t headerS) {
  return fry::wgRetryDelayMs(WgFetchOutcome::Forbidden403, attempt, headerS).delayMs;
}

void test_short_header_is_honoured() {
  TEST_ASSERT_EQUAL_UINT32(600000, forbidden(0, 600));
  TEST_ASSERT_EQUAL_UINT32(61000, forbidden(0, 61));
  TEST_ASSERT_EQUAL_UINT32(1800000, forbidden(0, 1800));
  TEST_ASSERT_EQUAL_UINT32(3599000, forbidden(0, 3599));
}

void test_short_header_is_raised_to_the_sixty_second_floor() {
  TEST_ASSERT_EQUAL_UINT32(60000, forbidden(0, 1));
  TEST_ASSERT_EQUAL_UINT32(60000, forbidden(0, 5));
  TEST_ASSERT_EQUAL_UINT32(60000, forbidden(0, 59));
  TEST_ASSERT_EQUAL_UINT32(60000, forbidden(0, 60));
}

void test_one_hour_or_more_keeps_the_flat_six_hours() {
  TEST_ASSERT_EQUAL_UINT32(21600000, forbidden(0, 3600));  // boundary: not honoured
  TEST_ASSERT_EQUAL_UINT32(21600000, forbidden(0, 3601));
  TEST_ASSERT_EQUAL_UINT32(21600000, forbidden(0, 21600));
  TEST_ASSERT_EQUAL_UINT32(21600000, forbidden(0, 21601));
  TEST_ASSERT_EQUAL_UINT32(21600000, forbidden(0, 86400));
  TEST_ASSERT_EQUAL_UINT32(21600000, forbidden(0, 999999));
}

void test_wrapped_negative_header_keeps_the_flat_six_hours() {
  // The client casts a signed parse to uint32_t, so "-1" arrives as 4294967295.
  TEST_ASSERT_EQUAL_UINT32(21600000, forbidden(0, 4000000000u));
  TEST_ASSERT_EQUAL_UINT32(21600000, forbidden(0, 4294967295u));
  TEST_ASSERT_EQUAL_UINT32(21600000, forbidden(0, 2147483648u));
}

void test_no_header_keeps_the_flat_six_hours_for_any_attempt() {
  TEST_ASSERT_EQUAL_UINT32(21600000, forbidden(0, 0));
  TEST_ASSERT_EQUAL_UINT32(21600000, forbidden(1, 0));
  TEST_ASSERT_EQUAL_UINT32(21600000, forbidden(50, 0));
  TEST_ASSERT_EQUAL_UINT32(21600000, forbidden(4000000000u, 0));
}

void test_honoured_wait_does_not_grow_with_the_attempt_number() {
  TEST_ASSERT_EQUAL_UINT32(600000, forbidden(0, 600));
  TEST_ASSERT_EQUAL_UINT32(600000, forbidden(1, 600));
  TEST_ASSERT_EQUAL_UINT32(600000, forbidden(50, 600));
  TEST_ASSERT_EQUAL_UINT32(600000, forbidden(4000000000u, 600));
}

void test_every_second_of_the_honoured_range_maps_exactly() {
  for (uint32_t h = 1; h < 3600; h++) {
    const uint32_t want = (h * 1000u < 60000u) ? 60000u : h * 1000u;
    TEST_ASSERT_EQUAL_UINT32(want, forbidden(0, h));
  }
  // and nothing in a sample of the rest of the range is honoured
  for (uint32_t h = 3600; h < 200000; h += 997) {
    TEST_ASSERT_EQUAL_UINT32(21600000, forbidden(0, h));
  }
}

void test_a_403_status_classifies_to_the_outcome_this_schedule_serves() {
  TEST_ASSERT_EQUAL(WgFetchOutcome::Forbidden403, fry::classifyWgFetch(true, true, true, 403));
  const WgFetchOutcome o = fry::classifyWgFetch(true, true, true, 403);
  TEST_ASSERT_EQUAL_UINT32(600000, fry::wgRetryDelayMs(o, 3, 600).delayMs);
}

void test_other_outcomes_ignore_the_change() {
  TEST_ASSERT_EQUAL_UINT32(900000, fry::wgRetryDelayMs(WgFetchOutcome::Unauthorized401, 0, 600).delayMs);
  TEST_ASSERT_EQUAL_UINT32(21600000,
                           fry::wgRetryDelayMs(WgFetchOutcome::OtherClientError4xx, 0, 600).delayMs);
  TEST_ASSERT_EQUAL_UINT32(60000, fry::wgRetryDelayMs(WgFetchOutcome::NoToken, 0, 600).delayMs);
  TEST_ASSERT_EQUAL_UINT32(60000, fry::wgRetryDelayMs(WgFetchOutcome::NoHeap, 0, 600).delayMs);
  TEST_ASSERT_EQUAL_UINT32(5000, fry::wgRetryDelayMs(WgFetchOutcome::NoClock, 0, 600).delayMs);
  TEST_ASSERT_EQUAL_UINT32(30000, fry::wgRetryDelayMs(WgFetchOutcome::TransientError, 0, 600).delayMs);
  TEST_ASSERT_EQUAL_UINT32(30000, fry::wgRetryDelayMs(WgFetchOutcome::ServerError5xx, 0, 600).delayMs);
}

void test_conflict_and_rate_limit_keep_their_own_clamp() {
  TEST_ASSERT_EQUAL_UINT32(600000, fry::wgRetryDelayMs(WgFetchOutcome::Conflict409, 0, 600).delayMs);
  TEST_ASSERT_EQUAL_UINT32(60000, fry::wgRetryDelayMs(WgFetchOutcome::RateLimited429, 0, 5).delayMs);
  TEST_ASSERT_EQUAL_UINT32(86400000,
                           fry::wgRetryDelayMs(WgFetchOutcome::RateLimited429, 0, 999999).delayMs);
  TEST_ASSERT_EQUAL_UINT32(3600000, fry::wgRetryDelayMs(WgFetchOutcome::RateLimited429, 0, 0).delayMs);
  TEST_ASSERT_EQUAL_UINT32(3600000, fry::wgRetryDelayMs(WgFetchOutcome::Conflict409, 0, 0).delayMs);
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_short_header_is_honoured);
  RUN_TEST(test_short_header_is_raised_to_the_sixty_second_floor);
  RUN_TEST(test_one_hour_or_more_keeps_the_flat_six_hours);
  RUN_TEST(test_wrapped_negative_header_keeps_the_flat_six_hours);
  RUN_TEST(test_no_header_keeps_the_flat_six_hours_for_any_attempt);
  RUN_TEST(test_honoured_wait_does_not_grow_with_the_attempt_number);
  RUN_TEST(test_every_second_of_the_honoured_range_maps_exactly);
  RUN_TEST(test_a_403_status_classifies_to_the_outcome_this_schedule_serves);
  RUN_TEST(test_other_outcomes_ignore_the_change);
  RUN_TEST(test_conflict_and_rate_limit_keep_their_own_clamp);
  return UNITY_END();
}
