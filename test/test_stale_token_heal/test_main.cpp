// Stale device-token self-heal, the decision alone (lib/fry_core/stale_token_heal.h).
//
// With apiBase = WG1, a stale stored device token makes the registration POST carry a Bearer; WG1
// then skips its token-less first-registration route (server.py:243-244) and answers a LOCAL 404
// (server.py:271). The firmware classified that as RegOther4xx (12) and retried in an hour forever,
// never clearing the token — a permanent deadlock. Only that exact signature may fire the heal;
// everything else is today's behaviour.
#include <unity.h>

#include <cstdint>

#include "stale_token_heal.h"

namespace {

void test_only_a_404_with_a_device_token_fires() {
  TEST_ASSERT_TRUE(fry::isStaleTokenSignature(404, true));
}

void test_a_404_on_a_token_less_attempt_does_not_fire() {
  // No stored device token (the attempt carried the build-time bootstrap token, or nothing): there
  // is no stale credential to clear, so the board keeps today's behaviour.
  TEST_ASSERT_FALSE(fry::isStaleTokenSignature(404, false));
}

void test_every_other_rejection_class_does_not_fire() {
  const int codes[] = {200, 201, 302, 400, 401, 403, 409, 422, 429, 500, 502, 503, 0, -1, -11};
  for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); i++) {
    TEST_ASSERT_FALSE_MESSAGE(fry::isStaleTokenSignature(codes[i], true), "a non-404 answer must never heal");
  }
  // 429 is "come back later" and 5xx/transport errors are outages: all leave the token alone.
  TEST_ASSERT_FALSE(fry::isStaleTokenSignature(429, true));
  TEST_ASSERT_FALSE(fry::isStaleTokenSignature(500, true));
  TEST_ASSERT_FALSE(fry::isStaleTokenSignature(-1, true));
}

void test_the_window_is_open_on_the_first_ever_heal() {
  const uint32_t now = fry::kHealMinPlausibleEpoch + 60;
  TEST_ASSERT_TRUE(fry::healWindowOpen(false, 0, now));
}

void test_a_second_stale_response_in_the_same_boot_does_not_fire() {
  const uint32_t now = fry::kHealMinPlausibleEpoch + 7UL * 3600UL;
  TEST_ASSERT_FALSE(fry::healWindowOpen(true, 0, now));                    // never healed, but this boot already did
  TEST_ASSERT_FALSE(fry::healWindowOpen(true, now - 7UL * 3600UL, now));   // and the persisted epoch is irrelevant then
}

void test_the_six_hour_limit_holds_across_simulated_reboots() {
  // Each call is a reboot: healedThisBoot is false again, only fry/healAt persists.
  const uint32_t healedAt = fry::kHealMinPlausibleEpoch + 10UL * 3600UL;
  TEST_ASSERT_FALSE(fry::healWindowOpen(false, healedAt, healedAt));                      // immediately after
  TEST_ASSERT_FALSE(fry::healWindowOpen(false, healedAt, healedAt + 1));
  TEST_ASSERT_FALSE(fry::healWindowOpen(false, healedAt, healedAt + 3600));               // +1 h
  TEST_ASSERT_FALSE(fry::healWindowOpen(false, healedAt, healedAt + 5UL * 3600UL + 3599));  // one second early
  TEST_ASSERT_TRUE(fry::healWindowOpen(false, healedAt, healedAt + 6UL * 3600UL));        // exactly 6 h
  TEST_ASSERT_TRUE(fry::healWindowOpen(false, healedAt, healedAt + 12UL * 3600UL));
}

void test_an_unsynced_or_rolled_back_clock_never_opens_the_window() {
  // Registration can run before NTP (the boot-time attempt): 1970 cannot prove 6 h have passed, and
  // a board that healed every boot would be exactly the storm the bound exists to prevent.
  const uint32_t healedAt = fry::kHealMinPlausibleEpoch + 3600;
  TEST_ASSERT_FALSE(fry::healWindowOpen(false, 0, 0));  // 1970, first ever
  TEST_ASSERT_FALSE(fry::healWindowOpen(false, 0, 946684800UL));  // 2000, still implausible
  TEST_ASSERT_FALSE(fry::healWindowOpen(false, healedAt, 0));
  TEST_ASSERT_FALSE(fry::healWindowOpen(false, healedAt, healedAt - 1));  // moved backwards
  TEST_ASSERT_TRUE(fry::healWindowOpen(false, 0, fry::kHealMinPlausibleEpoch));
}

void test_the_restore_comparison_is_byte_for_byte() {
  TEST_ASSERT_TRUE(fry::pairsMatchByteForByte("0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef"));
  TEST_ASSERT_TRUE(fry::pairsMatchByteForByte("", ""));
  // One byte different anywhere is not the same pair.
  TEST_ASSERT_FALSE(fry::pairsMatchByteForByte("0123456789abcdef0123456789abcdee", "0123456789abcdef0123456789abcdef"));
  TEST_ASSERT_FALSE(fry::pairsMatchByteForByte("0123456789abcdef0123456789abcde", "0123456789abcdef0123456789abcdef"));
  // A NUL does not end the comparison early on the longer side, and case matters.
  TEST_ASSERT_FALSE(fry::pairsMatchByteForByte("abc", "abcd"));
  TEST_ASSERT_FALSE(fry::pairsMatchByteForByte("ABC", "abc"));
  TEST_ASSERT_FALSE(fry::pairsMatchByteForByte(nullptr, "abc"));
  TEST_ASSERT_FALSE(fry::pairsMatchByteForByte("abc", nullptr));
}

void test_the_bounds_are_the_ones_the_spec_names() {
  TEST_ASSERT_EQUAL_UINT32(6UL * 3600UL, fry::kHealWindowSeconds);
  // 2020-09-13: a clock that cannot have synced yet is not plausible.
  TEST_ASSERT_TRUE(fry::kHealMinPlausibleEpoch >= 1600000000UL);
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_only_a_404_with_a_device_token_fires);
  RUN_TEST(test_a_404_on_a_token_less_attempt_does_not_fire);
  RUN_TEST(test_every_other_rejection_class_does_not_fire);
  RUN_TEST(test_the_window_is_open_on_the_first_ever_heal);
  RUN_TEST(test_a_second_stale_response_in_the_same_boot_does_not_fire);
  RUN_TEST(test_the_six_hour_limit_holds_across_simulated_reboots);
  RUN_TEST(test_an_unsynced_or_rolled_back_clock_never_opens_the_window);
  RUN_TEST(test_the_restore_comparison_is_byte_for_byte);
  RUN_TEST(test_the_bounds_are_the_ones_the_spec_names);
  return UNITY_END();
}
