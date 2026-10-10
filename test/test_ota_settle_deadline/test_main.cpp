// When a freshly installed (PENDING_VERIFY) image may be marked valid, and which time counts
// toward rolling it back (lib/fry_core/ota_health.*, PROTOCOL.md section 11.8).
//
// Round-1 0.4.0 marked the image valid on the FIRST hardwareapi answer, a few seconds after the
// join and before the VPN start, the first PoC/lease cycle or telemetry had ever run: a crash in
// any of those afterwards rebooted into a VALID image and crash-looped with no way back but USB.
// And the 20-minute deadline ran on uptime, so a board whose router was simply down rolled back a
// good image.
#include <unity.h>

#include "ota_health.h"

using fry::GuardAction;

namespace {

// POC_INTERVAL_MS (600 s, include/config.h) + 60 s: what src/core/ota_client.cpp passes.
const uint32_t kSettleMs = 11UL * 60UL * 1000UL;

// ---- F1: mark valid only after an answer AND the settle window -------------------------------

void test_an_early_answer_does_not_mark_the_image_valid() {
  TEST_ASSERT_FALSE(fry::decideMarkValid(true, true, 5000, kSettleMs));  // a 401 at t = 5 s
  TEST_ASSERT_FALSE(fry::decideMarkValid(true, true, 600000, kSettleMs));  // first PoC at 10 min
  TEST_ASSERT_FALSE(fry::decideMarkValid(true, true, kSettleMs - 1, kSettleMs));
}

void test_an_answer_plus_the_settle_window_marks_it_valid() {
  TEST_ASSERT_TRUE(fry::decideMarkValid(true, true, kSettleMs, kSettleMs));
  TEST_ASSERT_TRUE(fry::decideMarkValid(true, true, 3 * kSettleMs, kSettleMs));
}

void test_without_any_answer_it_is_never_marked_valid() {
  TEST_ASSERT_FALSE(fry::decideMarkValid(true, false, 10 * kSettleMs, kSettleMs));
}

void test_nothing_pending_means_nothing_to_mark() {
  TEST_ASSERT_FALSE(fry::decideMarkValid(false, true, 10 * kSettleMs, kSettleMs));
}

void test_the_settle_window_ends_before_the_prod_deadline() {
  // An image that answered must never be rolled back while it waits out the window: the guard
  // only acts without an answer, but the window must also fit inside the deadline it replaces.
  TEST_ASSERT_TRUE(kSettleMs < fry::kOtaVerifyDeadlineProdMs);
}

// ---- F2: the deadline accrues only while the station is associated with an IP ---------------

uint32_t runFor(uint32_t seconds, bool staConnected, uint32_t accrued = 0) {
  for (uint32_t s = 0; s < seconds; s++) accrued = fry::accrueVerifyMs(accrued, 1000, staConnected);
  return accrued;
}

void test_wifi_never_associated_for_20_min_means_no_rollback_and_no_strike() {
  // Router off after the update. Round 1 rolled the image back at 20 min of uptime and recorded
  // it as bad; with no rollback there is nothing for the previous image to count.
  const uint32_t accrued = runFor(21 * 60, false);
  TEST_ASSERT_EQUAL_UINT32(0, accrued);
  TEST_ASSERT_EQUAL((int)GuardAction::None,
                    (int)fry::decideRollbackGuard(true, false, accrued, fry::kOtaVerifyDeadlineProdMs));
}

void test_only_connected_time_counts_toward_the_deadline() {
  uint32_t accrued = runFor(10 * 60, false);  // 10 min down
  accrued = runFor(19 * 60, true, accrued);   // 19 min up, still no answer
  TEST_ASSERT_EQUAL((int)GuardAction::None,
                    (int)fry::decideRollbackGuard(true, false, accrued, fry::kOtaVerifyDeadlineProdMs));
  accrued = runFor(60, true, accrued);        // the 20th connected minute
  TEST_ASSERT_EQUAL((int)GuardAction::Rollback,
                    (int)fry::decideRollbackGuard(true, false, accrued, fry::kOtaVerifyDeadlineProdMs));
}

void test_an_answer_still_stops_the_guard() {
  const uint32_t accrued = runFor(40 * 60, true);
  TEST_ASSERT_EQUAL((int)GuardAction::None,
                    (int)fry::decideRollbackGuard(true, true, accrued, fry::kOtaVerifyDeadlineProdMs));
}

void test_the_test_channel_deadline_counts_the_same_way() {
  TEST_ASSERT_EQUAL((int)GuardAction::None,
                    (int)fry::decideRollbackGuard(true, false, runFor(5 * 60, false),
                                                  fry::kOtaVerifyDeadlineTestMs));
  TEST_ASSERT_EQUAL((int)GuardAction::Rollback,
                    (int)fry::decideRollbackGuard(true, false, runFor(2 * 60, true),
                                                  fry::kOtaVerifyDeadlineTestMs));
}

void test_accrual_saturates_instead_of_wrapping() {
  TEST_ASSERT_EQUAL_UINT32(0xFFFFFFFFu, fry::accrueVerifyMs(0xFFFFFF00u, 0x1000u, true));
  TEST_ASSERT_EQUAL_UINT32(0xFFFFFF00u, fry::accrueVerifyMs(0xFFFFFF00u, 0x1000u, false));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_an_early_answer_does_not_mark_the_image_valid);
  RUN_TEST(test_an_answer_plus_the_settle_window_marks_it_valid);
  RUN_TEST(test_without_any_answer_it_is_never_marked_valid);
  RUN_TEST(test_nothing_pending_means_nothing_to_mark);
  RUN_TEST(test_the_settle_window_ends_before_the_prod_deadline);
  RUN_TEST(test_wifi_never_associated_for_20_min_means_no_rollback_and_no_strike);
  RUN_TEST(test_only_connected_time_counts_toward_the_deadline);
  RUN_TEST(test_an_answer_still_stops_the_guard);
  RUN_TEST(test_the_test_channel_deadline_counts_the_same_way);
  RUN_TEST(test_accrual_saturates_instead_of_wrapping);
  return UNITY_END();
}
