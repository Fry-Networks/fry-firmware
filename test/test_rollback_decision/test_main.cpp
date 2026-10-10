// Post-OTA rollback decisions (lib/fry_core/ota_health.*, PROTOCOL.md section 11.5).
//
// The bootloader's app rollback was compiled in on every ESP32-family chip, but arduino-esp32's
// initArduino() marks the running image valid before setup() unless the sketch overrides the weak
// verifyRollbackLater(), so a bad image was never rolled back by the bootloader. The firmware now
// keeps a new image PENDING_VERIFY until hardwareapi answers once, and rolls back itself when no
// answer arrives before a deadline.
#include <unity.h>

#include "ota_health.h"

using fry::GuardAction;
using fry::OtaImageState;

namespace {

void test_deadlines_are_twenty_minutes_prod_and_two_minutes_test() {
  TEST_ASSERT_EQUAL_UINT32(20UL * 60UL * 1000UL, fry::kOtaVerifyDeadlineProdMs);
  TEST_ASSERT_EQUAL_UINT32(2UL * 60UL * 1000UL, fry::kOtaVerifyDeadlineTestMs);
}

void test_pending_image_without_a_heartbeat_rolls_back_at_the_deadline() {
  const uint32_t d = fry::kOtaVerifyDeadlineProdMs;
  TEST_ASSERT_EQUAL((int)GuardAction::None, (int)fry::decideRollbackGuard(true, false, 0, d));
  TEST_ASSERT_EQUAL((int)GuardAction::None, (int)fry::decideRollbackGuard(true, false, d - 1, d));
  TEST_ASSERT_EQUAL((int)GuardAction::Rollback, (int)fry::decideRollbackGuard(true, false, d, d));
  TEST_ASSERT_EQUAL((int)GuardAction::Rollback, (int)fry::decideRollbackGuard(true, false, d + 60000, d));
}

void test_any_heartbeat_or_a_valid_image_never_rolls_back() {
  const uint32_t d = fry::kOtaVerifyDeadlineTestMs;
  TEST_ASSERT_EQUAL((int)GuardAction::None, (int)fry::decideRollbackGuard(true, true, d * 10, d));
  TEST_ASSERT_EQUAL((int)GuardAction::None, (int)fry::decideRollbackGuard(false, false, d * 10, d));
  TEST_ASSERT_EQUAL((int)GuardAction::None, (int)fry::decideRollbackGuard(false, true, d * 10, d));
}

void test_a_rolled_back_pending_version_is_recorded_as_bad() {
  // Old image running, NVS still names the version we tried, bootloader reports an invalid slot.
  TEST_ASSERT_TRUE(fry::shouldRecordBadVersion("0.4.1", "0.4.0", true));
}

void test_no_evidence_means_no_bad_version() {
  // The new image booted: its own version is pending, nothing failed yet.
  TEST_ASSERT_FALSE(fry::shouldRecordBadVersion("0.4.1", "0.4.1", true));
  // pending != running but the bootloader saw no invalid slot (e.g. reflashed over USB).
  TEST_ASSERT_FALSE(fry::shouldRecordBadVersion("0.4.1", "0.4.0", false));
  TEST_ASSERT_FALSE(fry::shouldRecordBadVersion("", "0.4.0", true));
  TEST_ASSERT_FALSE(fry::shouldRecordBadVersion(nullptr, "0.4.0", true));
}

void test_image_state_names_match_the_status_field() {
  TEST_ASSERT_EQUAL_STRING("valid", fry::otaImageStateName(OtaImageState::Valid));
  TEST_ASSERT_EQUAL_STRING("pending", fry::otaImageStateName(OtaImageState::Pending));
  TEST_ASSERT_EQUAL_STRING("rolled_back", fry::otaImageStateName(OtaImageState::RolledBack));
}

void test_image_state_precedence() {
  // Pending wins: the running image is the unverified one.
  TEST_ASSERT_EQUAL((int)OtaImageState::Pending, (int)fry::otaImageState(true, true));
  TEST_ASSERT_EQUAL((int)OtaImageState::Pending, (int)fry::otaImageState(true, false));
  TEST_ASSERT_EQUAL((int)OtaImageState::RolledBack, (int)fry::otaImageState(false, true));
  TEST_ASSERT_EQUAL((int)OtaImageState::Valid, (int)fry::otaImageState(false, false));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_deadlines_are_twenty_minutes_prod_and_two_minutes_test);
  RUN_TEST(test_pending_image_without_a_heartbeat_rolls_back_at_the_deadline);
  RUN_TEST(test_any_heartbeat_or_a_valid_image_never_rolls_back);
  RUN_TEST(test_a_rolled_back_pending_version_is_recorded_as_bad);
  RUN_TEST(test_no_evidence_means_no_bad_version);
  RUN_TEST(test_image_state_names_match_the_status_field);
  RUN_TEST(test_image_state_precedence);
  return UNITY_END();
}
