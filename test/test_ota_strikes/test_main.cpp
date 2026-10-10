// Bad-version STRIKES instead of a one-shot verdict (lib/fry_core/ota_health.*, PROTOCOL.md 11.8).
//
// Round-1 0.4.0 recorded a version as bad after ONE rollback and never installed it again. A power
// cut before the first answer, a planned restart while pending, or a fleet-wide TLS/DNS outage
// would therefore pin boards to the old release until the one after. Now: one strike per
// rollback, the version is skipped only on the first check after the rollback boot, retried at the
// next 6-hour check, and skipped for good only at 3 strikes.
#include <unity.h>

#include <string>

#include "ota_health.h"

namespace {

void test_the_first_rollback_is_one_strike() {
  bool changed = false;
  TEST_ASSERT_EQUAL_UINT8(1, fry::nextStrikeCount("", 0, "0.4.1", false, &changed));
  TEST_ASSERT_TRUE(changed);
}

void test_the_same_version_again_adds_a_strike() {
  bool changed = false;
  TEST_ASSERT_EQUAL_UINT8(2, fry::nextStrikeCount("0.4.1", 1, "0.4.1", false, &changed));
  TEST_ASSERT_TRUE(changed);
  TEST_ASSERT_EQUAL_UINT8(3, fry::nextStrikeCount("0.4.1", 2, "0.4.1", false, &changed));
}

void test_a_different_version_restarts_the_count() {
  bool changed = false;
  TEST_ASSERT_EQUAL_UINT8(1, fry::nextStrikeCount("0.4.1", 2, "0.4.2", false, &changed));
  TEST_ASSERT_TRUE(changed);
}

void test_a_planned_restart_is_not_a_strike() {
  // restartToApply or a USB re-key while pending: the bootloader rolls back, nothing failed.
  bool changed = true;
  TEST_ASSERT_EQUAL_UINT8(1, fry::nextStrikeCount("0.4.1", 1, "0.4.1", true, &changed));
  TEST_ASSERT_FALSE(changed);
  TEST_ASSERT_EQUAL_UINT8(0, fry::nextStrikeCount("", 0, "0.4.1", true, &changed));
  TEST_ASSERT_FALSE(changed);
}

void test_no_rollback_evidence_means_no_strike() {
  bool changed = true;
  TEST_ASSERT_EQUAL_UINT8(2, fry::nextStrikeCount("0.4.1", 2, "", false, &changed));
  TEST_ASSERT_FALSE(changed);
  TEST_ASSERT_EQUAL_UINT8(2, fry::nextStrikeCount("0.4.1", 2, nullptr, false, &changed));
  TEST_ASSERT_FALSE(changed);
}

void test_the_count_saturates() {
  bool changed = false;
  TEST_ASSERT_EQUAL_UINT8(255, fry::nextStrikeCount("0.4.1", 255, "0.4.1", false, &changed));
}

void test_below_three_only_the_first_check_after_a_rollback_skips() {
  TEST_ASSERT_TRUE(fry::skipBadVersion("0.4.1", "0.4.1", 1, true));
  TEST_ASSERT_FALSE(fry::skipBadVersion("0.4.1", "0.4.1", 1, false));  // the next 6 h check retries
  TEST_ASSERT_TRUE(fry::skipBadVersion("0.4.1", "0.4.1", 2, true));
  TEST_ASSERT_FALSE(fry::skipBadVersion("0.4.1", "0.4.1", 2, false));
}

void test_three_strikes_is_permanent() {
  TEST_ASSERT_EQUAL_UINT8(3, fry::kOtaPermanentStrikes);
  TEST_ASSERT_TRUE(fry::skipBadVersion("0.4.1", "0.4.1", 3, false));
  TEST_ASSERT_TRUE(fry::skipBadVersion("0.4.1", "0.4.1", 4, false));
}

void test_other_versions_are_never_skipped() {
  TEST_ASSERT_FALSE(fry::skipBadVersion("0.4.2", "0.4.1", 3, true));
  TEST_ASSERT_FALSE(fry::skipBadVersion("0.4.1", "", 3, true));
  TEST_ASSERT_FALSE(fry::skipBadVersion("", "0.4.1", 3, true));
}

void test_a_different_latest_resets_the_strikes() {
  TEST_ASSERT_TRUE(fry::strikesReset("0.4.2", "0.4.1"));
  TEST_ASSERT_TRUE(fry::strikesReset("0.0.0", "0.4.1"));  // the fw-hold kill switch, too
  TEST_ASSERT_FALSE(fry::strikesReset("0.4.1", "0.4.1"));
  TEST_ASSERT_FALSE(fry::strikesReset("0.4.2", ""));
  TEST_ASSERT_FALSE(fry::strikesReset("", "0.4.1"));
}

// Walks a board through 6-hourly checks. installFails(n) says whether the n-th install fails.
int attemptsOverChecks(int checks, bool (*installFails)(int)) {
  std::string badver;
  uint8_t badn = 0;
  bool firstAfterRollback = false;
  int attempts = 0;
  for (int c = 0; c < checks; c++) {
    const bool skip = fry::skipBadVersion("0.4.1", badver.c_str(), badn, firstAfterRollback);
    firstAfterRollback = false;
    if (skip) continue;
    attempts++;
    if (!installFails(attempts)) break;  // the image verified: done
    bool changed = false;
    badn = fry::nextStrikeCount(badver.c_str(), badn, "0.4.1", false, &changed);
    if (changed) badver = "0.4.1";
    firstAfterRollback = true;  // the old image's first check after the rollback boot
  }
  return attempts;
}

bool alwaysFails(int) { return true; }
bool failsOnce(int n) { return n == 1; }

void test_a_bad_image_costs_at_most_three_attempts() {
  TEST_ASSERT_EQUAL_INT(3, attemptsOverChecks(40, alwaysFails));
}

void test_a_transient_failure_costs_one_skipped_check() {
  TEST_ASSERT_EQUAL_INT(2, attemptsOverChecks(40, failsOnce));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_first_rollback_is_one_strike);
  RUN_TEST(test_the_same_version_again_adds_a_strike);
  RUN_TEST(test_a_different_version_restarts_the_count);
  RUN_TEST(test_a_planned_restart_is_not_a_strike);
  RUN_TEST(test_no_rollback_evidence_means_no_strike);
  RUN_TEST(test_the_count_saturates);
  RUN_TEST(test_below_three_only_the_first_check_after_a_rollback_skips);
  RUN_TEST(test_three_strikes_is_permanent);
  RUN_TEST(test_other_versions_are_never_skipped);
  RUN_TEST(test_a_different_latest_resets_the_strikes);
  RUN_TEST(test_a_bad_image_costs_at_most_three_attempts);
  RUN_TEST(test_a_transient_failure_costs_one_skipped_check);
  return UNITY_END();
}
