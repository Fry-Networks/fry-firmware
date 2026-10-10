// fry::accrueVerifyMs (lib/fry_core/ota_health.cpp) adds connected time to the verify deadline and
// saturates at 0xFFFFFFFF instead of wrapping. test_ota_settle_deadline pins the deep-saturation
// case; this suite pins the EXACT boundary: with `remaining` = 0xFFFFFFFF - accrued, elapsed =
// remaining-1, remaining and remaining+1 (round-2 tests review #4).
//
// Note for mutation testing: at elapsed == remaining the exact sum IS 0xFFFFFFFF, the saturation
// value, so `elapsedMs > remaining` and `elapsedMs >= remaining` return the same number there -
// that mutant is behaviourally equivalent. What the boundary cases do pin is that nothing below
// the limit is ever clamped (remaining-1 -> 0xFFFFFFFE) and nothing above it ever wraps.
#include <unity.h>

#include "ota_health.h"

namespace {

const uint32_t kAccrued = 0xFFFFFF00u;
const uint32_t kRemaining = 0xFFFFFFFFu - kAccrued;  // 0xFF

void test_one_below_the_limit_is_added_exactly() {
  TEST_ASSERT_EQUAL_UINT32(0xFFFFFFFEu, fry::accrueVerifyMs(kAccrued, kRemaining - 1, true));
}

void test_exactly_the_limit_reaches_the_maximum_without_clamping() {
  TEST_ASSERT_EQUAL_UINT32(0xFFFFFFFFu, fry::accrueVerifyMs(kAccrued, kRemaining, true));
}

void test_one_over_the_limit_saturates_instead_of_wrapping_to_zero() {
  TEST_ASSERT_EQUAL_UINT32(0xFFFFFFFFu, fry::accrueVerifyMs(kAccrued, kRemaining + 1, true));
}

void test_the_edges_of_the_range() {
  TEST_ASSERT_EQUAL_UINT32(0xFFFFFFFFu, fry::accrueVerifyMs(0u, 0xFFFFFFFFu, true));  // exact, no clamp
  TEST_ASSERT_EQUAL_UINT32(0xFFFFFFFFu, fry::accrueVerifyMs(0xFFFFFFFFu, 0u, true));  // already full
  TEST_ASSERT_EQUAL_UINT32(0xFFFFFFFFu, fry::accrueVerifyMs(0xFFFFFFFFu, 1u, true));  // stays full
  TEST_ASSERT_EQUAL_UINT32(0u, fry::accrueVerifyMs(0u, 0u, true));
}

void test_disconnected_time_never_accrues_even_at_the_boundary() {
  TEST_ASSERT_EQUAL_UINT32(kAccrued, fry::accrueVerifyMs(kAccrued, kRemaining, false));
  TEST_ASSERT_EQUAL_UINT32(kAccrued, fry::accrueVerifyMs(kAccrued, kRemaining + 1, false));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_one_below_the_limit_is_added_exactly);
  RUN_TEST(test_exactly_the_limit_reaches_the_maximum_without_clamping);
  RUN_TEST(test_one_over_the_limit_saturates_instead_of_wrapping_to_zero);
  RUN_TEST(test_the_edges_of_the_range);
  RUN_TEST(test_disconnected_time_never_accrues_even_at_the_boundary);
  return UNITY_END();
}
