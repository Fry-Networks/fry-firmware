// fry::BleIdleTimer (lib/fry_core/ble_idle.*): the BLE stack is released only after the board has
// stayed Connected, with no central attached, for the whole grace period.
#include <unity.h>

#include <cstdint>

#include "ble_idle.h"

namespace {

void test_it_waits_out_the_grace_period_before_releasing() {
  fry::BleIdleTimer t;
  TEST_ASSERT_FALSE(t.poll(true, true, 0, 1000));
  TEST_ASSERT_FALSE(t.poll(true, true, 0, 1000 + fry::kBleIdleGraceMs - 1));
  TEST_ASSERT_TRUE(t.poll(true, true, 0, 1000 + fry::kBleIdleGraceMs));
}

void test_a_board_that_is_not_connected_never_releases() {
  fry::BleIdleTimer t;
  TEST_ASSERT_FALSE(t.poll(true, false, 0, 0));
  TEST_ASSERT_FALSE(t.poll(true, false, 0, 10 * fry::kBleIdleGraceMs));
}

void test_an_attached_central_blocks_and_restarts_the_period() {
  fry::BleIdleTimer t;
  TEST_ASSERT_FALSE(t.poll(true, true, 0, 0));
  TEST_ASSERT_FALSE(t.poll(true, true, 1, fry::kBleIdleGraceMs));       // attached: never release
  TEST_ASSERT_FALSE(t.poll(true, true, 0, fry::kBleIdleGraceMs + 1));   // period starts over
  TEST_ASSERT_FALSE(t.poll(true, true, 0, 2 * fry::kBleIdleGraceMs));
  TEST_ASSERT_TRUE(t.poll(true, true, 0, fry::kBleIdleGraceMs + 1 + fry::kBleIdleGraceMs));
}

void test_a_state_change_back_out_of_connected_restarts_the_period() {
  fry::BleIdleTimer t;
  TEST_ASSERT_FALSE(t.poll(true, true, 0, 0));
  TEST_ASSERT_FALSE(t.poll(true, false, 0, fry::kBleIdleGraceMs - 1));
  TEST_ASSERT_FALSE(t.poll(true, true, 0, fry::kBleIdleGraceMs));
  TEST_ASSERT_FALSE(t.poll(true, true, 0, 2 * fry::kBleIdleGraceMs - 1));
  TEST_ASSERT_TRUE(t.poll(true, true, 0, 2 * fry::kBleIdleGraceMs));
}

void test_a_stack_that_is_already_down_is_not_released_again() {
  fry::BleIdleTimer t;
  TEST_ASSERT_FALSE(t.poll(false, true, 0, 0));
  TEST_ASSERT_FALSE(t.poll(false, true, 0, 10 * fry::kBleIdleGraceMs));
}

void test_the_period_is_wrap_safe_on_a_32_bit_millisecond_counter() {
  fry::BleIdleTimer t;
  const uint32_t start = 0xFFFFFFFFu - 1000u;
  TEST_ASSERT_FALSE(t.poll(true, true, 0, start));
  TEST_ASSERT_FALSE(t.poll(true, true, 0, start + 5000u));
  TEST_ASSERT_TRUE(t.poll(true, true, 0, start + fry::kBleIdleGraceMs));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_it_waits_out_the_grace_period_before_releasing);
  RUN_TEST(test_a_board_that_is_not_connected_never_releases);
  RUN_TEST(test_an_attached_central_blocks_and_restarts_the_period);
  RUN_TEST(test_a_state_change_back_out_of_connected_restarts_the_period);
  RUN_TEST(test_a_stack_that_is_already_down_is_not_released_again);
  RUN_TEST(test_the_period_is_wrap_safe_on_a_32_bit_millisecond_counter);
  return UNITY_END();
}
