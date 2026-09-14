// A user whose board holds credentials for a network that no longer exists needs a way back that
// does not involve a USB cable. The BOOT button is the only input every supported board has, so a
// long hold on it clears stored configuration. These tests pin down the two properties that make
// that safe: it must not fire on an accidental tap, and it must not fire twice on one hold.
#include <unity.h>

#include "reset_button.h"

using fry::kFactoryResetHoldMs;
using fry::ResetButton;

namespace {

// Feeds `pressed` from `fromMs` to `toMs` in 50 ms steps and returns how many times it fired.
int feed(ResetButton& b, bool pressed, uint32_t fromMs, uint32_t toMs) {
  int fires = 0;
  for (uint32_t t = fromMs; t <= toMs; t += 50) {
    if (b.update(pressed, t)) fires++;
  }
  return fires;
}

void test_a_short_press_never_fires() {
  ResetButton b;
  TEST_ASSERT_EQUAL(0, feed(b, true, 0, 2000));
  TEST_ASSERT_EQUAL(0, feed(b, false, 2050, 2500));
}

void test_a_full_hold_fires_once() {
  ResetButton b;
  TEST_ASSERT_EQUAL(1, feed(b, true, 0, kFactoryResetHoldMs + 2000));
}

void test_releasing_early_resets_the_timer() {
  ResetButton b;
  // Almost there, then let go.
  feed(b, true, 0, kFactoryResetHoldMs - 1000);
  feed(b, false, kFactoryResetHoldMs - 950, kFactoryResetHoldMs - 500);

  // The next hold must start from zero, so a hold shorter than the threshold still does nothing.
  TEST_ASSERT_EQUAL(0, feed(b, true, kFactoryResetHoldMs, kFactoryResetHoldMs + 2000));
}

void test_holding_past_the_threshold_does_not_fire_repeatedly() {
  ResetButton b;
  feed(b, true, 0, kFactoryResetHoldMs + 100);

  // Still held a full minute later: no second reset.
  TEST_ASSERT_EQUAL(0, feed(b, true, kFactoryResetHoldMs + 150, kFactoryResetHoldMs + 60000));
}

void test_a_second_deliberate_hold_fires_again() {
  ResetButton b;
  feed(b, true, 0, kFactoryResetHoldMs + 100);
  feed(b, false, kFactoryResetHoldMs + 150, kFactoryResetHoldMs + 1000);

  TEST_ASSERT_EQUAL(1, feed(b, true, kFactoryResetHoldMs + 1050, 3 * kFactoryResetHoldMs));
}

void test_held_ms_reports_progress() {
  ResetButton b;
  b.update(true, 1000);
  b.update(true, 4000);

  TEST_ASSERT_EQUAL_UINT32(3000, b.heldMs(4000));
  TEST_ASSERT_EQUAL_UINT32(0, ResetButton().heldMs(4000));
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}

void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_a_short_press_never_fires);
  RUN_TEST(test_a_full_hold_fires_once);
  RUN_TEST(test_releasing_early_resets_the_timer);
  RUN_TEST(test_holding_past_the_threshold_does_not_fire_repeatedly);
  RUN_TEST(test_a_second_deliberate_hold_fires_again);
  RUN_TEST(test_held_ms_reports_progress);
  return UNITY_END();
}
