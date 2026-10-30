// Stale-token self-heal: the pure rules, EXECUTED (boot recovery, the clock, the retry's reply, the per-boot latch).
//
// lib/fry_core/heal_fix_rules.h holds the decisions; src/core/hardwareapi_client.cpp applies them (the wiring is
// pinned in test_heal_fix_wiring). Synthetic numbers only: there is no token, install id or key in this file.
//
// On main 85825ac the header does not exist: every test gated on it fails by name with that message (a runtime RED,
// not a compile error). The clock-window tests and the differential guard use only stale_token_heal.h, which main has,
// so they run on main and the clock-window ones FAIL there on behavior.
#include <unity.h>

#include <climits>
#include <cstdint>
#include <cstdio>

#include "stale_token_heal.h"

#if __has_include("heal_fix_rules.h")
#include "heal_fix_rules.h"
#define FRY_HAVE_HEAL_FIX_RULES 1
#endif

namespace {

// The window as shipped in 0.4.15 / main 85825ac, verbatim (lib/fry_core/stale_token_heal.h). The differential
// guard compares the current implementation to it.
bool shippedHealWindowOpen(bool healedThisBoot, uint32_t lastHealEpoch, uint32_t nowEpoch) {
  if (healedThisBoot || nowEpoch < fry::kHealMinPlausibleEpoch) return false;
  if (lastHealEpoch == 0) return true;
  return nowEpoch >= lastHealEpoch && nowEpoch - lastHealEpoch >= fry::kHealWindowSeconds;
}

const uint32_t kNow = 1790000000UL;  // a plausible synced clock (2026-09)
const uint32_t kCeiling = 2147483647UL;  // 2038-01-19, the clock ceiling (literal: main has no constant for it)
const uint32_t kWindow = 6UL * 3600UL;

// ---- the clock (stale_token_heal.h only, runs on main) ------------------------------------------------------------

void test_a_clock_past_the_32_bit_ceiling_never_opens_the_window() {
  // 2^31 is 2038-01-19 03:14:08: a signed 32-bit time_t has wrapped by then. Main has no ceiling and says "open".
  TEST_ASSERT_FALSE(fry::healWindowOpen(false, 0, 2147483648UL));
  TEST_ASSERT_FALSE(fry::healWindowOpen(false, 0, 4294967295UL));
  TEST_ASSERT_FALSE(fry::healWindowOpen(false, kNow, 3000000000UL));
}

void test_a_stamp_from_a_future_clock_does_not_block_the_heal_forever() {
  // A stamp written while a rogue NTP source said 2035, read back with the real clock: main stays closed until 2035.
  const uint32_t poisoned = 2051222400UL;  // 2035-01-01
  TEST_ASSERT_TRUE(fry::healWindowOpen(false, poisoned, kNow));
  TEST_ASSERT_TRUE(fry::healWindowOpen(false, 2147483647UL, kNow));
  // Still one per boot, whatever the stamp says.
  TEST_ASSERT_FALSE(fry::healWindowOpen(true, poisoned, kNow));
  // The edge: a stamp exactly one window ahead is a clock that stepped back 6 h (shipped: closed); one second more
  // cannot be a record of a past heal.
  TEST_ASSERT_FALSE(fry::healWindowOpen(false, kNow + kWindow, kNow));
  TEST_ASSERT_TRUE(fry::healWindowOpen(false, kNow + kWindow + 1, kNow));
  // A backwards step of one second, the shipped test's case, stays closed.
  TEST_ASSERT_FALSE(fry::healWindowOpen(false, kNow, kNow - 1));
}

void test_the_shipped_window_is_unchanged_on_the_plausible_domain() {
  // GREEN on main AND on the branch: for every plausible clock and every stamp a plausible clock could have written,
  // the answer is the one 0.4.15 gave. 0.4.15's per-boot flag and 6 h bound are exactly as shipped.
  const uint32_t lasts[] = {0UL, fry::kHealMinPlausibleEpoch, fry::kHealMinPlausibleEpoch + 3600UL, 1700000000UL,
                            kNow, 1800000000UL, 2000000000UL, 2147000000UL};
  long checked = 0;
  for (size_t li = 0; li < sizeof(lasts) / sizeof(lasts[0]); li++) {
    const uint32_t last = lasts[li];
    // The clock from exactly one window behind the stamp to 14 h after it, every second.
    for (long off = -static_cast<long>(kWindow); off <= 14L * 3600L; off++) {
      const long nowL = static_cast<long>(last) + off;
      if (nowL < 0 || nowL > static_cast<long>(kCeiling)) continue;
      const uint32_t now = static_cast<uint32_t>(nowL);
      for (int healed = 0; healed < 2; healed++) {
        const bool a = shippedHealWindowOpen(healed != 0, last, now);
        const bool b = fry::healWindowOpen(healed != 0, last, now);
        if (a != b) {
          char msg[96];
          snprintf(msg, sizeof(msg), "diverges: healed=%d last=%lu now=%lu", healed, static_cast<unsigned long>(last),
                   static_cast<unsigned long>(now));
          TEST_FAIL_MESSAGE(msg);
        }
        checked++;
      }
    }
  }
  // Control: the sweep really covered the interesting cases (both answers occur, and the exact boundaries are in it).
  TEST_ASSERT_TRUE(checked > 300000);
  TEST_ASSERT_TRUE(fry::healWindowOpen(false, kNow, kNow + kWindow));
  TEST_ASSERT_FALSE(fry::healWindowOpen(false, kNow, kNow + kWindow - 1));
  // Clocks below the floor are closed exactly as before.
  TEST_ASSERT_EQUAL(shippedHealWindowOpen(false, 0, 0), fry::healWindowOpen(false, 0, 0));
  TEST_ASSERT_EQUAL(shippedHealWindowOpen(false, 0, fry::kHealMinPlausibleEpoch - 1),
                    fry::healWindowOpen(false, 0, fry::kHealMinPlausibleEpoch - 1));
}

// ---- the rules in heal_fix_rules.h (fail by name on main) ------------------------------------------------------------

#if defined(FRY_HAVE_HEAL_FIX_RULES)

void test_boot_recovery_drops_the_shadows_only_for_a_complete_live_pair() {
  using fry::PairRecovery;
  TEST_ASSERT_TRUE(fry::recoveryFor(true, true) == PairRecovery::DropShadows);      // leftovers of an unconfirmed heal
  TEST_ASSERT_TRUE(fry::recoveryFor(false, false) == PairRecovery::RestoreShadows); // crash after the clear
  // The two half pairs main dropped the shadows for: a restore that wrote the id and not the token, and a crash
  // after the new install id was persisted but before any token.
  TEST_ASSERT_TRUE(fry::recoveryFor(true, false) == PairRecovery::RestoreShadows);
  TEST_ASSERT_TRUE(fry::recoveryFor(false, true) == PairRecovery::RestoreShadows);
}

void test_an_unusable_clock_reading_is_rejected_before_any_cast() {
  TEST_ASSERT_FALSE(fry::healTimeUsable(-1));            // time() error value
  TEST_ASSERT_FALSE(fry::healTimeUsable(-100));          // static_cast<uint32_t>(-100) = 4294967196: "plausible" on main
  TEST_ASSERT_FALSE(fry::healTimeUsable(INT64_MIN));
  TEST_ASSERT_FALSE(fry::healTimeUsable(0));
  TEST_ASSERT_FALSE(fry::healTimeUsable(static_cast<int64_t>(fry::kHealMinPlausibleEpoch) - 1));
  TEST_ASSERT_TRUE(fry::healTimeUsable(fry::kHealMinPlausibleEpoch));
  TEST_ASSERT_TRUE(fry::healTimeUsable(kNow));
  TEST_ASSERT_TRUE(fry::healTimeUsable(fry::kHealMaxPlausibleEpoch));
  TEST_ASSERT_EQUAL_UINT32(kCeiling, fry::kHealMaxPlausibleEpoch);
  TEST_ASSERT_FALSE(fry::healTimeUsable(static_cast<int64_t>(fry::kHealMaxPlausibleEpoch) + 1));
  // A 64-bit time_t past 2^32 would wrap to a plausible uint32_t epoch (2^32 + 1.79e9 -> 1.79e9).
  TEST_ASSERT_FALSE(fry::healTimeUsable((1LL << 32) + static_cast<int64_t>(kNow)));
}

void test_the_retry_body_is_read_only_when_its_length_is_known_and_small() {
  TEST_ASSERT_FALSE(fry::healReplyReadable(-1));      // chunked / unknown: fails closed
  TEST_ASSERT_FALSE(fry::healReplyReadable(0));
  TEST_ASSERT_TRUE(fry::healReplyReadable(1));
  TEST_ASSERT_TRUE(fry::healReplyReadable(120));      // a {"status","device_token"} answer
  TEST_ASSERT_TRUE(fry::healReplyReadable(2048));
  TEST_ASSERT_FALSE(fry::healReplyReadable(2049));
  TEST_ASSERT_FALSE(fry::healReplyReadable(INT_MAX));
  TEST_ASSERT_EQUAL_INT(2048, fry::kHealReplyMaxBytes);
}

void test_the_per_boot_latch_is_released_after_six_hours_of_uptime_and_not_before() {
  TEST_ASSERT_EQUAL_UINT32(21600000UL, fry::kHealLatchReleaseMs);
  TEST_ASSERT_FALSE(fry::healLatchExpired(0));
  TEST_ASSERT_FALSE(fry::healLatchExpired(1));
  TEST_ASSERT_FALSE(fry::healLatchExpired(fry::kHealLatchReleaseMs - 1));
  TEST_ASSERT_TRUE(fry::healLatchExpired(fry::kHealLatchReleaseMs));
  TEST_ASSERT_TRUE(fry::healLatchExpired(fry::kHealLatchReleaseMs + 1));
  TEST_ASSERT_TRUE(fry::healLatchExpired(UINT32_MAX));

  // Across a millis() wrap the unsigned difference is still the elapsed uptime.
  const uint32_t burnedAt = 0xFFFFFF00UL;
  uint32_t nowMs = burnedAt + (fry::kHealLatchReleaseMs - 1);
  TEST_ASSERT_FALSE(fry::healLatchExpired(static_cast<uint32_t>(nowMs - burnedAt)));
  nowMs = burnedAt + fry::kHealLatchReleaseMs;
  TEST_ASSERT_TRUE(fry::healLatchExpired(static_cast<uint32_t>(nowMs - burnedAt)));
}

void test_nothing_changes_inside_the_first_six_hours_and_the_rate_stays_one_per_window() {
  // Differential sweep. Shipped: once burnt, the latch holds for the rest of the uptime. New: it holds until the
  // release. Every uptime second of the first window must agree (both hold), and at no time may the combined gate
  // (latch released AND the persisted window open) admit a second heal inside one 6 h window of the stamp.
  const uint32_t stampEpoch = kNow;  // the heal burnt the latch and wrote this stamp at uptime 0
  long attempts = 0;
  for (uint32_t upSeconds = 0; upSeconds <= 7UL * 3600UL; upSeconds++) {
    const uint32_t upMs = upSeconds * 1000UL;
    const bool shippedHolds = true;
    const bool newHolds = !fry::healLatchExpired(upMs);
    const bool admits = !newHolds && fry::healWindowOpen(false, stampEpoch, stampEpoch + upSeconds);
    if (upSeconds < kWindow) {
      TEST_ASSERT_EQUAL_MESSAGE(shippedHolds, newHolds, "the first 6 h of an uptime must be exactly as shipped");
      TEST_ASSERT_FALSE_MESSAGE(admits, "no second heal inside the window");
    }
    if (admits) attempts++;
  }
  // From the 6 h mark both gates agree, so the heal can fire again: every later second admits it (it still needs a
  // new registration 404, and burns the latch and the stamp again when it does).
  TEST_ASSERT_TRUE(attempts > 3600);
  TEST_ASSERT_TRUE(!fry::healLatchExpired(kWindow * 1000UL - 1) && fry::healLatchExpired(kWindow * 1000UL));
  TEST_ASSERT_TRUE(fry::healWindowOpen(false, stampEpoch, stampEpoch + kWindow));
  TEST_ASSERT_FALSE(fry::healWindowOpen(false, stampEpoch, stampEpoch + kWindow - 1));
  // A wall clock that jumped (or a stamp that did not persist) cannot beat the persisted bound: the latch released
  // at 6 h of uptime, but the window is shut when the clock says less than 6 h passed.
  TEST_ASSERT_FALSE(fry::healWindowOpen(false, stampEpoch, stampEpoch + 3600UL));
}

void test_a_2xx_without_a_device_token_is_not_a_success() {
  TEST_ASSERT_FALSE(fry::healTokenUsable(0));
  TEST_ASSERT_TRUE(fry::healTokenUsable(1));
  TEST_ASSERT_TRUE(fry::healTokenUsable(64));
}

#else  // main: heal_fix_rules.h does not exist

#define FRY_RED_ON_MAIN(name) \
  void name() { TEST_FAIL_MESSAGE("main has no lib/fry_core/heal_fix_rules.h: this rule is missing"); }
FRY_RED_ON_MAIN(test_boot_recovery_drops_the_shadows_only_for_a_complete_live_pair)
FRY_RED_ON_MAIN(test_an_unusable_clock_reading_is_rejected_before_any_cast)
FRY_RED_ON_MAIN(test_the_retry_body_is_read_only_when_its_length_is_known_and_small)
FRY_RED_ON_MAIN(test_the_per_boot_latch_is_released_after_six_hours_of_uptime_and_not_before)
FRY_RED_ON_MAIN(test_nothing_changes_inside_the_first_six_hours_and_the_rate_stays_one_per_window)
FRY_RED_ON_MAIN(test_a_2xx_without_a_device_token_is_not_a_success)
#undef FRY_RED_ON_MAIN

#endif

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_boot_recovery_drops_the_shadows_only_for_a_complete_live_pair);
  RUN_TEST(test_a_clock_past_the_32_bit_ceiling_never_opens_the_window);
  RUN_TEST(test_a_stamp_from_a_future_clock_does_not_block_the_heal_forever);
  RUN_TEST(test_an_unusable_clock_reading_is_rejected_before_any_cast);
  RUN_TEST(test_the_shipped_window_is_unchanged_on_the_plausible_domain);
  RUN_TEST(test_the_retry_body_is_read_only_when_its_length_is_known_and_small);
  RUN_TEST(test_the_per_boot_latch_is_released_after_six_hours_of_uptime_and_not_before);
  RUN_TEST(test_nothing_changes_inside_the_first_six_hours_and_the_rate_stays_one_per_window);
  RUN_TEST(test_a_2xx_without_a_device_token_is_not_a_success);
  return UNITY_END();
}
