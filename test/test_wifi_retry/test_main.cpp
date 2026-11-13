// Retrying the stored network after a failed join at boot (lib/fry_core/wifi_retry.*).
//
// A boot made one 20 s join attempt; when it failed the board waited in the provisioning phase,
// which only a new provisioning commit leaves, so a stored network that was unreachable for those
// seconds kept the board offline until it was power-cycled.
#include <unity.h>

#include <cstdint>

#include "boot_policy.h"
#include "wifi_retry.h"

using fry::JoinRetry;
using fry::ProvErr;
using fry::RetryAction;

namespace {

// ---- the schedule --------------------------------------------------------------------------------

void test_a_non_credential_failure_is_retried_soon_and_the_delay_grows_to_a_cap() {
  const uint32_t want[] = {30000, 60000, 120000, 240000, 300000, 300000, 300000};
  for (uint32_t n = 1; n <= 7; n++) TEST_ASSERT_EQUAL_UINT32(want[n - 1], fry::joinRetryDelayMs(n, false));
  TEST_ASSERT_EQUAL_UINT32(300000, fry::joinRetryDelayMs(0xFFFFFFFFu, false));
}

void test_a_credential_class_failure_is_retried_more_slowly_but_never_abandoned() {
  const uint32_t want[] = {120000, 240000, 480000, 900000, 900000};
  for (uint32_t n = 1; n <= 5; n++) TEST_ASSERT_EQUAL_UINT32(want[n - 1], fry::joinRetryDelayMs(n, true));
  for (uint32_t n = 1; n <= 20; n++) TEST_ASSERT_TRUE(fry::joinRetryDelayMs(n, true) > fry::joinRetryDelayMs(n, false) || n >= 5);
  JoinRetry r;
  for (int i = 0; i < 200; i++) r.onFailure(0, ProvErr::WifiAuth);
  TEST_ASSERT_TRUE(r.armed());
  TEST_ASSERT_EQUAL_UINT32(900000, r.lastDelayMs());
}

void test_the_first_retry_comes_30_s_after_the_failed_boot_join() {
  JoinRetry r;
  TEST_ASSERT_FALSE(r.due(1000000));  // never armed: nothing to retry
  r.onFailure(25000, ProvErr::BadSsid);  // the 20 s join ended at 25 s
  TEST_ASSERT_FALSE(r.due(25000 + 29999));
  TEST_ASSERT_TRUE(r.due(25000 + 30000));
  TEST_ASSERT_EQUAL_UINT32(1, r.failures());
}

void test_the_class_of_the_last_failure_picks_the_delay() {
  JoinRetry r;
  r.onFailure(0, ProvErr::NoIp);
  TEST_ASSERT_EQUAL_UINT32(30000, r.lastDelayMs());
  r.onFailure(0, ProvErr::WifiAuth);
  TEST_ASSERT_EQUAL_UINT32(240000, r.lastDelayMs());  // second failure, credential class
}

void test_a_join_that_succeeds_forgets_everything() {
  JoinRetry r;
  r.onFailure(0, ProvErr::BadSsid);
  r.onFailure(40000, ProvErr::BadSsid);
  r.onSuccess();
  TEST_ASSERT_FALSE(r.armed());
  TEST_ASSERT_EQUAL_UINT32(0, r.failures());
  TEST_ASSERT_FALSE(r.due(0xFFFFFFF0u));
  r.onFailure(100000, ProvErr::BadSsid);  // a later failure starts over at 30 s
  TEST_ASSERT_EQUAL_UINT32(30000, r.lastDelayMs());
}

void test_the_millisecond_clock_wrapping_does_not_fire_or_stall_the_retry() {
  JoinRetry r;
  const uint32_t near = 0xFFFFFFFFu - 10000;
  r.onFailure(near, ProvErr::BadSsid);  // due 30 s later, past the wrap
  TEST_ASSERT_FALSE(r.due(near + 5000));
  TEST_ASSERT_FALSE(r.due(5000));  // 15 s after the failure, wrapped
  TEST_ASSERT_TRUE(r.due(25000));  // 35 s after the failure
}

// ---- the pause while a provisioning session is active --------------------------------------------------

void test_a_due_retry_waits_for_a_provisioning_session_and_resumes_after_it() {
  JoinRetry r;
  r.onFailure(0, ProvErr::BadSsid);
  uint32_t now = 30000;
  TEST_ASSERT_EQUAL((int)RetryAction::Wait, (int)fry::nextRetryAction(r, 29999, false, true));
  TEST_ASSERT_EQUAL((int)RetryAction::DeferSession, (int)fry::nextRetryAction(r, now, true, true));
  r.defer(now, fry::kJoinRetryQuietMs);
  // while the client stays connected the retry keeps being pushed back and never fires
  for (int i = 0; i < 20; i++) {
    now += 5000;
    if (fry::nextRetryAction(r, now, true, true) == RetryAction::DeferSession) r.defer(now, fry::kJoinRetryQuietMs);
    TEST_ASSERT_TRUE(fry::nextRetryAction(r, now, true, true) != RetryAction::Join);
  }
  // the session ends: not at once, after the quiet time
  TEST_ASSERT_EQUAL((int)RetryAction::Wait, (int)fry::nextRetryAction(r, now + 1000, false, true));
  TEST_ASSERT_EQUAL((int)RetryAction::Join, (int)fry::nextRetryAction(r, now + fry::kJoinRetryQuietMs, false, true));
}

void test_unusable_stored_settings_are_rechecked_later_not_joined() {
  JoinRetry r;
  r.onFailure(0, ProvErr::BadSsid);
  TEST_ASSERT_EQUAL((int)RetryAction::DeferUnusable, (int)fry::nextRetryAction(r, 30000, false, false));
  r.defer(30000, fry::kJoinRetryRecheckMs);
  TEST_ASSERT_EQUAL((int)RetryAction::Wait, (int)fry::nextRetryAction(r, 30000 + fry::kJoinRetryRecheckMs - 1, false, false));
  TEST_ASSERT_EQUAL((int)RetryAction::Join, (int)fry::nextRetryAction(r, 30000 + fry::kJoinRetryRecheckMs, false, true));
}

void test_a_deferral_never_moves_the_next_attempt_earlier() {
  JoinRetry r;
  r.onFailure(0, ProvErr::BadSsid);
  for (int i = 0; i < 6; i++) r.onFailure(0, ProvErr::BadSsid);  // next retry 300 s away
  r.defer(10000, 1000);
  TEST_ASSERT_FALSE(r.due(299999));
  TEST_ASSERT_TRUE(r.due(300000));
}

// ---- the phase machine around it -----------------------------------------------------------------------
//
// The same steps src/main.cpp takes: a boot join (blocking, 20 s) ends in AwaitingProvisioning on failure
// and in Ready on success; in AwaitingProvisioning the loop asks nextRetryAction() and starts another join
// when it says Join. Provisioning stays available the whole time (the phase is AwaitingProvisioning).

struct Board {
  fry::BootPhase phase = fry::BootPhase::ConnectingWifi;
  JoinRetry retry;
  uint32_t now = 0;
  int joins = 0;
  int failJoins = 0;          // the first K joins fail
  ProvErr failWith = ProvErr::BadSsid;
  bool session = false;       // a provisioning client is connected
  bool settingsUsable = true;
  int lateSuccessLines = 0;

  void join() {
    joins++;
    now += 20000;  // the blocking join window
    if (joins <= failJoins) {
      phase = fry::BootPhase::AwaitingProvisioning;
      retry.onFailure(now, failWith);
    } else {
      if (retry.failures() > 0) lateSuccessLines++;
      retry.onSuccess();
      phase = fry::BootPhase::Ready;
    }
  }
  // One loop pass, `dtMs` after the previous one.
  void pass(uint32_t dtMs) {
    now += dtMs;
    if (phase == fry::BootPhase::ConnectingWifi) {
      join();
      return;
    }
    if (phase == fry::BootPhase::AwaitingProvisioning) {
      const RetryAction a = fry::nextRetryAction(retry, now, session, settingsUsable);
      if (a == RetryAction::Join) {
        phase = fry::BootPhase::ConnectingWifi;
      } else if (a == RetryAction::DeferSession) {
        retry.defer(now, fry::kJoinRetryQuietMs);
      } else if (a == RetryAction::DeferUnusable) {
        retry.defer(now, fry::kJoinRetryRecheckMs);
      }
    }
  }
  void run(uint32_t totalMs, uint32_t stepMs = 1000) {
    const uint32_t end = now + totalMs;
    while (now < end && phase != fry::BootPhase::Ready) pass(stepMs);
  }
};

void test_a_board_whose_network_was_down_at_boot_joins_it_when_it_comes_back() {
  Board b;
  b.failJoins = 2;  // down for the boot join and the first retry
  b.run(600000);
  TEST_ASSERT_EQUAL((int)fry::BootPhase::Ready, (int)b.phase);
  TEST_ASSERT_EQUAL_INT(3, b.joins);
  TEST_ASSERT_EQUAL_INT(1, b.lateSuccessLines);
  TEST_ASSERT_FALSE(b.retry.armed());
}

void test_provisioning_stays_available_between_retries() {
  Board b;
  b.failJoins = 1000;
  b.run(900000);
  TEST_ASSERT_EQUAL((int)fry::BootPhase::AwaitingProvisioning, (int)b.phase);
  TEST_ASSERT_TRUE(b.retry.armed());
  TEST_ASSERT_TRUE(b.joins >= 4);
}

void test_the_retry_goes_on_for_ever_at_the_capped_delay() {
  Board b;
  b.failJoins = 100000;
  const uint32_t day = 24UL * 3600UL * 1000UL;
  b.run(day);
  // 30, 60, 120, 240 s, then every 300 s (each retry also spends its own 20 s join window)
  TEST_ASSERT_TRUE(b.joins > 200);
  TEST_ASSERT_TRUE(b.joins < 300);
  TEST_ASSERT_EQUAL((int)fry::BootPhase::AwaitingProvisioning, (int)b.phase);
}

void test_an_active_session_is_not_disturbed_and_the_retry_resumes_after_it() {
  Board b;
  b.failJoins = 1;  // only the boot join fails
  b.session = true;
  b.run(600000);
  TEST_ASSERT_EQUAL_INT(1, b.joins);  // no retry while the client stays connected
  TEST_ASSERT_EQUAL((int)fry::BootPhase::AwaitingProvisioning, (int)b.phase);
  b.session = false;
  b.run(2 * fry::kJoinRetryQuietMs);
  TEST_ASSERT_EQUAL((int)fry::BootPhase::Ready, (int)b.phase);
  TEST_ASSERT_EQUAL_INT(2, b.joins);
}

void test_a_rejected_password_class_is_retried_too_only_more_slowly() {
  Board fast, slow;
  fast.failJoins = slow.failJoins = 1000;
  slow.failWith = ProvErr::WifiAuth;
  fast.run(1800000);
  slow.run(1800000);
  TEST_ASSERT_TRUE(slow.joins >= 3);
  TEST_ASSERT_TRUE(slow.joins < fast.joins);
}

void test_no_stored_settings_means_no_join() {
  Board b;
  b.failJoins = 1000;
  b.settingsUsable = false;
  b.run(900000);
  TEST_ASSERT_EQUAL_INT(1, b.joins);  // only the boot attempt; the stored settings are rechecked, not joined
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_a_non_credential_failure_is_retried_soon_and_the_delay_grows_to_a_cap);
  RUN_TEST(test_a_credential_class_failure_is_retried_more_slowly_but_never_abandoned);
  RUN_TEST(test_the_first_retry_comes_30_s_after_the_failed_boot_join);
  RUN_TEST(test_the_class_of_the_last_failure_picks_the_delay);
  RUN_TEST(test_a_join_that_succeeds_forgets_everything);
  RUN_TEST(test_the_millisecond_clock_wrapping_does_not_fire_or_stall_the_retry);
  RUN_TEST(test_a_due_retry_waits_for_a_provisioning_session_and_resumes_after_it);
  RUN_TEST(test_unusable_stored_settings_are_rechecked_later_not_joined);
  RUN_TEST(test_a_deferral_never_moves_the_next_attempt_earlier);
  RUN_TEST(test_a_board_whose_network_was_down_at_boot_joins_it_when_it_comes_back);
  RUN_TEST(test_provisioning_stays_available_between_retries);
  RUN_TEST(test_the_retry_goes_on_for_ever_at_the_capped_delay);
  RUN_TEST(test_an_active_session_is_not_disturbed_and_the_retry_resumes_after_it);
  RUN_TEST(test_a_rejected_password_class_is_retried_too_only_more_slowly);
  RUN_TEST(test_no_stored_settings_means_no_join);
  return UNITY_END();
}
