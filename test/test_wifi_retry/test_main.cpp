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
using fry::SessionState;

namespace {
SessionState none() { return SessionState(); }
SessionState busy() { SessionState x; x.busy = true; x.clientConnected = true; return x; }  // a commit being joined
// The FSM sits in Provisioning (an SSID was written, no commit yet); the client may or may not still be there.
SessionState writing(uint32_t idleMs, bool connected) { SessionState x; x.provisioning = true; x.clientConnected = connected; x.msSinceActivity = idleMs; return x; }
SessionState client(uint32_t idleMs) { SessionState x; x.clientConnected = true; x.msSinceActivity = idleMs; return x; }
}  // namespace

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

void test_a_due_retry_waits_for_a_commit_in_progress_for_as_long_as_it_lasts() {
  JoinRetry r;
  r.onFailure(0, ProvErr::BadSsid);
  uint32_t now = 30000;
  TEST_ASSERT_EQUAL((int)RetryAction::Wait, (int)r.decide(29999, busy(), true));
  // a commit that stays in progress for an hour is never disturbed (the cap does not apply to it)
  for (int i = 0; i < 240; i++) {
    TEST_ASSERT_EQUAL((int)RetryAction::DeferSession, (int)r.decide(now, busy(), true));
    now += fry::kJoinRetryQuietMs;
  }
  // it ends: the retry resumes after the quiet time, not at once
  TEST_ASSERT_EQUAL((int)RetryAction::Wait, (int)r.decide(now - fry::kJoinRetryQuietMs + 1000, none(), true));
  TEST_ASSERT_EQUAL((int)RetryAction::Join, (int)r.decide(now, none(), true));
}

void test_a_provisioning_session_with_recent_activity_defers_the_retry() {
  JoinRetry r;
  r.onFailure(0, ProvErr::BadSsid);
  TEST_ASSERT_EQUAL((int)RetryAction::DeferSession, (int)r.decide(30000, writing(1000, true), true));
  TEST_ASSERT_EQUAL((int)RetryAction::DeferSession, (int)r.decide(45000, writing(fry::kSessionIdleMs - 1, false), true));
}

void test_an_abandoned_provisioning_session_stops_counting_after_the_idle_time() {
  JoinRetry r;
  r.onFailure(0, ProvErr::BadSsid);
  // SSID written, client gone, nothing for 5 minutes: the FSM is still in Provisioning, the retry must go on
  TEST_ASSERT_EQUAL((int)RetryAction::Join, (int)r.decide(30000, writing(fry::kSessionIdleMs, false), true));
  JoinRetry q;
  q.onFailure(0, ProvErr::BadSsid);
  TEST_ASSERT_EQUAL((int)RetryAction::Join, (int)q.decide(30000, writing(fry::kSessionIdleMs, true), true));  // client idle but connected
}

void test_a_provisioning_session_is_capped_like_an_active_client() {
  JoinRetry r;
  r.onFailure(0, ProvErr::BadSsid);
  uint32_t now = 30000;
  RetryAction last = RetryAction::Wait;
  while (now < 30000 + fry::kDeferCapMs + 2 * fry::kJoinRetryQuietMs) {
    last = r.decide(now, writing(1000, true), true);
    if (last == RetryAction::Join) break;
    now += fry::kJoinRetryQuietMs;
  }
  TEST_ASSERT_EQUAL((int)RetryAction::Join, (int)last);
  TEST_ASSERT_TRUE(now - 30000 >= fry::kDeferCapMs);
}

void test_a_client_with_recent_writes_defers_the_retry() {
  JoinRetry r;
  r.onFailure(0, ProvErr::BadSsid);
  TEST_ASSERT_EQUAL((int)RetryAction::DeferSession, (int)r.decide(30000, client(60000), true));
  TEST_ASSERT_EQUAL((int)RetryAction::DeferSession, (int)r.decide(45000, client(fry::kSessionIdleMs - 1), true));
}

void test_an_idle_client_does_not_block_the_retry() {
  JoinRetry r;
  r.onFailure(0, ProvErr::BadSsid);
  TEST_ASSERT_EQUAL((int)RetryAction::Join, (int)r.decide(30000, client(fry::kSessionIdleMs), true));
}

void test_total_deferral_by_an_active_client_is_capped() {
  JoinRetry r;
  r.onFailure(0, ProvErr::BadSsid);
  uint32_t now = 30000;
  const uint32_t start = now;
  RetryAction last = RetryAction::Wait;
  // the client keeps writing (never idle), pass after pass
  while (now - start <= fry::kDeferCapMs + 2 * fry::kJoinRetryQuietMs) {
    last = r.decide(now, client(1000), true);
    if (last == RetryAction::Join) break;
    TEST_ASSERT_TRUE(now - start < fry::kDeferCapMs);
    now += fry::kJoinRetryQuietMs;
  }
  TEST_ASSERT_EQUAL((int)RetryAction::Join, (int)last);
  TEST_ASSERT_TRUE(now - start >= fry::kDeferCapMs);
  TEST_ASSERT_TRUE(now - start <= fry::kDeferCapMs + fry::kJoinRetryQuietMs);
}

void test_the_cap_counts_continuous_deferral_only() {
  JoinRetry r;
  r.onFailure(0, ProvErr::BadSsid);
  uint32_t now = 30000;
  for (int i = 0; i < 20; i++) {  // 5 min of an active client
    r.decide(now, client(1000), true);
    now += fry::kJoinRetryQuietMs;
  }
  // the client leaves; the retry would join, but suppose a commit starts and fails the join: the timer restarts
  r.onFailure(now, ProvErr::BadSsid);
  now += 400000;
  TEST_ASSERT_EQUAL((int)RetryAction::DeferSession, (int)r.decide(now, client(1000), true));
  now += fry::kJoinRetryQuietMs;
  TEST_ASSERT_EQUAL((int)RetryAction::DeferSession, (int)r.decide(now, client(1000), true));
}

void test_unusable_stored_settings_are_rechecked_later_not_joined() {
  JoinRetry r;
  r.onFailure(0, ProvErr::BadSsid);
  TEST_ASSERT_EQUAL((int)RetryAction::DeferUnusable, (int)r.decide(30000, none(), false));
  TEST_ASSERT_EQUAL((int)RetryAction::Wait, (int)r.decide(30000 + fry::kJoinRetryRecheckMs - 1, none(), false));
  TEST_ASSERT_EQUAL((int)RetryAction::Join, (int)r.decide(30000 + fry::kJoinRetryRecheckMs, none(), true));
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
  SessionState session;       // the provisioning session
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
      if (retry.decide(now, session, settingsUsable) == RetryAction::Join) phase = fry::BootPhase::ConnectingWifi;
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
  b.session = busy();
  b.run(600000);
  TEST_ASSERT_EQUAL_INT(1, b.joins);  // no retry while a commit is in progress
  TEST_ASSERT_EQUAL((int)fry::BootPhase::AwaitingProvisioning, (int)b.phase);
  b.session = none();
  b.run(2 * fry::kJoinRetryQuietMs);
  TEST_ASSERT_EQUAL((int)fry::BootPhase::Ready, (int)b.phase);
  TEST_ASSERT_EQUAL_INT(2, b.joins);
}

void test_a_board_with_an_abandoned_setup_rejoins_its_stored_network() {
  Board b;
  b.failJoins = 1;  // down at boot; a phone writes an SSID at ~40 s and leaves
  uint32_t wroteAt = 0;
  while (b.now < 3600000 && b.phase != fry::BootPhase::Ready) {
    if (b.now >= 40000 && wroteAt == 0) wroteAt = b.now;
    b.session = wroteAt ? writing(b.now - wroteAt, false) : none();
    b.pass(1000);
  }
  TEST_ASSERT_EQUAL((int)fry::BootPhase::Ready, (int)b.phase);
  TEST_ASSERT_TRUE(b.now >= wroteAt + fry::kSessionIdleMs);  // not while the setup could still be going on
  TEST_ASSERT_TRUE(b.now <= wroteAt + fry::kSessionIdleMs + 2 * fry::kJoinRetryQuietMs + 20000);
}

void test_an_overnight_ble_client_cannot_keep_the_board_offline() {
  Board b;
  b.failJoins = 1;
  b.session = client(0);  // a client that wrote a moment ago, then holds the link: model it as writing every minute
  uint32_t lastWrite = 0;
  while (b.now < 3600000 && b.phase != fry::BootPhase::Ready) {
    if (b.now - lastWrite >= 60000) lastWrite = b.now;  // a write once a minute: always recent
    b.session = client(b.now - lastWrite);
    b.pass(1000);
  }
  TEST_ASSERT_EQUAL((int)fry::BootPhase::Ready, (int)b.phase);
  TEST_ASSERT_TRUE(b.now < 20UL * 60UL * 1000UL);  // joined within the cap (10 min) plus the first delay
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
  RUN_TEST(test_a_due_retry_waits_for_a_commit_in_progress_for_as_long_as_it_lasts);
  RUN_TEST(test_a_provisioning_session_with_recent_activity_defers_the_retry);
  RUN_TEST(test_an_abandoned_provisioning_session_stops_counting_after_the_idle_time);
  RUN_TEST(test_a_provisioning_session_is_capped_like_an_active_client);
  RUN_TEST(test_a_client_with_recent_writes_defers_the_retry);
  RUN_TEST(test_an_idle_client_does_not_block_the_retry);
  RUN_TEST(test_total_deferral_by_an_active_client_is_capped);
  RUN_TEST(test_the_cap_counts_continuous_deferral_only);
  RUN_TEST(test_unusable_stored_settings_are_rechecked_later_not_joined);
  RUN_TEST(test_a_deferral_never_moves_the_next_attempt_earlier);
  RUN_TEST(test_a_board_whose_network_was_down_at_boot_joins_it_when_it_comes_back);
  RUN_TEST(test_provisioning_stays_available_between_retries);
  RUN_TEST(test_the_retry_goes_on_for_ever_at_the_capped_delay);
  RUN_TEST(test_an_active_session_is_not_disturbed_and_the_retry_resumes_after_it);
  RUN_TEST(test_a_board_with_an_abandoned_setup_rejoins_its_stored_network);
  RUN_TEST(test_an_overnight_ble_client_cannot_keep_the_board_offline);
  RUN_TEST(test_a_rejected_password_class_is_retried_too_only_more_slowly);
  RUN_TEST(test_no_stored_settings_means_no_join);
  return UNITY_END();
}
