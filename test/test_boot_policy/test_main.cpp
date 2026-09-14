// Regression: a board whose stored WiFi credentials stop working must still be discoverable.
//
// Reported on Discord 2026-09-12 as "The Android app does not see my ESP32 board". A board that
// has credentials in storage boots straight to ConnectingWifi, so the provisioning transport is
// never started; when the join then fails the boot sequence drops back to AwaitingProvisioning
// with no BLE advertising and no softAP. The board is invisible to the app, and because the only
// factory reset lives behind a lab-only serial command there is no way back for a user at all.
#include <unity.h>

#include "boot_policy.h"

using fry::BootPhase;
using fry::BootPolicy;

namespace {

BootPolicy policy;

void test_unprovisioned_boot_starts_the_transport() {
  TEST_ASSERT_EQUAL((int)BootPhase::AwaitingProvisioning, (int)fry::initialBootPhase(false));

  TEST_ASSERT_TRUE(policy.onPhaseEntry(BootPhase::AwaitingProvisioning));
  TEST_ASSERT_TRUE(policy.transportStarted());
}

void test_provisioned_boot_skips_straight_to_wifi() {
  TEST_ASSERT_EQUAL((int)BootPhase::ConnectingWifi, (int)fry::initialBootPhase(true));

  // Nothing to advertise to while the join is still in flight, so the radio stays off. On ESP8266
  // this matters for more than power: starting the transport switches the radio to WIFI_AP.
  TEST_ASSERT_FALSE(policy.onPhaseEntry(BootPhase::ConnectingWifi));
  TEST_ASSERT_FALSE(policy.transportStarted());
}

void test_failed_wifi_join_starts_the_transport() {
  // The reported failure, start to finish: credentials in storage, join fails, phase returns to
  // AwaitingProvisioning. The transport MUST come up here or the board is unreachable for good.
  policy.onPhaseEntry(fry::initialBootPhase(true));

  TEST_ASSERT_TRUE(policy.onPhaseEntry(BootPhase::AwaitingProvisioning));
  TEST_ASSERT_TRUE(policy.transportStarted());
}

void test_repeated_join_failures_start_the_transport_only_once() {
  policy.onPhaseEntry(fry::initialBootPhase(true));
  TEST_ASSERT_TRUE(policy.onPhaseEntry(BootPhase::AwaitingProvisioning));

  // Retry loop: ConnectingWifi -> AwaitingProvisioning -> ConnectingWifi -> ... The transport is
  // already up, so the caller must not be told to start it again (NimBLE init is not idempotent).
  TEST_ASSERT_FALSE(policy.onPhaseEntry(BootPhase::ConnectingWifi));
  TEST_ASSERT_FALSE(policy.onPhaseEntry(BootPhase::AwaitingProvisioning));
  TEST_ASSERT_TRUE(policy.transportStarted());
}

void test_ready_phase_never_starts_the_transport() {
  policy.onPhaseEntry(fry::initialBootPhase(true));

  TEST_ASSERT_FALSE(policy.onPhaseEntry(BootPhase::Ready));
  TEST_ASSERT_FALSE(policy.transportStarted());
}

void test_successful_provisioning_does_not_restart_the_transport() {
  // Unprovisioned boot -> provisioned over the transport -> joins -> Ready. One start, no more.
  TEST_ASSERT_TRUE(policy.onPhaseEntry(BootPhase::AwaitingProvisioning));
  TEST_ASSERT_FALSE(policy.onPhaseEntry(BootPhase::ConnectingWifi));
  TEST_ASSERT_FALSE(policy.onPhaseEntry(BootPhase::Ready));
  TEST_ASSERT_TRUE(policy.transportStarted());
}

}  // namespace

// Unity's setUp/tearDown have C linkage (unity.h declares them inside an extern "C" block), so
// they must sit at global scope — inside an anonymous namespace they silently never run.
void setUp() { policy = BootPolicy(); }

void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_unprovisioned_boot_starts_the_transport);
  RUN_TEST(test_provisioned_boot_skips_straight_to_wifi);
  RUN_TEST(test_failed_wifi_join_starts_the_transport);
  RUN_TEST(test_repeated_join_failures_start_the_transport_only_once);
  RUN_TEST(test_ready_phase_never_starts_the_transport);
  RUN_TEST(test_successful_provisioning_does_not_restart_the_transport);
  return UNITY_END();
}
