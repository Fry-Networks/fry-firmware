// Improv 0x01 (Wi-Fi settings over USB) is accepted in EVERY phase (PROTOCOL.md section 11.8,
// round 2 F8). The transports' commitWifiOnlyCredentials() used to reset the FSM only from Error, so
// a board provisioned earlier this boot - FSM Connected, or Connecting while registration retries -
// answered a later 0x01 with InvalidRpc: SsidWritten is ignored in those states and commitWifiOnly
// persists nothing. resetForWifiOnlyCommit() (lib/fry_core/provisioning_commit.h) is the one rule
// both transports now apply before feeding the SSID.
#include <unity.h>

#include "provisioning_commit.h"
#include "provisioning_fsm.h"

using fry::ProvErr;
using fry::ProvEvent;
using fry::ProvInputs;
using fry::ProvisioningFsm;
using fry::ProvState;

namespace {

ProvInputs good() {
  ProvInputs in;
  in.ssidValid = true;
  in.walletValid = true;
  return in;
}

// What the transports do for a 0x01 after the reset rule: SSID, then the wallet-less commit.
bool improvCommit(ProvisioningFsm& fsm, bool* persisted) {
  fry::resetForWifiOnlyCommit(fsm);
  fsm.feed(ProvEvent::SsidWritten, good());
  fry::commitWifiOnly(fsm, [&]() { *persisted = true; });
  return fsm.readyToConnect();
}

ProvisioningFsm committed() {
  ProvisioningFsm fsm;
  fsm.feed(ProvEvent::SsidWritten, good());
  fsm.feed(ProvEvent::WalletWritten, good());
  return fsm;  // Connecting: the join is about to start
}

void test_a_connected_board_takes_new_wifi_settings_over_usb() {
  ProvisioningFsm fsm = committed();
  fsm.feed(ProvEvent::WifiUp, {});
  fsm.feed(ProvEvent::ApiOk, {});
  TEST_ASSERT_EQUAL((int)ProvState::Connected, (int)fsm.state());
  bool persisted = false;
  TEST_ASSERT_TRUE(improvCommit(fsm, &persisted));
  TEST_ASSERT_TRUE(persisted);
  TEST_ASSERT_EQUAL((int)ProvErr::None, (int)fsm.error());
}

void test_a_board_still_waiting_for_registration_takes_them_too() {
  ProvisioningFsm fsm = committed();
  fsm.feed(ProvEvent::WifiUp, {});  // joined; registration is retrying on its own schedule
  TEST_ASSERT_EQUAL((int)ProvState::Connecting, (int)fsm.state());
  bool persisted = false;
  TEST_ASSERT_TRUE(improvCommit(fsm, &persisted));
  TEST_ASSERT_TRUE(persisted);
}

void test_a_board_running_in_an_api_error_takes_them_usb_is_trusted() {
  ProvisioningFsm fsm = committed();
  fsm.feed(ProvEvent::WifiUp, {});
  ProvInputs in;
  in.detail = ProvErr::Reg409;
  fsm.feed(ProvEvent::ApiFail, in);
  TEST_ASSERT_FALSE(fsm.acceptsUntrustedWrites());  // BLE/open-AP writes are dropped here (F7) ...
  bool persisted = false;
  TEST_ASSERT_TRUE(improvCommit(fsm, &persisted));  // ... USB is physical access and starts over
  TEST_ASSERT_TRUE(persisted);
}

void test_a_failed_join_still_starts_over_as_before() {
  ProvisioningFsm fsm = committed();
  fsm.feed(ProvEvent::WifiAuthFail, {});
  TEST_ASSERT_EQUAL((int)ProvState::Error, (int)fsm.state());
  bool persisted = false;
  TEST_ASSERT_TRUE(improvCommit(fsm, &persisted));
  TEST_ASSERT_TRUE(persisted);
}

void test_idle_and_provisioning_are_not_reset() {
  ProvisioningFsm idle;
  fry::resetForWifiOnlyCommit(idle);
  TEST_ASSERT_EQUAL((int)ProvState::Idle, (int)idle.state());

  ProvisioningFsm prov;
  prov.feed(ProvEvent::SsidWritten, good());
  TEST_ASSERT_EQUAL((int)ProvState::Provisioning, (int)prov.state());
  fry::resetForWifiOnlyCommit(prov);
  TEST_ASSERT_EQUAL((int)ProvState::Provisioning, (int)prov.state());  // a re-written SSID is fine

  bool persisted = false;
  TEST_ASSERT_TRUE(improvCommit(prov, &persisted));
  TEST_ASSERT_TRUE(persisted);
}

void test_without_the_reset_a_connected_board_persists_nothing() {
  // The round-1 transport rule (reset from Error only), kept here as the reason the helper exists.
  ProvisioningFsm fsm = committed();
  fsm.feed(ProvEvent::WifiUp, {});
  fsm.feed(ProvEvent::ApiOk, {});
  if (fsm.state() == ProvState::Error) fsm.feed(ProvEvent::Reset, {});
  fsm.feed(ProvEvent::SsidWritten, good());
  bool persisted = false;
  fry::commitWifiOnly(fsm, [&]() { persisted = true; });
  TEST_ASSERT_FALSE(persisted);
  TEST_ASSERT_FALSE(fsm.readyToConnect());
  TEST_ASSERT_EQUAL((int)ProvState::Connected, (int)fsm.state());
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_a_connected_board_takes_new_wifi_settings_over_usb);
  RUN_TEST(test_a_board_still_waiting_for_registration_takes_them_too);
  RUN_TEST(test_a_board_running_in_an_api_error_takes_them_usb_is_trusted);
  RUN_TEST(test_a_failed_join_still_starts_over_as_before);
  RUN_TEST(test_idle_and_provisioning_are_not_reset);
  RUN_TEST(test_without_the_reset_a_connected_board_persists_nothing);
  return UNITY_END();
}
