// Regression (U4/U8): the provisioning state machine latched in Error until a reboot.
//
// A board whose join failed once, or whose registration failed once, reported Error forever: a
// second attempt from the app wrote the SSID again and was ignored, and a registration that
// succeeded on the device's own later retry never reached the status characteristic. Owners were
// told to power-cycle a board that was in fact working.
//
// Deliberately written against the pre-v1.1 FSM API only (no new events or error codes), so the
// same file compiles against the pre-fix code and fails there.
#include <unity.h>

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

ProvisioningFsm committed() {
  ProvisioningFsm fsm;
  fsm.feed(ProvEvent::SsidWritten, good());
  fsm.feed(ProvEvent::WalletWritten, good());
  return fsm;
}

void test_an_ssid_write_after_a_failed_join_starts_a_new_attempt() {
  ProvisioningFsm fsm = committed();
  fsm.feed(ProvEvent::WifiAuthFail, good());
  TEST_ASSERT_EQUAL((int)ProvState::Error, (int)fsm.state());

  TEST_ASSERT_TRUE(fsm.feed(ProvEvent::SsidWritten, good()));
  TEST_ASSERT_EQUAL((int)ProvState::Provisioning, (int)fsm.state());
  TEST_ASSERT_EQUAL((int)ProvErr::None, (int)fsm.error());

  TEST_ASSERT_TRUE(fsm.feed(ProvEvent::WalletWritten, good()));
  TEST_ASSERT_TRUE(fsm.readyToConnect());
}

void test_an_invalid_ssid_after_an_error_is_reported_as_bad_ssid() {
  ProvisioningFsm fsm = committed();
  fsm.feed(ProvEvent::WifiNoIp, good());
  ProvInputs bad;
  fsm.feed(ProvEvent::SsidWritten, bad);
  TEST_ASSERT_EQUAL((int)ProvState::Error, (int)fsm.state());
  TEST_ASSERT_EQUAL((int)ProvErr::BadSsid, (int)fsm.error());
}

void test_a_late_registration_success_reaches_connected() {
  ProvisioningFsm fsm = committed();
  fsm.feed(ProvEvent::WifiUp, good());
  fsm.feed(ProvEvent::ApiFail, good());
  TEST_ASSERT_EQUAL((int)ProvState::Error, (int)fsm.state());
  TEST_ASSERT_EQUAL((int)ProvErr::ApiFail, (int)fsm.error());

  TEST_ASSERT_TRUE(fsm.feed(ProvEvent::ApiOk, good()));
  TEST_ASSERT_EQUAL((int)ProvState::Connected, (int)fsm.state());
  TEST_ASSERT_EQUAL((int)ProvErr::None, (int)fsm.error());
}

void test_api_ok_never_hides_a_wifi_error() {
  // Controls: Error that did not come from the API side stays Error on ApiOk.
  ProvisioningFsm auth = committed();
  auth.feed(ProvEvent::WifiAuthFail, good());
  TEST_ASSERT_FALSE(auth.feed(ProvEvent::ApiOk, good()));
  TEST_ASSERT_EQUAL((int)ProvErr::WifiAuth, (int)auth.error());

  ProvisioningFsm wallet;
  ProvInputs noWallet;
  noWallet.ssidValid = true;
  wallet.feed(ProvEvent::SsidWritten, noWallet);
  wallet.feed(ProvEvent::WalletWritten, noWallet);
  TEST_ASSERT_EQUAL((int)ProvErr::BadWallet, (int)wallet.error());
  TEST_ASSERT_FALSE(wallet.feed(ProvEvent::ApiOk, good()));
  TEST_ASSERT_EQUAL((int)ProvState::Error, (int)wallet.state());
}

void test_api_fail_before_wifi_up_is_not_recovered_by_api_ok() {
  // Without the Wi-Fi latch an ApiOk is out of order, exactly as it is in Connecting.
  ProvisioningFsm fsm = committed();
  fsm.feed(ProvEvent::ApiFail, good());
  TEST_ASSERT_FALSE(fsm.feed(ProvEvent::ApiOk, good()));
  TEST_ASSERT_EQUAL((int)ProvState::Error, (int)fsm.state());
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_an_ssid_write_after_a_failed_join_starts_a_new_attempt);
  RUN_TEST(test_an_invalid_ssid_after_an_error_is_reported_as_bad_ssid);
  RUN_TEST(test_a_late_registration_success_reaches_connected);
  RUN_TEST(test_api_ok_never_hides_a_wifi_error);
  RUN_TEST(test_api_fail_before_wifi_up_is_not_recovered_by_api_ok);
  return UNITY_END();
}
