// A board that is RUNNING (Wi-Fi joined this boot) but in an API-side Error (4, 6, 9-13, or a key
// refusal raised after the join): who may re-provision it, and whether registration can still
// clear the error (lib/fry_core/provisioning_fsm.*, PROTOCOL.md section 11.8).
//
// Round 1 let any SSID write reset such a board, so anyone in BLE range (no pairing) or on the
// open ESP8266 AP could overwrite its Wi-Fi and wallet - 0.3.x kept Error terminal. And a key
// refusal in that state replaced the API code with 7/8, which a later successful registration
// could no longer clear.
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

ProvInputs untrustedSsid() {
  ProvInputs in = good();
  in.linkTrusted = false;
  return in;
}

// Committed, joined, then registration failed with `detail`.
ProvisioningFsm runningError(ProvErr detail) {
  ProvisioningFsm fsm;
  fsm.feed(ProvEvent::SsidWritten, good());
  fsm.feed(ProvEvent::WalletWritten, good());
  fsm.feed(ProvEvent::WifiUp, good());
  ProvInputs in;
  in.detail = detail;
  fsm.feed(ProvEvent::ApiFail, in);
  return fsm;
}

const ProvErr kApiSide[] = {ProvErr::Reg401, ProvErr::Reg403, ProvErr::Reg409, ProvErr::RegOther4xx,
                            ProvErr::Unreachable};

// ---- F9 ---------------------------------------------------------------------------------------

void test_a_key_refusal_while_running_does_not_block_a_later_registration() {
  ProvisioningFsm fsm = runningError(ProvErr::Unreachable);
  ProvInputs key;
  key.detail = ProvErr::BadKey;
  fsm.feed(ProvEvent::KeyRejected, key);
  TEST_ASSERT_EQUAL((int)ProvErr::BadKey, (int)fsm.error());  // the refusal is still reported
  TEST_ASSERT_TRUE(fsm.feed(ProvEvent::ApiOk, {}));
  TEST_ASSERT_EQUAL((int)ProvState::Connected, (int)fsm.state());
}

void test_a_locked_key_while_running_does_not_block_it_either() {
  ProvisioningFsm fsm = runningError(ProvErr::Reg409);
  ProvInputs key;
  key.detail = ProvErr::KeyLocked;
  fsm.feed(ProvEvent::KeyRejected, key);
  ProvInputs fail;
  fail.detail = ProvErr::Reg401;
  fsm.feed(ProvEvent::ApiFail, fail);  // a later failure replaces the detail again
  TEST_ASSERT_EQUAL((int)ProvErr::Reg401, (int)fsm.error());
  TEST_ASSERT_TRUE(fsm.feed(ProvEvent::ApiOk, {}));
  TEST_ASSERT_EQUAL((int)ProvState::Connected, (int)fsm.state());
}

void test_a_key_refusal_before_any_join_is_not_cleared_by_api_ok() {
  ProvisioningFsm fsm;
  ProvInputs key;
  key.detail = ProvErr::BadKey;
  fsm.feed(ProvEvent::KeyRejected, key);
  TEST_ASSERT_FALSE(fsm.feed(ProvEvent::ApiOk, {}));
  TEST_ASSERT_EQUAL((int)ProvState::Error, (int)fsm.state());
}

// ---- F7 ---------------------------------------------------------------------------------------

void test_an_untrusted_ssid_write_is_ignored_while_running_in_error() {
  for (ProvErr detail : kApiSide) {
    ProvisioningFsm fsm = runningError(detail);
    TEST_ASSERT_FALSE(fsm.acceptsUntrustedWrites());
    TEST_ASSERT_FALSE(fsm.feed(ProvEvent::SsidWritten, untrustedSsid()));
    TEST_ASSERT_EQUAL((int)ProvState::Error, (int)fsm.state());
    TEST_ASSERT_EQUAL((int)detail, (int)fsm.error());
    TEST_ASSERT_FALSE(fsm.feed(ProvEvent::WalletWritten, untrustedSsid()));
    TEST_ASSERT_FALSE(fsm.readyToConnect());
  }
  // The generic registration failure (4) is the same situation.
  ProvisioningFsm generic = runningError(ProvErr::None);
  TEST_ASSERT_EQUAL((int)ProvErr::ApiFail, (int)generic.error());
  TEST_ASSERT_FALSE(generic.acceptsUntrustedWrites());
  generic.feed(ProvEvent::SsidWritten, untrustedSsid());
  TEST_ASSERT_EQUAL((int)ProvState::Error, (int)generic.state());
}

void test_a_key_refusal_raised_while_running_keeps_it_running() {
  ProvisioningFsm fsm = runningError(ProvErr::Reg409);
  ProvInputs key;
  key.detail = ProvErr::BadKey;
  fsm.feed(ProvEvent::KeyRejected, key);
  TEST_ASSERT_FALSE(fsm.acceptsUntrustedWrites());
  fsm.feed(ProvEvent::SsidWritten, untrustedSsid());
  TEST_ASSERT_EQUAL((int)ProvState::Error, (int)fsm.state());
}

void test_a_trusted_ssid_write_still_starts_over() {
  // An encrypted BLE link (the key write paired it), USB, or the WPA2 setup AP.
  for (ProvErr detail : kApiSide) {
    ProvisioningFsm fsm = runningError(detail);
    TEST_ASSERT_TRUE(fsm.feed(ProvEvent::SsidWritten, good()));
    TEST_ASSERT_EQUAL((int)ProvState::Provisioning, (int)fsm.state());
  }
}

void test_wifi_errors_still_reset_on_any_ssid_write() {
  // The U4 fix: a failed join is not "running", and the owner's retry must not need a reboot.
  ProvisioningFsm auth;
  auth.feed(ProvEvent::SsidWritten, good());
  auth.feed(ProvEvent::WalletWritten, good());
  auth.feed(ProvEvent::WifiAuthFail, good());
  TEST_ASSERT_TRUE(auth.acceptsUntrustedWrites());
  TEST_ASSERT_TRUE(auth.feed(ProvEvent::SsidWritten, untrustedSsid()));
  TEST_ASSERT_EQUAL((int)ProvState::Provisioning, (int)auth.state());

  ProvisioningFsm noip;
  noip.feed(ProvEvent::SsidWritten, good());
  noip.feed(ProvEvent::WalletWritten, good());
  noip.feed(ProvEvent::WifiNoIp, good());
  TEST_ASSERT_TRUE(noip.feed(ProvEvent::SsidWritten, untrustedSsid()));
  TEST_ASSERT_EQUAL((int)ProvState::Provisioning, (int)noip.state());
}

void test_errors_raised_before_any_join_accept_untrusted_writes() {
  ProvisioningFsm badWallet;
  ProvInputs noWallet;
  noWallet.ssidValid = true;
  badWallet.feed(ProvEvent::SsidWritten, noWallet);
  badWallet.feed(ProvEvent::WalletWritten, noWallet);
  TEST_ASSERT_TRUE(badWallet.acceptsUntrustedWrites());
  TEST_ASSERT_TRUE(badWallet.feed(ProvEvent::SsidWritten, untrustedSsid()));

  ProvisioningFsm keyless;
  keyless.feed(ProvEvent::SsidWritten, good());
  keyless.feed(ProvEvent::KeyMissing, good());  // commit refused: no key, never joined
  TEST_ASSERT_TRUE(keyless.acceptsUntrustedWrites());
}

void test_outside_error_the_trust_flag_changes_nothing() {
  ProvisioningFsm fsm;
  TEST_ASSERT_TRUE(fsm.acceptsUntrustedWrites());
  TEST_ASSERT_TRUE(fsm.feed(ProvEvent::SsidWritten, untrustedSsid()));
  TEST_ASSERT_EQUAL((int)ProvState::Provisioning, (int)fsm.state());
  ProvInputs defaults;
  TEST_ASSERT_TRUE(defaults.linkTrusted);  // USB/Improv and every pre-v1.1 caller
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_a_key_refusal_while_running_does_not_block_a_later_registration);
  RUN_TEST(test_a_locked_key_while_running_does_not_block_it_either);
  RUN_TEST(test_a_key_refusal_before_any_join_is_not_cleared_by_api_ok);
  RUN_TEST(test_an_untrusted_ssid_write_is_ignored_while_running_in_error);
  RUN_TEST(test_a_key_refusal_raised_while_running_keeps_it_running);
  RUN_TEST(test_a_trusted_ssid_write_still_starts_over);
  RUN_TEST(test_wifi_errors_still_reset_on_any_ssid_write);
  RUN_TEST(test_errors_raised_before_any_join_accept_untrusted_writes);
  RUN_TEST(test_outside_error_the_trust_flag_changes_nothing);
  return UNITY_END();
}
