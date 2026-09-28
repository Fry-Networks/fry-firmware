// Miner-key policy (lib/fry_core/key_policy.*, PROTOCOL.md section 11): which keys an owner may
// write, what the boot sequence does with the stored one, and who may replace it.
//
// The old firmware minted its own key on first boot and had no way to take one from the owner, so
// a user who already held a FEM- key (dashboard or FEM PC) could never put it on a board. Every
// key below is SYNTHETIC - never a real miner key.
#include <unity.h>

#include <cstring>

#include "key_policy.h"
#include "miner_identity.h"
#include "provisioning_fsm.h"

using fry::BootKeyAction;
using fry::KeyModel;
using fry::KeyTransport;
using fry::KeyWriteVerdict;
using fry::ProvErr;
using fry::ProvEvent;
using fry::ProvInputs;
using fry::ProvisioningFsm;
using fry::ProvState;

namespace {

// Dashboard mints FEM-<32 uppercase base36>, FEM PC FEM-<32 uppercase hex>, migrated legacy
// boards may hold FEM-<32 lowercase hex>.
const char kBase36Key[] = "FEM-TESTKEY0000000000000000000000001";
const char kUpperHexKey[] = "FEM-0123456789ABCDEF0123456789ABCDEF";
const char kLowerHexKey[] = "FEM-0123456789abcdef0123456789abcdef";
const char kMixedKey[] = "FEM-TestKey0000000000000000000000002";
const char kLegacyKey[] = "IOT-0123456789ABCDEF0123456789ABCDEF";

// ---- isAcceptableOwnerKey (C-1) ---------------------------------------------------------------

void test_owner_key_accepts_every_minted_shape_byte_exact() {
  TEST_ASSERT_TRUE(fry::isAcceptableOwnerKey(kBase36Key));
  TEST_ASSERT_TRUE(fry::isAcceptableOwnerKey(kUpperHexKey));
  TEST_ASSERT_TRUE(fry::isAcceptableOwnerKey(kLowerHexKey));
  TEST_ASSERT_TRUE(fry::isAcceptableOwnerKey(kMixedKey));
}

void test_owner_key_rejects_everything_else() {
  TEST_ASSERT_FALSE(fry::isAcceptableOwnerKey(nullptr));
  TEST_ASSERT_FALSE(fry::isAcceptableOwnerKey(""));
  TEST_ASSERT_FALSE(fry::isAcceptableOwnerKey(kLegacyKey));                              // IOT-
  TEST_ASSERT_FALSE(fry::isAcceptableOwnerKey("fem-TESTKEY0000000000000000000000001"));  // prefix case
  TEST_ASSERT_FALSE(fry::isAcceptableOwnerKey("FEM-TESTKEY000000000000000000000001"));   // 31
  TEST_ASSERT_FALSE(fry::isAcceptableOwnerKey("FEM-TESTKEY00000000000000000000000001")); // 33
  TEST_ASSERT_FALSE(fry::isAcceptableOwnerKey("FEM-TESTKEY000000000000000000000000-"));  // punctuation
  TEST_ASSERT_FALSE(fry::isAcceptableOwnerKey(" FEM-TESTKEY000000000000000000000001"));  // no trimming here
  TEST_ASSERT_FALSE(fry::isAcceptableOwnerKey("FEM-TESTKEY000000000000000000000001 "));
}

void test_existing_validator_is_untouched() {
  // isValidMinerKey stays the strict uppercase-hex check; a pinned test elsewhere relies on it.
  TEST_ASSERT_FALSE(fry::isValidMinerKey(kBase36Key));
  TEST_ASSERT_FALSE(fry::isValidMinerKey(kLowerHexKey));
  TEST_ASSERT_TRUE(fry::isValidMinerKey(kUpperHexKey));
}

// ---- decideBootKey (D-2) ----------------------------------------------------------------------

void test_boot_keeps_any_stored_key_in_both_models() {
  const char* stored[] = {kUpperHexKey, kBase36Key, kLowerHexKey, "garbage-a-board-wrote-once"};
  for (const char* k : stored) {
    TEST_ASSERT_EQUAL((int)BootKeyAction::Keep, (int)fry::decideBootKey(KeyModel::UserSupplied, true, k));
    TEST_ASSERT_EQUAL((int)BootKeyAction::Keep, (int)fry::decideBootKey(KeyModel::DeviceKeeps, true, k));
  }
}

void test_boot_migrates_a_legacy_key_in_both_models() {
  TEST_ASSERT_EQUAL((int)BootKeyAction::MigrateLegacy,
                    (int)fry::decideBootKey(KeyModel::UserSupplied, true, kLegacyKey));
  TEST_ASSERT_EQUAL((int)BootKeyAction::MigrateLegacy,
                    (int)fry::decideBootKey(KeyModel::DeviceKeeps, true, kLegacyKey));
}

void test_boot_without_a_key_mints_only_when_the_device_keeps_its_key() {
  TEST_ASSERT_EQUAL((int)BootKeyAction::Mint, (int)fry::decideBootKey(KeyModel::DeviceKeeps, false, nullptr));
  TEST_ASSERT_EQUAL((int)BootKeyAction::Wait, (int)fry::decideBootKey(KeyModel::UserSupplied, false, nullptr));
  // A present-but-empty value is no key at all.
  TEST_ASSERT_EQUAL((int)BootKeyAction::Wait, (int)fry::decideBootKey(KeyModel::UserSupplied, true, ""));
  TEST_ASSERT_EQUAL((int)BootKeyAction::Mint, (int)fry::decideBootKey(KeyModel::DeviceKeeps, true, ""));
}

void test_build_default_is_user_supplied() {
  TEST_ASSERT_EQUAL((int)KeyModel::UserSupplied, (int)fry::kBuildKeyModel);
}

void test_join_needs_a_key_only_when_the_owner_supplies_it() {
  TEST_ASSERT_TRUE(fry::keyAllowsJoin(KeyModel::UserSupplied, true));
  TEST_ASSERT_FALSE(fry::keyAllowsJoin(KeyModel::UserSupplied, false));
  TEST_ASSERT_TRUE(fry::keyAllowsJoin(KeyModel::DeviceKeeps, true));
  TEST_ASSERT_TRUE(fry::keyAllowsJoin(KeyModel::DeviceKeeps, false));
}

// ---- mayWriteKey ------------------------------------------------------------------------------

void test_first_key_is_accepted_over_every_secure_transport() {
  const KeyTransport secure[] = {KeyTransport::Usb, KeyTransport::Ble, KeyTransport::SoftApSecure};
  for (KeyTransport t : secure) {
    TEST_ASSERT_EQUAL((int)KeyWriteVerdict::Accept,
                      (int)fry::mayWriteKey(KeyModel::UserSupplied, t, false, false, true));
  }
}

void test_an_open_softap_never_carries_a_key() {
  TEST_ASSERT_EQUAL((int)KeyWriteVerdict::NeedsSecureAp,
                    (int)fry::mayWriteKey(KeyModel::UserSupplied, KeyTransport::SoftApOpen, false, false, true));
  TEST_ASSERT_EQUAL((int)KeyWriteVerdict::NeedsSecureAp,
                    (int)fry::mayWriteKey(KeyModel::UserSupplied, KeyTransport::SoftApOpen, true, true, true, true));
}

void test_a_malformed_key_is_bad_key() {
  TEST_ASSERT_EQUAL((int)KeyWriteVerdict::BadKey,
                    (int)fry::mayWriteKey(KeyModel::UserSupplied, KeyTransport::Usb, false, false, false));
  TEST_ASSERT_EQUAL((int)KeyWriteVerdict::BadKey,
                    (int)fry::mayWriteKey(KeyModel::DeviceKeeps, KeyTransport::Ble, true, true, false));
}

void test_device_keeps_model_refuses_every_new_key() {
  const KeyTransport all[] = {KeyTransport::Usb, KeyTransport::Ble, KeyTransport::SoftApSecure};
  for (KeyTransport t : all) {
    TEST_ASSERT_EQUAL((int)KeyWriteVerdict::Locked,
                      (int)fry::mayWriteKey(KeyModel::DeviceKeeps, t, true, false, true));
  }
}

void test_a_confirmed_key_is_replaceable_over_usb_only() {
  TEST_ASSERT_EQUAL((int)KeyWriteVerdict::Accept,
                    (int)fry::mayWriteKey(KeyModel::UserSupplied, KeyTransport::Usb, true, true, true));
  TEST_ASSERT_EQUAL((int)KeyWriteVerdict::Locked,
                    (int)fry::mayWriteKey(KeyModel::UserSupplied, KeyTransport::Ble, true, true, true));
  TEST_ASSERT_EQUAL((int)KeyWriteVerdict::Locked,
                    (int)fry::mayWriteKey(KeyModel::UserSupplied, KeyTransport::SoftApSecure, true, true, true));
  // Not yet confirmed by a 2xx registration: still the owner's to correct over the air.
  TEST_ASSERT_EQUAL((int)KeyWriteVerdict::Accept,
                    (int)fry::mayWriteKey(KeyModel::UserSupplied, KeyTransport::Ble, true, false, true));
}

void test_rewriting_the_stored_key_is_a_harmless_no_op() {
  // An app re-provisioning Wi-Fi on a registered board writes the key it already holds first.
  TEST_ASSERT_EQUAL((int)KeyWriteVerdict::Accept,
                    (int)fry::mayWriteKey(KeyModel::UserSupplied, KeyTransport::Ble, true, true, true, true));
  TEST_ASSERT_EQUAL((int)KeyWriteVerdict::Accept,
                    (int)fry::mayWriteKey(KeyModel::DeviceKeeps, KeyTransport::Ble, true, true, true, true));
}

void test_verdicts_map_to_protocol_error_codes() {
  TEST_ASSERT_EQUAL((int)ProvErr::None, (int)fry::keyVerdictProvErr(KeyWriteVerdict::Accept));
  TEST_ASSERT_EQUAL(7, (int)fry::keyVerdictProvErr(KeyWriteVerdict::BadKey));
  TEST_ASSERT_EQUAL(8, (int)fry::keyVerdictProvErr(KeyWriteVerdict::Locked));
  TEST_ASSERT_EQUAL(8, (int)fry::keyVerdictProvErr(KeyWriteVerdict::NeedsSecureAp));
}

// ---- masking + setup code ---------------------------------------------------------------------

void test_mask_keeps_six_chars_and_an_ellipsis() {
  char out[16];
  TEST_ASSERT_EQUAL_size_t(9, fry::maskMinerKey(kBase36Key, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("FEM-TE\xE2\x80\xA6", out);
  TEST_ASSERT_EQUAL_size_t(0, fry::maskMinerKey("", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("", out);
  TEST_ASSERT_EQUAL_size_t(0, fry::maskMinerKey(nullptr, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("", out);
  char tiny[4];
  TEST_ASSERT_EQUAL_size_t(0, fry::maskMinerKey(kBase36Key, tiny, sizeof(tiny)));  // never truncates
}

void test_setup_code_is_eight_unambiguous_chars() {
  char code[9];
  const uint32_t seeds[][2] = {{0, 0}, {0xFFFFFFFFu, 0xFFFFFFFFu}, {0x12345678u, 0x9ABCDEF0u}};
  for (const auto& s : seeds) {
    TEST_ASSERT_TRUE(fry::makeSetupCode(s[0], s[1], code, sizeof(code)));
    TEST_ASSERT_EQUAL_size_t(8, strlen(code));
    for (int i = 0; i < 8; i++) {
      TEST_ASSERT_NOT_NULL(strchr("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", code[i]));
    }
  }
  TEST_ASSERT_FALSE(fry::makeSetupCode(1, 2, code, 8));  // no room for the NUL
  char a[9], b[9];
  fry::makeSetupCode(1, 0, a, sizeof(a));
  fry::makeSetupCode(2, 0, b, sizeof(b));
  TEST_ASSERT_TRUE(strcmp(a, b) != 0);
}

// ---- FSM: key events (append-only ProvEvent values) ------------------------------------------

void test_wallet_commit_without_a_key_is_error_key_required() {
  ProvisioningFsm fsm;
  ProvInputs in;
  in.ssidValid = true;
  fsm.feed(ProvEvent::SsidWritten, in);
  TEST_ASSERT_TRUE(fsm.feed(ProvEvent::KeyMissing, in));
  TEST_ASSERT_EQUAL((int)ProvState::Error, (int)fsm.state());
  TEST_ASSERT_EQUAL((int)ProvErr::KeyRequired, (int)fsm.error());
  TEST_ASSERT_FALSE(fsm.readyToConnect());
}

void test_rejected_key_write_is_error_with_its_detail() {
  ProvisioningFsm fsm;
  ProvInputs in;
  in.detail = ProvErr::BadKey;
  TEST_ASSERT_TRUE(fsm.feed(ProvEvent::KeyRejected, in));  // allowed from Idle (09 before 01)
  TEST_ASSERT_EQUAL((int)ProvState::Error, (int)fsm.state());
  TEST_ASSERT_EQUAL((int)ProvErr::BadKey, (int)fsm.error());

  // A later rejection in Error replaces the detail, it does not stack.
  in.detail = ProvErr::KeyLocked;
  fsm.feed(ProvEvent::KeyRejected, in);
  TEST_ASSERT_EQUAL((int)ProvErr::KeyLocked, (int)fsm.error());

  // Anything that is not a key code is reported as BadKey, never as a registration error.
  ProvisioningFsm fsm2;
  in.detail = ProvErr::Reg401;
  fsm2.feed(ProvEvent::KeyRejected, in);
  TEST_ASSERT_EQUAL((int)ProvErr::BadKey, (int)fsm2.error());
}

void test_key_missing_after_wifi_up_is_reported_too() {
  // Improv Serial commits Wi-Fi only; the board joins, then has no key to register with.
  ProvisioningFsm fsm;
  ProvInputs in;
  in.ssidValid = true;
  fsm.feed(ProvEvent::SsidWritten, in);
  fsm.feed(ProvEvent::WifiOnlyCommit, in);
  fsm.feed(ProvEvent::WifiUp, in);
  fsm.feed(ProvEvent::KeyMissing, in);
  TEST_ASSERT_EQUAL((int)ProvState::Error, (int)fsm.state());
  TEST_ASSERT_EQUAL((int)ProvErr::KeyRequired, (int)fsm.error());
}

void test_key_events_never_disturb_connected() {
  ProvisioningFsm fsm;
  ProvInputs in;
  in.ssidValid = true;
  in.walletValid = true;
  fsm.feed(ProvEvent::SsidWritten, in);
  fsm.feed(ProvEvent::WalletWritten, in);
  fsm.feed(ProvEvent::WifiUp, in);
  fsm.feed(ProvEvent::ApiOk, in);
  TEST_ASSERT_EQUAL((int)ProvState::Connected, (int)fsm.state());
  in.detail = ProvErr::BadKey;
  TEST_ASSERT_FALSE(fsm.feed(ProvEvent::KeyRejected, in));
  TEST_ASSERT_FALSE(fsm.feed(ProvEvent::KeyMissing, in));
  TEST_ASSERT_EQUAL((int)ProvState::Connected, (int)fsm.state());
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_owner_key_accepts_every_minted_shape_byte_exact);
  RUN_TEST(test_owner_key_rejects_everything_else);
  RUN_TEST(test_existing_validator_is_untouched);
  RUN_TEST(test_boot_keeps_any_stored_key_in_both_models);
  RUN_TEST(test_boot_migrates_a_legacy_key_in_both_models);
  RUN_TEST(test_boot_without_a_key_mints_only_when_the_device_keeps_its_key);
  RUN_TEST(test_build_default_is_user_supplied);
  RUN_TEST(test_join_needs_a_key_only_when_the_owner_supplies_it);
  RUN_TEST(test_first_key_is_accepted_over_every_secure_transport);
  RUN_TEST(test_an_open_softap_never_carries_a_key);
  RUN_TEST(test_a_malformed_key_is_bad_key);
  RUN_TEST(test_device_keeps_model_refuses_every_new_key);
  RUN_TEST(test_a_confirmed_key_is_replaceable_over_usb_only);
  RUN_TEST(test_rewriting_the_stored_key_is_a_harmless_no_op);
  RUN_TEST(test_verdicts_map_to_protocol_error_codes);
  RUN_TEST(test_mask_keeps_six_chars_and_an_ellipsis);
  RUN_TEST(test_setup_code_is_eight_unambiguous_chars);
  RUN_TEST(test_wallet_commit_without_a_key_is_error_key_required);
  RUN_TEST(test_rejected_key_write_is_error_with_its_detail);
  RUN_TEST(test_key_missing_after_wifi_up_is_reported_too);
  RUN_TEST(test_key_events_never_disturb_connected);
  return UNITY_END();
}
