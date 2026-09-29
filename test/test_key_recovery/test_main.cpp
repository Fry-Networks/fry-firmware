// Key RECOVERY for fielded boards (lib/fry_core/key_policy.*, PROTOCOL.md section 11.8).
//
// A board minted its key as SHA256(mac6 || salt) and keeps the salt next to it. If fry/minerKey is
// lost (a dropped NVS entry, a damaged LittleFS file on ESP8266) while the salt survives, 0.3.x
// derived the very same key again on the next boot. Round-1 0.4.0 (USER_SUPPLIED) waited for the
// owner instead, dropping a working miner back into provisioning. Recovery re-derives the SAME
// key; it never mints a new one, and never touches a key the owner wrote.
#include <unity.h>

#include "key_policy.h"

using fry::BootKeyAction;
using fry::KeyModel;

namespace {

void test_a_lost_minted_key_is_recovered_from_the_salt() {
  TEST_ASSERT_EQUAL((int)BootKeyAction::Recover,
                    (int)fry::decideBootKey(KeyModel::UserSupplied, false, nullptr, true, false));
  TEST_ASSERT_EQUAL((int)BootKeyAction::Recover,
                    (int)fry::decideBootKey(KeyModel::UserSupplied, true, "", true, false));
}

void test_a_lost_owner_key_is_never_re_derived() {
  // keySrc == "user": the salt has nothing to do with that key.
  TEST_ASSERT_EQUAL((int)BootKeyAction::Wait,
                    (int)fry::decideBootKey(KeyModel::UserSupplied, false, nullptr, true, true));
}

void test_without_a_salt_a_user_supplied_board_still_waits() {
  // A new 0.4 board: never minted anything, so there is nothing to recover.
  TEST_ASSERT_EQUAL((int)BootKeyAction::Wait,
                    (int)fry::decideBootKey(KeyModel::UserSupplied, false, nullptr, false, false));
}

void test_device_keeps_recovers_with_a_salt_and_mints_without() {
  TEST_ASSERT_EQUAL((int)BootKeyAction::Recover,
                    (int)fry::decideBootKey(KeyModel::DeviceKeeps, false, nullptr, true, false));
  TEST_ASSERT_EQUAL((int)BootKeyAction::Mint,
                    (int)fry::decideBootKey(KeyModel::DeviceKeeps, false, nullptr, false, false));
}

void test_a_stored_key_is_kept_or_migrated_exactly_as_before() {
  const char* stored[] = {"FEM-0123456789ABCDEF0123456789ABCDEF", "FEM-TESTKEY0000000000000000000000001"};
  for (const char* k : stored) {
    for (int salt = 0; salt < 2; salt++) {
      for (int user = 0; user < 2; user++) {
        TEST_ASSERT_EQUAL((int)BootKeyAction::Keep,
                          (int)fry::decideBootKey(KeyModel::UserSupplied, true, k, salt, user));
      }
    }
  }
  TEST_ASSERT_EQUAL((int)BootKeyAction::MigrateLegacy,
                    (int)fry::decideBootKey(KeyModel::UserSupplied, true,
                                            "IOT-0123456789ABCDEF0123456789ABCDEF", true, false));
}

void test_the_three_argument_form_is_unchanged() {
  // Pinned by test_key_policy: no salt information means no recovery.
  TEST_ASSERT_EQUAL((int)BootKeyAction::Wait,
                    (int)fry::decideBootKey(KeyModel::UserSupplied, false, nullptr));
  TEST_ASSERT_EQUAL((int)BootKeyAction::Mint,
                    (int)fry::decideBootKey(KeyModel::DeviceKeeps, false, nullptr));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_a_lost_minted_key_is_recovered_from_the_salt);
  RUN_TEST(test_a_lost_owner_key_is_never_re_derived);
  RUN_TEST(test_without_a_salt_a_user_supplied_board_still_waits);
  RUN_TEST(test_device_keeps_recovers_with_a_salt_and_mints_without);
  RUN_TEST(test_a_stored_key_is_kept_or_migrated_exactly_as_before);
  RUN_TEST(test_the_three_argument_form_is_unchanged);
  return UNITY_END();
}
