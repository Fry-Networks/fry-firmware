// Regression: writing the WALLET characteristic must persist the credentials BEFORE the
// provisioning FSM reports readyToConnect(). The main loop polls readyToConnect() from another
// task and reads the credentials back from NVS, so a state change that precedes the write lets
// the loop connect with an empty SSID ("SSID too long or missing", seen on a T-Beam over BLE).
#include <unity.h>

#include "provisioning_commit.h"
#include "provisioning_fsm.h"

using fry::ProvEvent;
using fry::ProvInputs;
using fry::ProvisioningFsm;
using fry::ProvState;

namespace {

ProvisioningFsm fsm;
ProvState stateSeenByPersist = ProvState::Idle;
int persistCalls = 0;

void persist() {
  persistCalls++;
  stateSeenByPersist = fsm.state();
}

void provisioned() {
  ProvInputs in;
  in.ssidValid = true;
  fsm.feed(ProvEvent::SsidWritten, in);
  fsm.feed(ProvEvent::PassWritten, in);
}

void test_persist_runs_before_the_fsm_reports_ready_to_connect() {
  provisioned();
  ProvInputs in;
  in.walletValid = true;

  bool changed = fry::commitOnWallet(fsm, in, persist);

  TEST_ASSERT_TRUE(changed);
  TEST_ASSERT_EQUAL(1, persistCalls);
  // The whole point: credentials were on disk while the FSM was still Provisioning.
  TEST_ASSERT_EQUAL((int)ProvState::Provisioning, (int)stateSeenByPersist);
  TEST_ASSERT_TRUE(fsm.readyToConnect());
}

void test_invalid_wallet_persists_nothing_and_errors() {
  provisioned();
  ProvInputs in;
  in.walletValid = false;

  bool changed = fry::commitOnWallet(fsm, in, persist);

  TEST_ASSERT_TRUE(changed);
  TEST_ASSERT_EQUAL(0, persistCalls);
  TEST_ASSERT_EQUAL((int)ProvState::Error, (int)fsm.state());
}

void test_wallet_before_ssid_persists_nothing() {
  ProvInputs in;
  in.walletValid = true;

  bool changed = fry::commitOnWallet(fsm, in, persist);

  TEST_ASSERT_FALSE(changed);
  TEST_ASSERT_EQUAL(0, persistCalls);
  TEST_ASSERT_EQUAL((int)ProvState::Idle, (int)fsm.state());
}

void test_second_wallet_write_after_commit_is_ignored() {
  provisioned();
  ProvInputs in;
  in.walletValid = true;
  fry::commitOnWallet(fsm, in, persist);

  bool changed = fry::commitOnWallet(fsm, in, persist);

  TEST_ASSERT_FALSE(changed);
  TEST_ASSERT_EQUAL(1, persistCalls);
}


// ---- the wallet-less Improv commit -----------------------------------------------------------
// Improv Serial sends an SSID and a password and nothing else, so it commits without a wallet.
// The ordering rule this file exists for is unchanged: persist first, report Connecting second.
void test_wifi_only_commit_persists_before_reporting_ready_to_connect() {
  provisioned();

  bool changed = fry::commitWifiOnly(fsm, persist);

  TEST_ASSERT_TRUE(changed);
  TEST_ASSERT_EQUAL(1, persistCalls);
  TEST_ASSERT_EQUAL((int)ProvState::Provisioning, (int)stateSeenByPersist);
  TEST_ASSERT_TRUE(fsm.readyToConnect());
}

void test_wifi_only_commit_before_a_valid_ssid_persists_nothing() {
  bool changed = fry::commitWifiOnly(fsm, persist);

  TEST_ASSERT_FALSE(changed);
  TEST_ASSERT_EQUAL(0, persistCalls);
  TEST_ASSERT_EQUAL((int)ProvState::Idle, (int)fsm.state());
}

void test_wifi_only_commit_does_not_repeat_after_committing() {
  provisioned();
  fry::commitWifiOnly(fsm, persist);

  bool changed = fry::commitWifiOnly(fsm, persist);

  TEST_ASSERT_FALSE(changed);
  TEST_ASSERT_EQUAL(1, persistCalls);
  TEST_ASSERT_EQUAL((int)ProvState::Connecting, (int)fsm.state());
}

void test_wifi_only_commit_leaves_the_wallet_path_alone() {
  // The BLE/SoftAP commit must behave exactly as before now that a second commit event exists.
  provisioned();
  ProvInputs in;
  in.walletValid = true;

  TEST_ASSERT_TRUE(fry::commitOnWallet(fsm, in, persist));
  TEST_ASSERT_EQUAL(1, persistCalls);
  TEST_ASSERT_EQUAL((int)ProvState::Provisioning, (int)stateSeenByPersist);
  TEST_ASSERT_TRUE(fsm.readyToConnect());
}

}  // namespace

// Unity's setUp/tearDown hooks have C linkage (declared inside unity.h's extern "C" block), so
// they must live at global scope — inside the anonymous namespace they would silently never run.
void setUp() {
  fsm = ProvisioningFsm();
  stateSeenByPersist = ProvState::Idle;
  persistCalls = 0;
}

void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_persist_runs_before_the_fsm_reports_ready_to_connect);
  RUN_TEST(test_invalid_wallet_persists_nothing_and_errors);
  RUN_TEST(test_wallet_before_ssid_persists_nothing);
  RUN_TEST(test_second_wallet_write_after_commit_is_ignored);
  RUN_TEST(test_wifi_only_commit_persists_before_reporting_ready_to_connect);
  RUN_TEST(test_wifi_only_commit_before_a_valid_ssid_persists_nothing);
  RUN_TEST(test_wifi_only_commit_does_not_repeat_after_committing);
  RUN_TEST(test_wifi_only_commit_leaves_the_wallet_path_alone);
  return UNITY_END();
}
