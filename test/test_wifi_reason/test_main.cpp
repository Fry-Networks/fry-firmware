// Wi-Fi disconnect reason -> ProvErr (lib/fry_core/wifi_reason.*), and the FSM event that carries
// "no AP with that SSID" to the owner as BadSsid instead of WifiAuth.
//
// Before: both branches of the chip connect() error mapping returned WifiAuth, so a mistyped or
// out-of-range SSID (WIFI_REASON_NO_AP_FOUND, 201) was reported to the owner as a wrong password.
#include <unity.h>

#include "provisioning_fsm.h"
#include "wifi_reason.h"

using fry::ProvErr;
using fry::ProvEvent;
using fry::ProvInputs;
using fry::ProvisioningFsm;
using fry::ProvState;

namespace {

void test_no_ap_found_is_bad_ssid() {
  TEST_ASSERT_EQUAL((int)ProvErr::BadSsid, (int)fry::classifyWifiDisconnect(201));
}

void test_auth_class_reasons_are_wifi_auth() {
  TEST_ASSERT_EQUAL((int)ProvErr::WifiAuth, (int)fry::classifyWifiDisconnect(2));    // AUTH_EXPIRE
  TEST_ASSERT_EQUAL((int)ProvErr::WifiAuth, (int)fry::classifyWifiDisconnect(15));   // 4WAY_HANDSHAKE_TIMEOUT
  TEST_ASSERT_EQUAL((int)ProvErr::WifiAuth, (int)fry::classifyWifiDisconnect(202));  // AUTH_FAIL
  TEST_ASSERT_EQUAL((int)ProvErr::WifiAuth, (int)fry::classifyWifiDisconnect(203));  // ASSOC_FAIL: the AP exists
}

void test_undiagnosed_reason_stays_wifi_auth() {
  TEST_ASSERT_EQUAL((int)ProvErr::WifiAuth, (int)fry::classifyWifiDisconnect(0));
  TEST_ASSERT_EQUAL((int)ProvErr::WifiAuth, (int)fry::classifyWifiDisconnect(8));
  TEST_ASSERT_EQUAL((int)ProvErr::WifiAuth, (int)fry::classifyWifiDisconnect(255));
}

void test_fsm_no_ap_event_reports_bad_ssid() {
  ProvisioningFsm fsm;
  ProvInputs in;
  in.ssidValid = true;
  in.walletValid = true;
  fsm.feed(ProvEvent::SsidWritten, in);
  fsm.feed(ProvEvent::WalletWritten, in);
  TEST_ASSERT_EQUAL((int)ProvState::Connecting, (int)fsm.state());
  TEST_ASSERT_TRUE(fsm.feed(ProvEvent::WifiNoAp, in));
  TEST_ASSERT_EQUAL((int)ProvState::Error, (int)fsm.state());
  TEST_ASSERT_EQUAL((int)ProvErr::BadSsid, (int)fsm.error());
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_no_ap_found_is_bad_ssid);
  RUN_TEST(test_auth_class_reasons_are_wifi_auth);
  RUN_TEST(test_undiagnosed_reason_stays_wifi_auth);
  RUN_TEST(test_fsm_no_ap_event_reports_bad_ssid);
  return UNITY_END();
}
