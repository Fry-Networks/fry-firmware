// Registration outcome -> status code, retry schedule and log text (lib/fry_core/reg_result.*),
// plus the v1.1 status encoding every transport reports it through.
//
// Before v1.1 every hardwareapi rejection surfaced as one code (4, "registration failed") and one
// log line ("server does not accept this miner code yet"), whether the key was legacy (401), in use
// on another install (409) or the server was simply down - and a transport failure blocked the loop
// for 2+4+8 s of retries. Owners could not tell which of those they had.
#include <unity.h>

#include <cstring>

#include "provisioning_fsm.h"
#include "reg_result.h"

using fry::ProvErr;
using fry::ProvEvent;
using fry::ProvInputs;
using fry::ProvisioningFsm;
using fry::ProvState;
using fry::RegClass;

namespace {

void test_http_codes_classify_per_protocol() {
  TEST_ASSERT_EQUAL((int)RegClass::Ok, (int)fry::classifyRegistration(200));
  TEST_ASSERT_EQUAL((int)RegClass::Ok, (int)fry::classifyRegistration(201));
  TEST_ASSERT_EQUAL((int)RegClass::Ok, (int)fry::classifyRegistration(202));
  TEST_ASSERT_EQUAL((int)RegClass::Unauthorized, (int)fry::classifyRegistration(401));
  TEST_ASSERT_EQUAL((int)RegClass::Forbidden, (int)fry::classifyRegistration(403));
  TEST_ASSERT_EQUAL((int)RegClass::Conflict, (int)fry::classifyRegistration(409));
  TEST_ASSERT_EQUAL((int)RegClass::OtherClientError, (int)fry::classifyRegistration(400));
  TEST_ASSERT_EQUAL((int)RegClass::OtherClientError, (int)fry::classifyRegistration(404));
  TEST_ASSERT_EQUAL((int)RegClass::OtherClientError, (int)fry::classifyRegistration(422));
  // 429 is "come back later", not "you are wrong": it is retried like an outage.
  TEST_ASSERT_EQUAL((int)RegClass::Unreachable, (int)fry::classifyRegistration(429));
  TEST_ASSERT_EQUAL((int)RegClass::Unreachable, (int)fry::classifyRegistration(500));
  TEST_ASSERT_EQUAL((int)RegClass::Unreachable, (int)fry::classifyRegistration(503));
  TEST_ASSERT_EQUAL((int)RegClass::Unreachable, (int)fry::classifyRegistration(-1));  // HTTPClient transport
  TEST_ASSERT_EQUAL((int)RegClass::Unreachable, (int)fry::classifyRegistration(-11));
  TEST_ASSERT_EQUAL((int)RegClass::Unreachable, (int)fry::classifyRegistration(0));
  TEST_ASSERT_EQUAL((int)RegClass::Unreachable, (int)fry::classifyRegistration(302));
}

void test_classes_map_to_the_appended_error_codes() {
  TEST_ASSERT_EQUAL((int)ProvErr::None, (int)fry::regClassProvErr(RegClass::Ok));
  TEST_ASSERT_EQUAL(9, (int)fry::regClassProvErr(RegClass::Unauthorized));
  TEST_ASSERT_EQUAL(10, (int)fry::regClassProvErr(RegClass::Forbidden));
  TEST_ASSERT_EQUAL(11, (int)fry::regClassProvErr(RegClass::Conflict));
  TEST_ASSERT_EQUAL(12, (int)fry::regClassProvErr(RegClass::OtherClientError));
  TEST_ASSERT_EQUAL(13, (int)fry::regClassProvErr(RegClass::Unreachable));
}

void test_error_code_numbering_is_append_only() {
  // 0-5 are PROTOCOL.md section 2 and must never move.
  TEST_ASSERT_EQUAL(0, (int)ProvErr::None);
  TEST_ASSERT_EQUAL(1, (int)ProvErr::BadSsid);
  TEST_ASSERT_EQUAL(2, (int)ProvErr::WifiAuth);
  TEST_ASSERT_EQUAL(3, (int)ProvErr::NoIp);
  TEST_ASSERT_EQUAL(4, (int)ProvErr::ApiFail);
  TEST_ASSERT_EQUAL(5, (int)ProvErr::BadWallet);
  TEST_ASSERT_EQUAL(6, (int)ProvErr::KeyRequired);
  TEST_ASSERT_EQUAL(7, (int)ProvErr::BadKey);
  TEST_ASSERT_EQUAL(8, (int)ProvErr::KeyLocked);
  TEST_ASSERT_EQUAL(9, (int)ProvErr::Reg401);
  TEST_ASSERT_EQUAL(10, (int)ProvErr::Reg403);
  TEST_ASSERT_EQUAL(11, (int)ProvErr::Reg409);
  TEST_ASSERT_EQUAL(12, (int)ProvErr::RegOther4xx);
  TEST_ASSERT_EQUAL(13, (int)ProvErr::Unreachable);
}

void test_legacy_byte_folds_new_codes_into_registration_failed() {
  for (int e = 0; e <= 5; e++) {
    TEST_ASSERT_EQUAL(e, (int)fry::legacyProvErr(static_cast<ProvErr>(e)));
  }
  for (int e = 6; e <= 13; e++) {
    TEST_ASSERT_EQUAL(4, (int)fry::legacyProvErr(static_cast<ProvErr>(e)));
  }
}

void test_status_bytes_are_state_or_error_triplet() {
  uint8_t out[3] = {0xAA, 0xAA, 0xAA};
  TEST_ASSERT_EQUAL_size_t(1, fry::encodeProvStatus(ProvState::Connecting, ProvErr::None, out, sizeof(out)));
  TEST_ASSERT_EQUAL_UINT8(2, out[0]);

  TEST_ASSERT_EQUAL_size_t(3, fry::encodeProvStatus(ProvState::Error, ProvErr::Reg409, out, sizeof(out)));
  const uint8_t reg409[] = {4, 4, 11};
  TEST_ASSERT_EQUAL_UINT8_ARRAY(reg409, out, 3);

  TEST_ASSERT_EQUAL_size_t(3, fry::encodeProvStatus(ProvState::Error, ProvErr::WifiAuth, out, sizeof(out)));
  const uint8_t auth[] = {4, 2, 2};
  TEST_ASSERT_EQUAL_UINT8_ARRAY(auth, out, 3);

  TEST_ASSERT_EQUAL_size_t(0, fry::encodeProvStatus(ProvState::Error, ProvErr::KeyRequired, out, 2));
}

void test_unreachable_backs_off_from_one_minute_doubling_to_an_hour() {
  const uint32_t expect[] = {60000, 120000, 240000, 480000, 960000, 1920000, 3600000, 3600000};
  for (uint32_t n = 1; n <= 8; n++) {
    TEST_ASSERT_EQUAL_UINT32(expect[n - 1], fry::nextRegisterDelayMs(RegClass::Unreachable, n));
  }
  TEST_ASSERT_EQUAL_UINT32(3600000, fry::nextRegisterDelayMs(RegClass::Unreachable, 1000));
  TEST_ASSERT_EQUAL_UINT32(3600000, fry::nextRegisterDelayMs(RegClass::Unreachable, 0xFFFFFFFFu));
  TEST_ASSERT_EQUAL_UINT32(60000, fry::nextRegisterDelayMs(RegClass::Unreachable, 0));
}

void test_client_errors_wait_an_hour_and_success_keeps_the_heartbeat() {
  const RegClass fourxx[] = {RegClass::Unauthorized, RegClass::Forbidden, RegClass::Conflict,
                             RegClass::OtherClientError};
  for (RegClass c : fourxx) {
    TEST_ASSERT_EQUAL_UINT32(3600000, fry::nextRegisterDelayMs(c, 1));
    TEST_ASSERT_EQUAL_UINT32(3600000, fry::nextRegisterDelayMs(c, 9));
  }
  TEST_ASSERT_EQUAL_UINT32(3600000, fry::nextRegisterDelayMs(RegClass::Ok, 0));
}

void test_only_an_outage_earns_the_quick_retry() {
  TEST_ASSERT_TRUE(fry::regClassRetryQuickly(RegClass::Unreachable));
  TEST_ASSERT_FALSE(fry::regClassRetryQuickly(RegClass::Ok));
  TEST_ASSERT_FALSE(fry::regClassRetryQuickly(RegClass::Unauthorized));
  TEST_ASSERT_FALSE(fry::regClassRetryQuickly(RegClass::Conflict));
}

void test_every_class_has_log_text_and_none_blames_the_miner_code() {
  const RegClass all[] = {RegClass::Ok, RegClass::Unauthorized, RegClass::Forbidden, RegClass::Conflict,
                          RegClass::OtherClientError, RegClass::Unreachable};
  for (RegClass c : all) {
    const char* t = fry::regClassText(c);
    TEST_ASSERT_NOT_NULL(t);
    TEST_ASSERT_TRUE(strlen(t) > 0);
    TEST_ASSERT_NULL(strstr(t, "miner code"));
  }
}

void test_server_detail_is_bounded_printable_and_key_masked() {
  char out[160];
  size_t n = fry::sanitizeServerDetail("key not registered", "", out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("key not registered", out);
  TEST_ASSERT_EQUAL_size_t(18, n);

  // Quotes, backslashes and control bytes never reach the log line.
  fry::sanitizeServerDetail("bad \"x\"\\\n\ty", "", out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("bad 'x'/??y", out);

  // Any key-shaped token is masked, the device's own key included.
  fry::sanitizeServerDetail("FEM-TESTKEY0000000000000000000000001 is active elsewhere",
                            "FEM-TESTKEY0000000000000000000000001", out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("FEM-TE... is active elsewhere", out);
  fry::sanitizeServerDetail("legacy IOT-0123456789abcdef0123456789abcdef refused", "", out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("legacy IOT-01... refused", out);

  // Truncated at 120 characters.
  char longIn[300];
  memset(longIn, 'a', sizeof(longIn) - 1);
  longIn[sizeof(longIn) - 1] = 0;
  TEST_ASSERT_EQUAL_size_t(120, fry::sanitizeServerDetail(longIn, "", out, sizeof(out)));
  TEST_ASSERT_EQUAL_size_t(120, strlen(out));

  // Small buffers and null input are safe.
  char small[8];
  TEST_ASSERT_EQUAL_size_t(7, fry::sanitizeServerDetail("abcdefghijk", "", small, sizeof(small)));
  TEST_ASSERT_EQUAL_STRING("abcdefg", small);
  TEST_ASSERT_EQUAL_size_t(0, fry::sanitizeServerDetail(nullptr, "", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("", out);
}

// ---- FSM: ApiFail carries the detail --------------------------------------------------------

ProvisioningFsm connectingWithWifiUp() {
  ProvisioningFsm fsm;
  ProvInputs in;
  in.ssidValid = true;
  in.walletValid = true;
  fsm.feed(ProvEvent::SsidWritten, in);
  fsm.feed(ProvEvent::WalletWritten, in);
  fsm.feed(ProvEvent::WifiUp, in);
  return fsm;
}

void test_api_fail_reports_the_registration_detail() {
  ProvisioningFsm fsm = connectingWithWifiUp();
  ProvInputs in;
  in.detail = fry::regClassProvErr(RegClass::Conflict);
  TEST_ASSERT_TRUE(fsm.feed(ProvEvent::ApiFail, in));
  TEST_ASSERT_EQUAL((int)ProvState::Error, (int)fsm.state());
  TEST_ASSERT_EQUAL((int)ProvErr::Reg409, (int)fsm.error());
  uint8_t out[3];
  fry::encodeProvStatus(fsm.state(), fsm.error(), out, sizeof(out));
  const uint8_t expect[] = {4, 4, 11};
  TEST_ASSERT_EQUAL_UINT8_ARRAY(expect, out, 3);
}

void test_api_fail_without_detail_stays_generic() {
  ProvisioningFsm fsm = connectingWithWifiUp();
  TEST_ASSERT_TRUE(fsm.feed(ProvEvent::ApiFail, {}));
  TEST_ASSERT_EQUAL((int)ProvErr::ApiFail, (int)fsm.error());
  // A non-registration detail is not smuggled in through ApiFail.
  ProvisioningFsm fsm2 = connectingWithWifiUp();
  ProvInputs in;
  in.detail = ProvErr::BadWallet;
  fsm2.feed(ProvEvent::ApiFail, in);
  TEST_ASSERT_EQUAL((int)ProvErr::ApiFail, (int)fsm2.error());
}

void test_a_later_failure_updates_the_detail_and_success_recovers() {
  ProvisioningFsm fsm = connectingWithWifiUp();
  ProvInputs in;
  in.detail = ProvErr::Unreachable;
  fsm.feed(ProvEvent::ApiFail, in);
  in.detail = ProvErr::Reg401;
  fsm.feed(ProvEvent::ApiFail, in);
  TEST_ASSERT_EQUAL((int)ProvErr::Reg401, (int)fsm.error());
  TEST_ASSERT_TRUE(fsm.feed(ProvEvent::ApiOk, {}));
  TEST_ASSERT_EQUAL((int)ProvState::Connected, (int)fsm.state());
  TEST_ASSERT_EQUAL((int)ProvErr::None, (int)fsm.error());
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_http_codes_classify_per_protocol);
  RUN_TEST(test_classes_map_to_the_appended_error_codes);
  RUN_TEST(test_error_code_numbering_is_append_only);
  RUN_TEST(test_legacy_byte_folds_new_codes_into_registration_failed);
  RUN_TEST(test_status_bytes_are_state_or_error_triplet);
  RUN_TEST(test_unreachable_backs_off_from_one_minute_doubling_to_an_hour);
  RUN_TEST(test_client_errors_wait_an_hour_and_success_keeps_the_heartbeat);
  RUN_TEST(test_only_an_outage_earns_the_quick_retry);
  RUN_TEST(test_every_class_has_log_text_and_none_blames_the_miner_code);
  RUN_TEST(test_server_detail_is_bounded_printable_and_key_masked);
  RUN_TEST(test_api_fail_reports_the_registration_detail);
  RUN_TEST(test_api_fail_without_detail_stays_generic);
  RUN_TEST(test_a_later_failure_updates_the_detail_and_success_recovers);
  return UNITY_END();
}
