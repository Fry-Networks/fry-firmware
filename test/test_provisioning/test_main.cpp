// Unity test suite for lib/fry_core/. Runs under `pio test -e native` (host, CI) and compiles
// (but is NOT run — the lead owns the boards) under `pio test -e esp32 --without-uploading
// --without-testing`. test_build_src is false, so only lib/ + this file are in the test binary —
// src/main.cpp's setup()/loop() are never linked in here, so there is no symbol clash with the
// setup()/loop() defined below for the embedded compile-only check.
#ifdef ARDUINO
#include <Arduino.h>
#endif
#include <unity.h>

#include "ota_boot_counter.h"
#include "provisioning_fsm.h"
#include "socks5_parse.h"

using fry::OtaBootCounter;
using fry::ProvErr;
using fry::ProvEvent;
using fry::ProvInputs;
using fry::ProvisioningFsm;
using fry::ProvState;
using fry::Socks5AddrType;
using fry::Socks5ConnectRequest;
using fry::Socks5Greeting;
using fry::Socks5Result;
using fry::parseConnectRequest;
using fry::parseGreeting;

void setUp(void) {}
void tearDown(void) {}

// ── ProvisioningFsm (8 cases) ────────────────────────────────────────────────

void test_fsm_idle_to_provisioning_on_valid_ssid(void) {
  ProvisioningFsm fsm;
  ProvInputs in;
  in.ssidValid = true;
  bool changed = fsm.feed(ProvEvent::SsidWritten, in);
  TEST_ASSERT_TRUE(changed);
  TEST_ASSERT_EQUAL(static_cast<int>(ProvState::Provisioning), static_cast<int>(fsm.state()));
}

void test_fsm_wallet_write_commits_to_connecting(void) {
  ProvisioningFsm fsm;
  ProvInputs in;
  in.ssidValid = true;
  fsm.feed(ProvEvent::SsidWritten, in);
  in.walletValid = true;
  bool changed = fsm.feed(ProvEvent::WalletWritten, in);
  TEST_ASSERT_TRUE(changed);
  TEST_ASSERT_EQUAL(static_cast<int>(ProvState::Connecting), static_cast<int>(fsm.state()));
  TEST_ASSERT_TRUE(fsm.readyToConnect());
}

void test_fsm_invalid_wallet_error_badwallet(void) {
  ProvisioningFsm fsm;
  ProvInputs in;
  in.ssidValid = true;
  fsm.feed(ProvEvent::SsidWritten, in);
  in.walletValid = false;
  bool changed = fsm.feed(ProvEvent::WalletWritten, in);
  TEST_ASSERT_TRUE(changed);
  TEST_ASSERT_EQUAL(static_cast<int>(ProvState::Error), static_cast<int>(fsm.state()));
  TEST_ASSERT_EQUAL(static_cast<int>(ProvErr::BadWallet), static_cast<int>(fsm.error()));
}

void test_fsm_invalid_ssid_error_badssid(void) {
  ProvisioningFsm fsm;
  ProvInputs in;
  in.ssidValid = false;
  bool changed = fsm.feed(ProvEvent::SsidWritten, in);
  TEST_ASSERT_TRUE(changed);
  TEST_ASSERT_EQUAL(static_cast<int>(ProvState::Error), static_cast<int>(fsm.state()));
  TEST_ASSERT_EQUAL(static_cast<int>(ProvErr::BadSsid), static_cast<int>(fsm.error()));
}

void test_fsm_wifiup_then_apiok_connected(void) {
  ProvisioningFsm fsm;
  ProvInputs in;
  in.ssidValid = true;
  fsm.feed(ProvEvent::SsidWritten, in);
  in.walletValid = true;
  fsm.feed(ProvEvent::WalletWritten, in);
  fsm.feed(ProvEvent::WifiUp, in);
  bool changed = fsm.feed(ProvEvent::ApiOk, in);
  TEST_ASSERT_TRUE(changed);
  TEST_ASSERT_EQUAL(static_cast<int>(ProvState::Connected), static_cast<int>(fsm.state()));
}

void test_fsm_wifiauthfail_error_wifiauth(void) {
  ProvisioningFsm fsm;
  ProvInputs in;
  in.ssidValid = true;
  fsm.feed(ProvEvent::SsidWritten, in);
  in.walletValid = true;
  fsm.feed(ProvEvent::WalletWritten, in);
  bool changed = fsm.feed(ProvEvent::WifiAuthFail, in);
  TEST_ASSERT_TRUE(changed);
  TEST_ASSERT_EQUAL(static_cast<int>(ProvState::Error), static_cast<int>(fsm.state()));
  TEST_ASSERT_EQUAL(static_cast<int>(ProvErr::WifiAuth), static_cast<int>(fsm.error()));
}

void test_fsm_reset_from_error_to_idle(void) {
  ProvisioningFsm fsm;
  ProvInputs in;
  in.ssidValid = false;
  fsm.feed(ProvEvent::SsidWritten, in);  // -> Error/BadSsid
  TEST_ASSERT_EQUAL(static_cast<int>(ProvState::Error), static_cast<int>(fsm.state()));
  bool changed = fsm.feed(ProvEvent::Reset, in);
  TEST_ASSERT_TRUE(changed);
  TEST_ASSERT_EQUAL(static_cast<int>(ProvState::Idle), static_cast<int>(fsm.state()));
  TEST_ASSERT_EQUAL(static_cast<int>(ProvErr::None), static_cast<int>(fsm.error()));
}

void test_fsm_out_of_order_event_ignored(void) {
  ProvisioningFsm fsm;
  ProvInputs in;
  bool changed = fsm.feed(ProvEvent::WifiUp, in);  // WifiUp while Idle — out of order
  TEST_ASSERT_FALSE(changed);
  TEST_ASSERT_EQUAL(static_cast<int>(ProvState::Idle), static_cast<int>(fsm.state()));
}

// ── OtaBootCounter (3 cases) ─────────────────────────────────────────────────

void test_ota_counter_increment(void) {
  OtaBootCounter c;
  TEST_ASSERT_EQUAL_UINT8(0, c.count());
  TEST_ASSERT_EQUAL_UINT8(1, c.increment());
  TEST_ASSERT_EQUAL_UINT8(2, c.increment());
  TEST_ASSERT_EQUAL_UINT8(2, c.count());
}

void test_ota_counter_clear(void) {
  OtaBootCounter c;
  c.increment();
  c.increment();
  c.clear();
  TEST_ASSERT_EQUAL_UINT8(0, c.count());
  TEST_ASSERT_FALSE(c.shouldRollBack(3));
}

void test_ota_counter_shouldrollback_at_limit(void) {
  OtaBootCounter c;
  c.increment();
  c.increment();
  TEST_ASSERT_FALSE(c.shouldRollBack(3));
  c.increment();
  TEST_ASSERT_TRUE(c.shouldRollBack(3));
}

// ── socks5_parse (5 cases) ────────────────────────────────────────────────────

void test_socks5_valid_noauth_greeting(void) {
  const uint8_t buf[] = {0x05, 0x01, 0x00};
  Socks5Greeting g;
  size_t consumed = 0;
  Socks5Result r = parseGreeting(buf, sizeof(buf), g, consumed);
  TEST_ASSERT_EQUAL(static_cast<int>(Socks5Result::Ok), static_cast<int>(r));
  TEST_ASSERT_TRUE(g.noAuthOffered);
  TEST_ASSERT_EQUAL_UINT32(3, consumed);
}

void test_socks5_unsupported_method(void) {
  const uint8_t buf[] = {0x05, 0x01, 0x02};  // GSSAPI only, no 0x00
  Socks5Greeting g;
  size_t consumed = 0;
  Socks5Result r = parseGreeting(buf, sizeof(buf), g, consumed);
  TEST_ASSERT_EQUAL(static_cast<int>(Socks5Result::UnsupportedMethod), static_cast<int>(r));
  TEST_ASSERT_FALSE(g.noAuthOffered);
}

void test_socks5_ipv4_connect(void) {
  // VER CMD RSV ATYP  93.184.216.34  port 80
  const uint8_t buf[] = {0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x00, 0x50};
  Socks5ConnectRequest req;
  size_t consumed = 0;
  Socks5Result r = parseConnectRequest(buf, sizeof(buf), req, consumed);
  TEST_ASSERT_EQUAL(static_cast<int>(Socks5Result::Ok), static_cast<int>(r));
  TEST_ASSERT_EQUAL(static_cast<int>(Socks5AddrType::IPv4), static_cast<int>(req.addrType));
  TEST_ASSERT_EQUAL_STRING("93.184.216.34", req.host);
  TEST_ASSERT_EQUAL_UINT16(80, req.port);
  TEST_ASSERT_EQUAL_UINT32(10, consumed);
}

void test_socks5_domain_connect(void) {
  // VER CMD RSV ATYP  len=11 "example.com"  port 443
  const uint8_t buf[] = {0x05, 0x01, 0x00, 0x03, 11, 'e', 'x', 'a', 'm', 'p',
                          'l',  'e',  '.',  'c',  'o', 'm', 0x01, 0xBB};
  Socks5ConnectRequest req;
  size_t consumed = 0;
  Socks5Result r = parseConnectRequest(buf, sizeof(buf), req, consumed);
  TEST_ASSERT_EQUAL(static_cast<int>(Socks5Result::Ok), static_cast<int>(r));
  TEST_ASSERT_EQUAL(static_cast<int>(Socks5AddrType::Domain), static_cast<int>(req.addrType));
  TEST_ASSERT_EQUAL_STRING("example.com", req.host);
  TEST_ASSERT_EQUAL_UINT16(443, req.port);
  TEST_ASSERT_EQUAL_UINT32(18, consumed);
}

void test_socks5_truncated_request(void) {
  // ATYP=IPv4 declared but only 2 of the 4 address bytes present, port missing entirely.
  const uint8_t buf[] = {0x05, 0x01, 0x00, 0x01, 93, 184};
  Socks5ConnectRequest req;
  size_t consumed = 0;
  Socks5Result r = parseConnectRequest(buf, sizeof(buf), req, consumed);
  TEST_ASSERT_EQUAL(static_cast<int>(Socks5Result::NeedMoreData), static_cast<int>(r));
}

int main(int argc = 0, char** argv = nullptr) {
  (void)argc;
  (void)argv;
  UNITY_BEGIN();
  RUN_TEST(test_fsm_idle_to_provisioning_on_valid_ssid);
  RUN_TEST(test_fsm_wallet_write_commits_to_connecting);
  RUN_TEST(test_fsm_invalid_wallet_error_badwallet);
  RUN_TEST(test_fsm_invalid_ssid_error_badssid);
  RUN_TEST(test_fsm_wifiup_then_apiok_connected);
  RUN_TEST(test_fsm_wifiauthfail_error_wifiauth);
  RUN_TEST(test_fsm_reset_from_error_to_idle);
  RUN_TEST(test_fsm_out_of_order_event_ignored);
  RUN_TEST(test_ota_counter_increment);
  RUN_TEST(test_ota_counter_clear);
  RUN_TEST(test_ota_counter_shouldrollback_at_limit);
  RUN_TEST(test_socks5_valid_noauth_greeting);
  RUN_TEST(test_socks5_unsupported_method);
  RUN_TEST(test_socks5_ipv4_connect);
  RUN_TEST(test_socks5_domain_connect);
  RUN_TEST(test_socks5_truncated_request);
  return UNITY_END();
}

#ifdef ARDUINO
void setup() {
  delay(2000);
  main();
}
void loop() {}
#endif
