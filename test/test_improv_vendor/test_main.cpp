// Fry vendor Improv commands 0xF0 FrySetMinerKey / 0xF1 FryGetStatus and the BLE 0A status JSON
// (lib/fry_core/improv_serial.*, lib/fry_core/device_status.*; PROTOCOL.md section 11.4).
//
// GOLDEN VECTORS, as in test_improv_serial: the bytes below were produced by an independent
// encoder (a few lines of Python over the protocol text, recorded in the review evidence), not by
// this firmware. test/flash/improv_fry.test.mjs reads these same arrays out of THIS file and checks
// them against a third, JavaScript encoder and against the hex in PROTOCOL.md, so the web setup
// page, the app and the firmware cannot drift apart silently. Keep the `const uint8_t kFry...[]`
// declarations one per array; the node test parses them.
//
// The key in every vector is SYNTHETIC.
#include <unity.h>

#include <cstring>

#include "device_status.h"
#include "improv_serial.h"
#include "key_policy.h"

using fry::DeviceStatus;
using fry::KeyWriteVerdict;
using fry::ProvErr;
using fry::ProvState;
using fry::improv::Command;
using fry::improv::isKnownCommand;
using fry::improv::Parser;
using fry::improv::Result;

namespace {

// ---- golden vectors (shared with test/flash/improv_fry.test.mjs) ----------------------------
const uint8_t kFryReqSetKey[] = {0x49, 0x4D, 0x50, 0x52, 0x4F, 0x56, 0x01, 0x03, 0x27, 0xF0, 0x25, 0x24, 0x46, 0x45, 0x4D, 0x2D, 0x54, 0x45, 0x53, 0x54, 0x4B, 0x45, 0x59, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x20};
const uint8_t kFryReqGetStatus[] = {0x49, 0x4D, 0x50, 0x52, 0x4F, 0x56, 0x01, 0x03, 0x02, 0xF1, 0x00, 0xD4};
const uint8_t kFrySetKeyOk[] = {0x49, 0x4D, 0x50, 0x52, 0x4F, 0x56, 0x01, 0x04, 0x0F, 0xF0, 0x0D, 0x02, 0x6F, 0x6B, 0x09, 0x46, 0x45, 0x4D, 0x2D, 0x54, 0x45, 0xE2, 0x80, 0xA6, 0x79};
const uint8_t kFrySetKeyBadKey[] = {0x49, 0x4D, 0x50, 0x52, 0x4F, 0x56, 0x01, 0x04, 0x10, 0xF0, 0x0E, 0x03, 0x65, 0x72, 0x72, 0x01, 0x37, 0x07, 0x62, 0x61, 0x64, 0x5F, 0x6B, 0x65, 0x79, 0x4A};
const uint8_t kFrySetKeyLocked[] = {0x49, 0x4D, 0x50, 0x52, 0x4F, 0x56, 0x01, 0x04, 0x13, 0xF0, 0x11, 0x03, 0x65, 0x72, 0x72, 0x01, 0x38, 0x0A, 0x6B, 0x65, 0x79, 0x5F, 0x6C, 0x6F, 0x63, 0x6B, 0x65, 0x64, 0x9F};
const uint8_t kFryStatusConnected[] = {0x49, 0x4D, 0x50, 0x52, 0x4F, 0x56, 0x01, 0x04, 0x2A, 0xF1, 0x28, 0x01, 0x31, 0x01, 0x33, 0x01, 0x30, 0x01, 0x30, 0x01, 0x31, 0x09, 0x46, 0x45, 0x4D, 0x2D, 0x54, 0x45, 0xE2, 0x80, 0xA6, 0x05, 0x30, 0x2E, 0x34, 0x2E, 0x30, 0x03, 0x32, 0x30, 0x32, 0x02, 0x31, 0x32, 0x05, 0x76, 0x61, 0x6C, 0x69, 0x64, 0x00, 0xD4};
const uint8_t kFryStatusKeyRequired[] = {0x49, 0x4D, 0x50, 0x52, 0x4F, 0x56, 0x01, 0x04, 0x29, 0xF1, 0x27, 0x01, 0x31, 0x01, 0x34, 0x01, 0x34, 0x01, 0x36, 0x01, 0x30, 0x00, 0x05, 0x30, 0x2E, 0x34, 0x2E, 0x30, 0x01, 0x30, 0x02, 0x2D, 0x31, 0x07, 0x70, 0x65, 0x6E, 0x64, 0x69, 0x6E, 0x67, 0x08, 0x41, 0x42, 0x43, 0x44, 0x32, 0x33, 0x34, 0x35, 0x79};

const char kKey[] = "FEM-TESTKEY0000000000000000000000001";
const char kMasked[] = "FEM-TE\xE2\x80\xA6";

Result feedAll(Parser& p, const uint8_t* bytes, size_t n) {
  Result r = Result::None;
  for (size_t i = 0; i < n; i++) r = p.feed(bytes[i]);
  return r;
}

DeviceStatus connectedStatus() {
  DeviceStatus s;
  s.state = ProvState::Connected;
  s.err = ProvErr::None;
  s.keySet = true;
  s.keyConfirmed = true;
  fry::maskMinerKey(kKey, s.keyMasked, sizeof(s.keyMasked));
  s.regHttp = 202;
  s.hbAgeS = 12;
  s.fw = "0.4.0";
  s.ota = "valid";
  s.apCode = "";
  return s;
}

DeviceStatus keyRequiredStatus() {
  DeviceStatus s;
  s.state = ProvState::Error;
  s.err = ProvErr::KeyRequired;
  s.keySet = false;
  s.regHttp = 0;
  s.hbAgeS = -1;
  s.fw = "0.4.0";
  s.ota = "pending";
  s.apCode = "ABCD2345";
  return s;
}

// ---- commands -------------------------------------------------------------------------------

void test_vendor_commands_are_known_and_0x42_stays_unknown() {
  TEST_ASSERT_EQUAL_UINT8(0xF0, static_cast<uint8_t>(Command::FrySetMinerKey));
  TEST_ASSERT_EQUAL_UINT8(0xF1, static_cast<uint8_t>(Command::FryGetStatus));
  TEST_ASSERT_TRUE(isKnownCommand(0xF0));
  TEST_ASSERT_TRUE(isKnownCommand(0xF1));
  TEST_ASSERT_FALSE(isKnownCommand(0x42));
  TEST_ASSERT_FALSE(isKnownCommand(0xF2));
  TEST_ASSERT_FALSE(isKnownCommand(0xEF));
}

void test_set_key_request_parses_and_decodes() {
  Parser p;
  TEST_ASSERT_EQUAL((int)Result::Rpc, (int)feedAll(p, kFryReqSetKey, sizeof(kFryReqSetKey)));
  TEST_ASSERT_EQUAL_UINT8(0xF0, p.command());
  char key[40];
  TEST_ASSERT_TRUE(fry::improv::decodeKeyWrite(p.data(), p.dataLen(), key, sizeof(key)));
  TEST_ASSERT_EQUAL_STRING(kKey, key);
}

void test_get_status_request_parses() {
  Parser p;
  TEST_ASSERT_EQUAL((int)Result::Rpc, (int)feedAll(p, kFryReqGetStatus, sizeof(kFryReqGetStatus)));
  TEST_ASSERT_EQUAL_UINT8(0xF1, p.command());
  TEST_ASSERT_EQUAL_UINT8(0, p.dataLen());
}

void test_malformed_key_write_is_refused_before_policy() {
  char key[40] = "untouched";
  const uint8_t lenMismatch[] = {36, 'F', 'E', 'M'};                // says 36, carries 3
  TEST_ASSERT_FALSE(fry::improv::decodeKeyWrite(lenMismatch, sizeof(lenMismatch), key, sizeof(key)));
  TEST_ASSERT_FALSE(fry::improv::decodeKeyWrite(nullptr, 0, key, sizeof(key)));
  const uint8_t empty[] = {0};
  TEST_ASSERT_FALSE(fry::improv::decodeKeyWrite(empty, 0, key, sizeof(key)));
  TEST_ASSERT_EQUAL_STRING("untouched", key);
  // Well framed but the wrong length decodes; the caller's C-1 check answers bad_key.
  const uint8_t shortKey[] = {3, 'F', 'E', 'M'};
  TEST_ASSERT_TRUE(fry::improv::decodeKeyWrite(shortKey, sizeof(shortKey), key, sizeof(key)));
  TEST_ASSERT_EQUAL_STRING("FEM", key);
  // A buffer too small for the value is refused rather than truncated.
  char tiny[8];
  TEST_ASSERT_FALSE(fry::improv::decodeKeyWrite(kFryReqSetKey + 11, 37, tiny, sizeof(tiny)));
}

void test_key_write_results_match_the_goldens() {
  uint8_t out[fry::improv::kMaxPacket];
  size_t n = fry::improv::encodeKeyWriteResult(KeyWriteVerdict::Accept, kMasked, out, sizeof(out));
  TEST_ASSERT_EQUAL_size_t(sizeof(kFrySetKeyOk), n);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(kFrySetKeyOk, out, n);

  n = fry::improv::encodeKeyWriteResult(KeyWriteVerdict::BadKey, kMasked, out, sizeof(out));
  TEST_ASSERT_EQUAL_size_t(sizeof(kFrySetKeyBadKey), n);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(kFrySetKeyBadKey, out, n);

  n = fry::improv::encodeKeyWriteResult(KeyWriteVerdict::Locked, kMasked, out, sizeof(out));
  TEST_ASSERT_EQUAL_size_t(sizeof(kFrySetKeyLocked), n);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(kFrySetKeyLocked, out, n);
}

void test_status_results_match_the_goldens() {
  uint8_t out[fry::improv::kMaxPacket];
  size_t n = fry::improv::encodeFryStatus(connectedStatus(), out, sizeof(out));
  TEST_ASSERT_EQUAL_size_t(sizeof(kFryStatusConnected), n);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(kFryStatusConnected, out, n);

  n = fry::improv::encodeFryStatus(keyRequiredStatus(), out, sizeof(out));
  TEST_ASSERT_EQUAL_size_t(sizeof(kFryStatusKeyRequired), n);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(kFryStatusKeyRequired, out, n);
}

void test_status_result_fits_the_parser_limit_in_the_worst_case() {
  DeviceStatus s = connectedStatus();
  s.state = ProvState::Error;
  s.err = ProvErr::Unreachable;
  s.regHttp = -11;
  s.hbAgeS = 2147483647;
  s.fw = "10.20.30-rc.40";
  s.ota = "rolled_back";
  s.apCode = "ABCDEFGH";
  uint8_t out[fry::improv::kMaxPacket];
  TEST_ASSERT_TRUE(fry::improv::encodeFryStatus(s, out, sizeof(out)) > 0);
}

// ---- BLE 0A JSON ----------------------------------------------------------------------------

void test_status_json_is_the_contract_shape() {
  char json[200];
  size_t n = fry::buildStatusJson(connectedStatus(), json, sizeof(json));
  TEST_ASSERT_EQUAL_STRING(
      "{\"v\":1,\"proto\":2,\"caps\":[\"key_write\",\"error_reset\",\"errs_v2\"],\"s\":3,\"e\":0,"
      "\"d\":0,\"k\":1,\"kc\":1,\"reg\":202,\"hb\":12,\"fw\":\"0.4.0\",\"ota\":\"valid\"}",
      json);
  TEST_ASSERT_EQUAL_size_t(strlen(json), n);

  fry::buildStatusJson(keyRequiredStatus(), json, sizeof(json));
  TEST_ASSERT_EQUAL_STRING(
      "{\"v\":1,\"proto\":2,\"caps\":[\"key_write\",\"error_reset\",\"errs_v2\"],\"s\":4,\"e\":4,"
      "\"d\":6,\"k\":0,\"kc\":0,\"reg\":0,\"hb\":-1,\"fw\":\"0.4.0\",\"ota\":\"pending\"}",
      json);
}

void test_status_json_never_carries_a_secret() {
  char json[200];
  fry::buildStatusJson(keyRequiredStatus(), json, sizeof(json));
  TEST_ASSERT_NULL(strstr(json, "ABCD2345"));  // the setup code is USB-only
  fry::buildStatusJson(connectedStatus(), json, sizeof(json));
  TEST_ASSERT_NULL(strstr(json, "FEM-"));      // not even the masked key
}

void test_status_json_stays_within_160_bytes_or_refuses() {
  DeviceStatus s = connectedStatus();
  s.state = ProvState::Error;
  s.err = ProvErr::Unreachable;
  s.regHttp = -11;
  s.hbAgeS = 4294967;  // the largest age HeartbeatTracker can report (uint32 ms / 1000)
  s.fw = "10.20.30-rc.40";
  s.ota = "rolled_back";
  char json[200];
  const size_t n = fry::buildStatusJson(s, json, sizeof(json));
  TEST_ASSERT_TRUE(n > 0);
  TEST_ASSERT_TRUE(n <= fry::kStatusJsonMax);
  TEST_ASSERT_EQUAL_size_t(160, fry::kStatusJsonMax);

  s.fw = "a-firmware-version-string-that-is-far-too-long-to-fit";
  TEST_ASSERT_EQUAL_size_t(0, fry::buildStatusJson(s, json, sizeof(json)));
  TEST_ASSERT_EQUAL_STRING("", json);
  s.fw = "0.4.0\"}";  // never emitted unescaped
  TEST_ASSERT_EQUAL_size_t(0, fry::buildStatusJson(s, json, sizeof(json)));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_vendor_commands_are_known_and_0x42_stays_unknown);
  RUN_TEST(test_set_key_request_parses_and_decodes);
  RUN_TEST(test_get_status_request_parses);
  RUN_TEST(test_malformed_key_write_is_refused_before_policy);
  RUN_TEST(test_key_write_results_match_the_goldens);
  RUN_TEST(test_status_results_match_the_goldens);
  RUN_TEST(test_status_result_fits_the_parser_limit_in_the_worst_case);
  RUN_TEST(test_status_json_is_the_contract_shape);
  RUN_TEST(test_status_json_never_carries_a_secret);
  RUN_TEST(test_status_json_stays_within_160_bytes_or_refuses);
  return UNITY_END();
}
