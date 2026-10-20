// OTA rollout gate (lib/fry_core/ota_rollout.h, ota_rollout_json.h, decideOtaUpdate's inRollout).
//
// The manifest MAY carry a top-level "rollout": {"bucket_lo":0-99,"bucket_hi":0-99,"allow":[<16 hex>]}.
// device bucket = (first 4 bytes of SHA-256(miner key), big-endian uint32) % 100; allow entries are
// the first 16 hex chars of that same digest (the manifest is public: never raw keys).
//   absent          -> no gate (every 0.4.7 behaviour unchanged)
//   present, broken -> ignored entirely (= absent)
//   well-formed     -> eligible iff lo <= bucket <= hi OR the key's 16-hex prefix is in allow
#include <unity.h>

#include <ArduinoJson.h>

#include <cstring>
#include <string>

#include "ota_health.h"
#include "ota_rollout.h"
#include "ota_rollout_json.h"
#include "sha256.h"

using fry::OtaDecision;
using fry::RolloutVerdict;

namespace {

const char kUrl[] = "https://example.invalid/firmware.bin";
const char kSha[] = "2222222222222222222222222222222222222222222222222222222222222222";

// Independently computed with python hashlib (see the commit message): sha256 of the ASCII key.
//   "abc"           -> ba7816bf8f01cfea...  first4 = 3128432319  bucket 19
//   "FEM-TEST-0001" -> 9fa03ae3c55d4deb...  first4 = 2678078179  bucket 79
//   ""              -> e3b0c44298fc1c14...  first4 = 3820012610  bucket 10
void digestOf(const char* s, uint8_t out[32]) {
  fry::Sha256::hash(reinterpret_cast<const uint8_t*>(s), strlen(s), out);
}

RolloutVerdict verdict(const char* json, const char* key) {
  JsonDocument doc;
  TEST_ASSERT_TRUE(deserializeJson(doc, json) == DeserializationError::Ok);
  uint8_t d[32];
  digestOf(key, d);
  return fry::evaluateRollout(doc, d);
}

// ---- pure bucket / prefix ----

void test_bucket_known_vectors() {
  uint8_t d[32];
  digestOf("abc", d);
  TEST_ASSERT_EQUAL_UINT32(19, fry::rolloutBucket(d));
  digestOf("FEM-TEST-0001", d);
  TEST_ASSERT_EQUAL_UINT32(79, fry::rolloutBucket(d));
  digestOf("", d);
  TEST_ASSERT_EQUAL_UINT32(10, fry::rolloutBucket(d));
}

void test_bucket_is_big_endian_first_four_bytes() {
  uint8_t d[32] = {0};
  d[0] = 0x00; d[1] = 0x00; d[2] = 0x00; d[3] = 0x63;  // 99
  TEST_ASSERT_EQUAL_UINT32(99, fry::rolloutBucket(d));
  d[3] = 0x64;  // 100 -> 0
  TEST_ASSERT_EQUAL_UINT32(0, fry::rolloutBucket(d));
  d[0] = 0xFF; d[1] = 0xFF; d[2] = 0xFF; d[3] = 0xFF;  // 4294967295 % 100 = 95
  TEST_ASSERT_EQUAL_UINT32(95, fry::rolloutBucket(d));
  // bytes beyond the fourth never matter
  d[4] = 0xAA; d[31] = 0x55;
  TEST_ASSERT_EQUAL_UINT32(95, fry::rolloutBucket(d));
}

void test_prefix_hex_is_lowercase_16() {
  uint8_t d[32];
  digestOf("abc", d);
  char p[17];
  fry::rolloutPrefixHex(d, p);
  TEST_ASSERT_EQUAL_STRING("ba7816bf8f01cfea", p);
  digestOf("FEM-TEST-0001", d);
  fry::rolloutPrefixHex(d, p);
  TEST_ASSERT_EQUAL_STRING("9fa03ae3c55d4deb", p);
}

void test_eligibility_boundaries() {
  TEST_ASSERT_TRUE(fry::rolloutEligible(0, 99, 0, false));
  TEST_ASSERT_TRUE(fry::rolloutEligible(0, 99, 99, false));
  TEST_ASSERT_TRUE(fry::rolloutEligible(10, 10, 10, false));   // lo == hi
  TEST_ASSERT_FALSE(fry::rolloutEligible(10, 10, 9, false));
  TEST_ASSERT_FALSE(fry::rolloutEligible(10, 10, 11, false));
  TEST_ASSERT_FALSE(fry::rolloutEligible(0, 0, 1, false));
  TEST_ASSERT_TRUE(fry::rolloutEligible(0, 0, 0, false));
  TEST_ASSERT_TRUE(fry::rolloutEligible(99, 99, 99, false));
  TEST_ASSERT_FALSE(fry::rolloutEligible(99, 99, 98, false));
  TEST_ASSERT_TRUE(fry::rolloutEligible(20, 30, 50, true));    // allow overrides the range
  TEST_ASSERT_FALSE(fry::rolloutEligible(20, 30, 50, false));
}

// ---- JSON evaluation ----

void test_absent_field_is_absent() {
  TEST_ASSERT_EQUAL((int)RolloutVerdict::Absent,
                    (int)verdict("{\"firmware_version\":\"0.4.8\",\"channel\":\"prod\",\"builds\":{}}", "abc"));
  TEST_ASSERT_EQUAL((int)RolloutVerdict::Absent, (int)verdict("{}", "abc"));
}

void test_range_inside_and_outside() {
  // "abc" is bucket 19
  TEST_ASSERT_EQUAL((int)RolloutVerdict::Eligible,
                    (int)verdict("{\"rollout\":{\"bucket_lo\":0,\"bucket_hi\":19}}", "abc"));
  TEST_ASSERT_EQUAL((int)RolloutVerdict::Eligible,
                    (int)verdict("{\"rollout\":{\"bucket_lo\":19,\"bucket_hi\":19}}", "abc"));
  TEST_ASSERT_EQUAL((int)RolloutVerdict::NotEligible,
                    (int)verdict("{\"rollout\":{\"bucket_lo\":0,\"bucket_hi\":18}}", "abc"));
  TEST_ASSERT_EQUAL((int)RolloutVerdict::NotEligible,
                    (int)verdict("{\"rollout\":{\"bucket_lo\":20,\"bucket_hi\":99}}", "abc"));
  TEST_ASSERT_EQUAL((int)RolloutVerdict::Eligible,
                    (int)verdict("{\"rollout\":{\"bucket_lo\":0,\"bucket_hi\":99}}", "abc"));
}

void test_allow_prefix_makes_an_out_of_range_key_eligible() {
  const char* j =
      "{\"rollout\":{\"bucket_lo\":0,\"bucket_hi\":0,\"allow\":[\"1111111111111111\",\"ba7816bf8f01cfea\"]}}";
  TEST_ASSERT_EQUAL((int)RolloutVerdict::Eligible, (int)verdict(j, "abc"));
  TEST_ASSERT_EQUAL((int)RolloutVerdict::NotEligible, (int)verdict(j, "FEM-TEST-0001"));
}

void test_allow_prefix_case_insensitive_and_empty_allow() {
  TEST_ASSERT_EQUAL((int)RolloutVerdict::Eligible,
                    (int)verdict("{\"rollout\":{\"bucket_lo\":0,\"bucket_hi\":0,\"allow\":[\"BA7816BF8F01CFEA\"]}}", "abc"));
  TEST_ASSERT_EQUAL((int)RolloutVerdict::NotEligible,
                    (int)verdict("{\"rollout\":{\"bucket_lo\":0,\"bucket_hi\":0,\"allow\":[]}}", "abc"));
}

void test_malformed_variants_are_ignored_entirely() {
  const char* bad[] = {
      "{\"rollout\":5}",
      "{\"rollout\":\"x\"}",
      "{\"rollout\":null}",
      "{\"rollout\":true}",
      "{\"rollout\":[]}",
      "{\"rollout\":{}}",                                                  // no bucket range
      "{\"rollout\":{\"bucket_lo\":0}}",
      "{\"rollout\":{\"bucket_hi\":50}}",
      "{\"rollout\":{\"bucket_lo\":\"0\",\"bucket_hi\":50}}",              // string numbers
      "{\"rollout\":{\"bucket_lo\":0,\"bucket_hi\":\"50\"}}",
      "{\"rollout\":{\"bucket_lo\":0.5,\"bucket_hi\":50}}",                // float
      "{\"rollout\":{\"bucket_lo\":0,\"bucket_hi\":50.0}}",
      "{\"rollout\":{\"bucket_lo\":true,\"bucket_hi\":50}}",
      "{\"rollout\":{\"bucket_lo\":null,\"bucket_hi\":50}}",
      "{\"rollout\":{\"bucket_lo\":60,\"bucket_hi\":50}}",                 // lo > hi
      "{\"rollout\":{\"bucket_lo\":-1,\"bucket_hi\":50}}",                 // out of range
      "{\"rollout\":{\"bucket_lo\":0,\"bucket_hi\":100}}",
      "{\"rollout\":{\"bucket_lo\":100,\"bucket_hi\":100}}",
      "{\"rollout\":{\"bucket_lo\":0,\"bucket_hi\":4294967296}}",
      "{\"rollout\":{\"bucket_lo\":0,\"bucket_hi\":50,\"allow\":\"ba7816bf8f01cfea\"}}",    // not a list
      "{\"rollout\":{\"bucket_lo\":0,\"bucket_hi\":50,\"allow\":{\"a\":\"ba7816bf8f01cfea\"}}}",
      "{\"rollout\":{\"bucket_lo\":0,\"bucket_hi\":50,\"allow\":[5]}}",
      "{\"rollout\":{\"bucket_lo\":0,\"bucket_hi\":50,\"allow\":[null]}}",
      "{\"rollout\":{\"bucket_lo\":0,\"bucket_hi\":50,\"allow\":[\"ba7816bf8f01cfe\"]}}",   // 15 chars
      "{\"rollout\":{\"bucket_lo\":0,\"bucket_hi\":50,\"allow\":[\"ba7816bf8f01cfea0\"]}}", // 17 chars
      "{\"rollout\":{\"bucket_lo\":0,\"bucket_hi\":50,\"allow\":[\"ga7816bf8f01cfea\"]}}",  // non-hex
      "{\"rollout\":{\"bucket_lo\":0,\"bucket_hi\":50,\"allow\":[\"ba7816bf8f01cfea\",\"zz\"]}}",  // one bad entry poisons it
      "{\"rollout\":{\"bucket_lo\":0,\"bucket_hi\":50,\"allow\":[[\"ba7816bf8f01cfea\"]]}}",       // extra nesting
      "{\"rollout\":{\"bucket_lo\":0,\"bucket_hi\":50,\"allow\":[{\"k\":\"ba7816bf8f01cfea\"}]}}",
      "{\"rollout\":{\"rollout\":{\"bucket_lo\":0,\"bucket_hi\":50}}}",
      "{\"rollout\":{\"bucket_lo\":{\"v\":0},\"bucket_hi\":50}}",
      "{\"rollout\":{\"bucket_lo\":[0],\"bucket_hi\":50}}",
      "{\"rollout\":{\"bucket_lo\":0,\"bucket_hi\":50,\"extra\":{\"x\":1}}}",
  };
  for (const char* j : bad) {
    char msg[200];
    snprintf(msg, sizeof(msg), "%s", j);
    // Each is ignored: Malformed, which the caller treats as no gate.
    TEST_ASSERT_EQUAL_MESSAGE((int)RolloutVerdict::Malformed, (int)verdict(j, "abc"), msg);
    // and the verdict does not depend on which key asks
    TEST_ASSERT_EQUAL_MESSAGE((int)RolloutVerdict::Malformed, (int)verdict(j, "FEM-TEST-0001"), msg);
  }
}

void test_unknown_scalar_keys_in_rollout_are_tolerated() {
  TEST_ASSERT_EQUAL((int)RolloutVerdict::Eligible,
                    (int)verdict("{\"rollout\":{\"bucket_lo\":0,\"bucket_hi\":50,\"note\":\"stage 1\",\"n\":3}}", "abc"));
}

void test_non_object_manifest_is_absent() {
  JsonDocument doc;
  TEST_ASSERT_TRUE(deserializeJson(doc, "[1,2]") == DeserializationError::Ok);
  uint8_t d[32];
  digestOf("abc", d);
  TEST_ASSERT_EQUAL((int)RolloutVerdict::Absent, (int)fry::evaluateRollout(doc, d));
}

// ---- decision order ----

void test_not_in_rollout_name_and_value() {
  TEST_ASSERT_EQUAL_STRING("not_in_rollout", fry::otaDecisionName(OtaDecision::NotInRollout));
  // existing enumerators keep their values (appended, never inserted)
  TEST_ASSERT_EQUAL(0, (int)OtaDecision::Update);
  TEST_ASSERT_EQUAL(1, (int)OtaDecision::NotNewer);
  TEST_ASSERT_EQUAL(2, (int)OtaDecision::WrongChannel);
  TEST_ASSERT_EQUAL(3, (int)OtaDecision::BadVersion);
  TEST_ASSERT_EQUAL(4, (int)OtaDecision::NoBuild);
}

void test_decision_order_with_gate_closed() {
  const bool in = false;
  // WrongChannel, NotNewer, BadVersion all win over NotInRollout
  TEST_ASSERT_EQUAL((int)OtaDecision::WrongChannel,
                    (int)fry::decideOtaUpdate("test", "prod", "0.4.8", "0.4.7", "", kUrl, kSha, in));
  TEST_ASSERT_EQUAL((int)OtaDecision::NotNewer,
                    (int)fry::decideOtaUpdate("prod", "prod", "0.4.7", "0.4.7", "", kUrl, kSha, in));
  TEST_ASSERT_EQUAL((int)OtaDecision::NotNewer,
                    (int)fry::decideOtaUpdate("prod", "prod", "", "0.4.7", "", kUrl, kSha, in));
  TEST_ASSERT_EQUAL((int)OtaDecision::BadVersion,
                    (int)fry::decideOtaUpdate("prod", "prod", "0.4.8", "0.4.7", "0.4.8", kUrl, kSha, in));
  // NotInRollout wins over NoBuild and Update
  TEST_ASSERT_EQUAL((int)OtaDecision::NotInRollout,
                    (int)fry::decideOtaUpdate("prod", "prod", "0.4.8", "0.4.7", "", kUrl, kSha, in));
  TEST_ASSERT_EQUAL((int)OtaDecision::NotInRollout,
                    (int)fry::decideOtaUpdate("prod", "prod", "0.4.8", "0.4.7", "", "", "", in));
}

void test_gate_open_or_defaulted_is_the_old_decision() {
  TEST_ASSERT_EQUAL((int)OtaDecision::Update,
                    (int)fry::decideOtaUpdate("prod", "prod", "0.4.8", "0.4.7", "", kUrl, kSha, true));
  TEST_ASSERT_EQUAL((int)OtaDecision::Update,
                    (int)fry::decideOtaUpdate("prod", "prod", "0.4.8", "0.4.7", "", kUrl, kSha));  // default
  TEST_ASSERT_EQUAL((int)OtaDecision::NoBuild,
                    (int)fry::decideOtaUpdate("prod", "prod", "0.4.8", "0.4.7", "", "", "", true));
  TEST_ASSERT_EQUAL((int)OtaDecision::NoBuild,
                    (int)fry::decideOtaUpdate("prod", "prod", "0.4.8", "0.4.7", "", "", ""));
}

// Verdict -> inRollout mapping the firmware applies (ota_client.cpp): only NotEligible closes the gate.
void test_only_not_eligible_closes_the_gate() {
  TEST_ASSERT_TRUE(fry::rolloutAllows(RolloutVerdict::Absent));
  TEST_ASSERT_TRUE(fry::rolloutAllows(RolloutVerdict::Malformed));
  TEST_ASSERT_TRUE(fry::rolloutAllows(RolloutVerdict::Eligible));
  TEST_ASSERT_FALSE(fry::rolloutAllows(RolloutVerdict::NotEligible));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_bucket_known_vectors);
  RUN_TEST(test_bucket_is_big_endian_first_four_bytes);
  RUN_TEST(test_prefix_hex_is_lowercase_16);
  RUN_TEST(test_eligibility_boundaries);
  RUN_TEST(test_absent_field_is_absent);
  RUN_TEST(test_range_inside_and_outside);
  RUN_TEST(test_allow_prefix_makes_an_out_of_range_key_eligible);
  RUN_TEST(test_allow_prefix_case_insensitive_and_empty_allow);
  RUN_TEST(test_malformed_variants_are_ignored_entirely);
  RUN_TEST(test_unknown_scalar_keys_in_rollout_are_tolerated);
  RUN_TEST(test_non_object_manifest_is_absent);
  RUN_TEST(test_not_in_rollout_name_and_value);
  RUN_TEST(test_decision_order_with_gate_closed);
  RUN_TEST(test_gate_open_or_defaulted_is_the_old_decision);
  RUN_TEST(test_only_not_eligible_closes_the_gate);
  return UNITY_END();
}
