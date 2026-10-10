// The firmware's Improv vendor encoders against the ONE shared vector file,
// test/fixtures/improv_fry_vectors.json (PROTOCOL.md 11.4). The dashboard vendors a byte-identical
// copy of that file and asserts its own codec against it, and test/flash/improv_fry.test.mjs checks
// it against an independent JavaScript encoder and PROTOCOL.md, so a vector can no longer drift in
// one repo without failing a suite. Read at run time from the project root (the native runner's
// working directory).
#include <unity.h>

#include <ArduinoJson.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "device_status.h"
#include "improv_serial.h"
#include "key_policy.h"

using fry::DeviceStatus;
using fry::KeyWriteVerdict;
using fry::ProvErr;
using fry::ProvState;
using fry::improv::Parser;
using fry::improv::Result;

namespace {

const char kFixture[] = "test/fixtures/improv_fry_vectors.json";
JsonDocument g_doc;

std::vector<uint8_t> fromHex(const char* hex) {
  std::vector<uint8_t> out;
  for (size_t i = 0; hex && hex[i] && hex[i + 1]; i += 2) {
    char byte[3] = {hex[i], hex[i + 1], 0};
    out.push_back(static_cast<uint8_t>(strtoul(byte, nullptr, 16)));
  }
  return out;
}

std::string toHex(const uint8_t* p, size_t n) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; i++) {
    s += d[p[i] >> 4];
    s += d[p[i] & 15];
  }
  return s;
}

JsonObject vectorNamed(const char* name) {
  for (JsonObject v : g_doc["vectors"].as<JsonArray>()) {
    if (strcmp(v["name"] | "", name) == 0) return v;
  }
  return JsonObject();
}

DeviceStatus statusFrom(JsonObject s) {
  DeviceStatus st;
  st.state = static_cast<ProvState>(s["state"].as<int>());
  st.err = static_cast<ProvErr>(s["err"].as<int>());
  st.keySet = s["keySet"].as<bool>();
  st.keyConfirmed = s["keyConfirmed"].as<bool>();
  fry::maskMinerKey(s["key"] | "", st.keyMasked, sizeof(st.keyMasked));
  st.regHttp = s["regHttp"].as<int>();
  st.hbAgeS = s["hbAgeS"].as<int32_t>();
  st.fw = s["fw"] | "";
  st.ota = s["ota"] | "";
  st.apCode = s["apCode"] | "";
  return st;
}

KeyWriteVerdict verdictFrom(const char* v) {
  if (strcmp(v, "accept") == 0) return KeyWriteVerdict::Accept;
  if (strcmp(v, "bad_key") == 0) return KeyWriteVerdict::BadKey;
  return KeyWriteVerdict::Locked;
}

void test_the_fixture_loads_with_all_seven_vectors() {
  TEST_ASSERT_EQUAL_INT(1, g_doc["schema"].as<int>());
  const char* names[] = {"kFryReqSetKey",    "kFryReqGetStatus",    "kFrySetKeyOk",
                         "kFrySetKeyBadKey", "kFrySetKeyLocked",    "kFryStatusConnected",
                         "kFryStatusKeyRequired"};
  for (const char* n : names) TEST_ASSERT_FALSE_MESSAGE(vectorNamed(n).isNull(), n);
  TEST_ASSERT_EQUAL_size_t(7, g_doc["vectors"].as<JsonArray>().size());
}

void test_every_result_vector_is_what_the_encoder_writes_for_its_strings() {
  for (JsonObject v : g_doc["vectors"].as<JsonArray>()) {
    if (strcmp(v["kind"] | "", "rpc_result") != 0) continue;
    std::vector<std::string> owned;
    for (JsonVariant s : v["strings"].as<JsonArray>()) owned.push_back(s.as<const char*>());
    std::vector<const char*> ptrs;
    for (auto& s : owned) ptrs.push_back(s.c_str());
    uint8_t out[fry::improv::kMaxPacket];
    const size_t n = fry::improv::encodeRpcResult(static_cast<uint8_t>(v["command"].as<int>()),
                                                  ptrs.data(), static_cast<uint8_t>(ptrs.size()),
                                                  out, sizeof(out));
    TEST_ASSERT_EQUAL_STRING_MESSAGE(v["hex"] | "", toHex(out, n).c_str(), v["name"] | "");
  }
}

void test_key_write_results_come_from_the_verdict_encoder() {
  for (const char* name : {"kFrySetKeyOk", "kFrySetKeyBadKey", "kFrySetKeyLocked"}) {
    JsonObject v = vectorNamed(name);
    uint8_t out[fry::improv::kMaxPacket];
    const size_t n = fry::improv::encodeKeyWriteResult(verdictFrom(v["verdict"] | ""),
                                                       v["masked"] | "", out, sizeof(out));
    TEST_ASSERT_EQUAL_STRING_MESSAGE(v["hex"] | "", toHex(out, n).c_str(), name);
  }
}

void test_status_results_come_from_the_status_encoder() {
  for (const char* name : {"kFryStatusConnected", "kFryStatusKeyRequired"}) {
    JsonObject v = vectorNamed(name);
    uint8_t out[fry::improv::kMaxPacket];
    const size_t n = fry::improv::encodeFryStatus(statusFrom(v["status"]), out, sizeof(out));
    TEST_ASSERT_EQUAL_STRING_MESSAGE(v["hex"] | "", toHex(out, n).c_str(), name);
  }
}

void test_request_vectors_parse_to_their_command_and_data() {
  for (JsonObject v : g_doc["vectors"].as<JsonArray>()) {
    if (strcmp(v["kind"] | "", "rpc_request") != 0) continue;
    const std::vector<uint8_t> bytes = fromHex(v["hex"] | "");
    Parser p;
    Result r = Result::None;
    for (uint8_t b : bytes) r = p.feed(b);
    TEST_ASSERT_EQUAL_MESSAGE((int)Result::Rpc, (int)r, v["name"] | "");
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(v["command"].as<int>()), p.command());
    TEST_ASSERT_EQUAL_STRING(v["data_hex"] | "", toHex(p.data(), p.dataLen()).c_str());
  }
  JsonObject set = vectorNamed("kFryReqSetKey");
  const std::vector<uint8_t> data = fromHex(set["data_hex"] | "");
  char key[40];
  TEST_ASSERT_TRUE(fry::improv::decodeKeyWrite(data.data(), static_cast<uint8_t>(data.size()), key,
                                               sizeof(key)));
  TEST_ASSERT_EQUAL_STRING(set["key"] | "", key);
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  FILE* f = fopen(kFixture, "rb");
  std::string body;
  if (f) {
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) body.append(buf, n);
    fclose(f);
  }
  UNITY_BEGIN();
  if (!f || deserializeJson(g_doc, body)) {
    printf("cannot read %s from the project root\n", kFixture);
    return UNITY_END() + 1;
  }
  RUN_TEST(test_the_fixture_loads_with_all_seven_vectors);
  RUN_TEST(test_every_result_vector_is_what_the_encoder_writes_for_its_strings);
  RUN_TEST(test_key_write_results_come_from_the_verdict_encoder);
  RUN_TEST(test_status_results_come_from_the_status_encoder);
  RUN_TEST(test_request_vectors_parse_to_their_command_and_data);
  return UNITY_END();
}
