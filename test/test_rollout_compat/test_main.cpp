// Compatibility of the staged-rollout manifest field (lib/fry_core/ota_rollout*.h):
//
//  1. Boards already in the field (v0.3.1 / 0.3.3 manifest selection, compiled here EXACTLY as they
//     shipped from test/test_legacy_manifest_select/*.inc, which this test includes and does not
//     modify) ignore a top-level "rollout" key: the selection is the same with and without it.
//  2. 0.4.5 and 0.4.7 (their manifest parse region, ota_client.cpp:497-539, and decideOtaUpdate,
//     ota_health.cpp:101-109, are byte-identical between the two tags) behave exactly as before
//     when the field is absent OR malformed: an exhaustive table against a verbatim copy of the
//     0.4.7 decision, plus the firmware's parse -> evaluate -> decide pipeline mirrored below.
//     (ota_client.cpp itself needs the Arduino core and cannot be compiled on the host.)
//  3. The manifest tools/make_manifest.py emits with --rollout-* parses and gates as designed.
#include <unity.h>

#include <ArduinoJson.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "ota_health.h"
#include "ota_rollout_json.h"
#include "semver.h"
#include "sha256.h"

namespace {

// ---- legacy excerpts, compiled as shipped (same wrapper as test_legacy_manifest_select) ----

struct NullSerial {
  void println(const char*) {}
} Serial;

struct Selection {
  bool parsed = false;
  bool willUpdate = false;
  std::string latest;
  std::string url;
  std::string sha;
};

#define FRY_BUILD_ENV env
#define FRY_FIRMWARE_VERSION current

Selection select_v031(const char* body, const char* env, const char* current) {
  Selection r;
  auto run = [&]() -> bool {
#include "../test_legacy_manifest_select/legacy_v031_select.inc"
    r.parsed = true;
    r.latest = latest;
    r.url = url;
    r.sha = sha;
    r.willUpdate = willUpdate;
    return willUpdate;
  };
  run();
  return r;
}

Selection select_v033(const char* body, const char* env, const char* current) {
  Selection r;
  auto run = [&]() -> bool {
#include "../test_legacy_manifest_select/legacy_v033_select.inc"
    r.parsed = true;
    r.latest = latest;
    r.url = url;
    r.sha = sha;
    r.willUpdate = willUpdate;
    return willUpdate;
  };
  run();
  return r;
}

#undef FRY_BUILD_ENV
#undef FRY_FIRMWARE_VERSION

typedef Selection (*Selector)(const char*, const char*, const char*);
const Selector kSelectors[] = {select_v031, select_v033};
const char* const kSelectorNames[] = {"v0.3.1", "0.3.3"};

// What `make_manifest.py --version 0.4.8 --no-exclusions --envs esp32,esp32c3,esp8266 --rollout-lo 0
// --rollout-hi 10 --rollout-allow <2 prefixes>` writes (compact; the tool pretty-prints the same keys).
const char kToolManifestWithRollout[] =
    "{\"builds\":{\"esp32\":{\"sha256\":\"2f49c768c0f58454b279eaa2794a6500fd58b1dd5a07babd98dd867453b9a2db\","
    "\"url\":\"https://example.invalid/rel/firmware-esp32.bin\"},\"esp32c3\":{\"sha256\":"
    "\"aed042b7b5cb4677e619e5ba71bdab8b53cb938095ca28e6b84850286320be24\",\"url\":"
    "\"https://example.invalid/rel/firmware-esp32c3.bin\"},\"esp8266\":{\"sha256\":"
    "\"23917810c308ce823244022f2cf4d7403ce74f5de59a80ae6283a209454f0caf\",\"url\":"
    "\"https://example.invalid/rel/firmware-esp8266.bin\"}},\"channel\":\"prod\",\"firmware_version\":\"0.4.8\","
    "\"olostep_kill\":false,\"rollout\":{\"allow\":[\"9fa03ae3c55d4deb\",\"ba7816bf8f01cfea\"],"
    "\"bucket_hi\":10,\"bucket_lo\":0}}";
// The same manifest without the key (what the tool wrote before the flags existed).
const char kToolManifestPlain[] =
    "{\"builds\":{\"esp32\":{\"sha256\":\"2f49c768c0f58454b279eaa2794a6500fd58b1dd5a07babd98dd867453b9a2db\","
    "\"url\":\"https://example.invalid/rel/firmware-esp32.bin\"},\"esp32c3\":{\"sha256\":"
    "\"aed042b7b5cb4677e619e5ba71bdab8b53cb938095ca28e6b84850286320be24\",\"url\":"
    "\"https://example.invalid/rel/firmware-esp32c3.bin\"},\"esp8266\":{\"sha256\":"
    "\"23917810c308ce823244022f2cf4d7403ce74f5de59a80ae6283a209454f0caf\",\"url\":"
    "\"https://example.invalid/rel/firmware-esp8266.bin\"}},\"channel\":\"prod\",\"firmware_version\":\"0.4.8\","
    "\"olostep_kill\":false}";

// Splice a "rollout" value into the plain manifest (before its closing brace).
std::string withRollout(const char* rolloutJson) {
  std::string s = kToolManifestPlain;
  s.pop_back();
  s += ",\"rollout\":";
  s += rolloutJson;
  s += "}";
  return s;
}

const char* const kRolloutVariants[] = {
    "{\"bucket_lo\":0,\"bucket_hi\":10}",
    "{\"bucket_lo\":0,\"bucket_hi\":0}",
    "{\"bucket_lo\":99,\"bucket_hi\":99}",
    "{\"bucket_lo\":0,\"bucket_hi\":99,\"allow\":[]}",
    "{\"bucket_lo\":0,\"bucket_hi\":10,\"allow\":[\"9fa03ae3c55d4deb\"]}",
    "{\"bucket_lo\":60,\"bucket_hi\":50}",                 // malformed: lo > hi
    "{\"bucket_lo\":0,\"bucket_hi\":100}",                 // malformed: out of range
    "{\"bucket_lo\":\"0\",\"bucket_hi\":10}",              // malformed: strings
    "{\"bucket_lo\":0,\"bucket_hi\":10,\"allow\":\"x\"}",  // malformed: allow not a list
    "{\"bucket_lo\":0,\"bucket_hi\":10,\"allow\":[[\"9fa03ae3c55d4deb\"]]}",
    "{\"rollout\":{\"bucket_lo\":0,\"bucket_hi\":10}}",
    "5", "\"x\"", "null", "[]", "{}", "true",
};

const char* const kEnvs[] = {"esp32", "esp32c3", "esp8266", "esp32s3"};
const char* const kInstalled[] = {"0.3.1", "0.3.2", "0.3.3", "0.4.0", "0.4.5", "0.4.7", "0.4.8", "0.5.0"};

void assertSameSelection(const Selection& a, const Selection& b, const char* msg) {
  TEST_ASSERT_EQUAL_MESSAGE(a.parsed, b.parsed, msg);
  TEST_ASSERT_EQUAL_MESSAGE(a.willUpdate, b.willUpdate, msg);
  TEST_ASSERT_EQUAL_STRING_MESSAGE(a.latest.c_str(), b.latest.c_str(), msg);
  TEST_ASSERT_EQUAL_STRING_MESSAGE(a.url.c_str(), b.url.c_str(), msg);
  TEST_ASSERT_EQUAL_STRING_MESSAGE(a.sha.c_str(), b.sha.c_str(), msg);
}

// ---- 1. legacy clients ----

void test_legacy_clients_select_the_same_with_and_without_rollout() {
  for (int s = 0; s < 2; s++) {
    for (const char* env : kEnvs) {
      for (const char* cur : kInstalled) {
        const Selection base = kSelectors[s](kToolManifestPlain, env, cur);
        const Selection withTool = kSelectors[s](kToolManifestWithRollout, env, cur);
        char msg[160];
        snprintf(msg, sizeof(msg), "%s %s on %s (tool manifest)", kSelectorNames[s], cur, env);
        assertSameSelection(base, withTool, msg);
        for (const char* variant : kRolloutVariants) {
          const std::string body = withRollout(variant);
          snprintf(msg, sizeof(msg), "%s %s on %s rollout=%s", kSelectorNames[s], cur, env, variant);
          assertSameSelection(base, kSelectors[s](body.c_str(), env, cur), msg);
        }
      }
    }
  }
}

void test_legacy_positive_control_they_do_update_and_never_without_a_build() {
  for (int s = 0; s < 2; s++) {
    const Selection a = kSelectors[s](kToolManifestWithRollout, "esp32", "0.3.3");
    TEST_ASSERT_TRUE(a.parsed);
    TEST_ASSERT_TRUE(a.willUpdate);  // the gate is invisible to them: update, whatever the bucket
    TEST_ASSERT_EQUAL_STRING("https://example.invalid/rel/firmware-esp32.bin", a.url.c_str());
    const Selection none = kSelectors[s](kToolManifestWithRollout, "esp32s3", "0.3.3");
    TEST_ASSERT_FALSE(none.willUpdate);
    TEST_ASSERT_EQUAL_STRING("", none.url.c_str());
  }
}

// ---- 2. 0.4.5 / 0.4.7 ----

// VERBATIM lib/fry_core/ota_health.cpp:101-109 at fw-v0.4.7 (identical at fw-v0.4.5).
bool empty(const char* s) { return s == nullptr || s[0] == 0; }
fry::OtaDecision decide_v047(const char* manifestChannel, const char* ownChannel, const char* latest,
                             const char* current, const char* badver, const char* url,
                             const char* sha256) {
  if (!fry::otaChannelAccepted(manifestChannel, ownChannel)) return fry::OtaDecision::WrongChannel;
  if (empty(latest) || !fry::isNewerVersionOta(latest, current)) return fry::OtaDecision::NotNewer;
  if (fry::isSkippedBadVersion(latest, badver)) return fry::OtaDecision::BadVersion;
  if (empty(url) || empty(sha256)) return fry::OtaDecision::NoBuild;
  return fry::OtaDecision::Update;
}

void test_decision_table_matches_v047_exhaustively() {
  const char* const channels[] = {nullptr, "", "prod", "test", "Prod"};
  const char* const owns[] = {"prod", "test", "", nullptr};
  const char* const latests[] = {nullptr, "", "0.4.7", "0.4.8", "0.4.10", "0.5.0-rc.1", "garbage", "0.4.8-rc.1"};
  const char* const currents[] = {"0.4.7", "0.4.5", "0.4.8", "0.4.8-rc.1"};
  const char* const badvers[] = {nullptr, "", "0.4.8", "0.4.10"};
  const char* const urls[] = {nullptr, "", "https://x/y.bin"};
  const char* const shas[] = {nullptr, "", "2222222222222222222222222222222222222222222222222222222222222222"};
  int n = 0;
  for (auto ch : channels)
    for (auto own : owns)
      for (auto la : latests)
        for (auto cu : currents)
          for (auto bv : badvers)
            for (auto u : urls)
              for (auto sh : shas) {
                const fry::OtaDecision want = decide_v047(ch, own, la, cu, bv, u, sh);
                // the old 7-argument call (every existing caller) and the gate left open
                TEST_ASSERT_EQUAL((int)want, (int)fry::decideOtaUpdate(ch, own, la, cu, bv, u, sh));
                TEST_ASSERT_EQUAL((int)want, (int)fry::decideOtaUpdate(ch, own, la, cu, bv, u, sh, true));
                // a closed gate changes ONLY outcomes that would have reached NoBuild/Update
                const fry::OtaDecision closed = fry::decideOtaUpdate(ch, own, la, cu, bv, u, sh, false);
                if (want == fry::OtaDecision::NoBuild || want == fry::OtaDecision::Update) {
                  TEST_ASSERT_EQUAL((int)fry::OtaDecision::NotInRollout, (int)closed);
                } else {
                  TEST_ASSERT_EQUAL((int)want, (int)closed);
                }
                n++;
              }
  TEST_ASSERT_TRUE(n > 10000);
}

// The firmware's pipeline (src/core/ota_client.cpp checkNow), mirrored: parse, read the build entry,
// evaluate the rollout from the key digest, decide.
fry::OtaDecision pipeline(const char* body, const char* env, const char* current, const char* key) {
  JsonDocument doc;
  if (deserializeJson(doc, body)) return fry::OtaDecision::NotNewer;
  const char* latest = doc["firmware_version"] | "";
  const char* channel = doc["channel"] | "";
  JsonObject build = doc["builds"][env];
  const char* url = build["url"] | "";
  const char* sha = build["sha256"] | "";
  bool inRollout = true;
  if (key && key[0]) {
    uint8_t d[32];
    fry::Sha256::hash(reinterpret_cast<const uint8_t*>(key), strlen(key), d);
    inRollout = fry::rolloutAllows(fry::evaluateRollout(doc, d));
  }
  return fry::decideOtaUpdate(channel, "prod", latest, current, "", url, sha, inRollout);
}

void test_absent_or_malformed_rollout_is_the_047_decision() {
  const char* const keys[] = {"abc", "FEM-TEST-0001", "", "FEM-ZZZ"};
  const char* const malformed[] = {
      "{\"bucket_lo\":60,\"bucket_hi\":50}", "{\"bucket_lo\":0,\"bucket_hi\":100}",
      "{\"bucket_lo\":\"0\",\"bucket_hi\":10}", "{\"bucket_lo\":0,\"bucket_hi\":10,\"allow\":\"x\"}",
      "{\"bucket_lo\":0,\"bucket_hi\":10,\"allow\":[[\"9fa03ae3c55d4deb\"]]}",
      "{\"bucket_lo\":0,\"bucket_hi\":10,\"allow\":[\"short\"]}", "5", "null", "[]", "{}", "\"x\"",
  };
  for (const char* env : kEnvs) {
    for (const char* cur : {"0.4.5", "0.4.7", "0.4.8", "0.5.0"}) {
      for (const char* key : keys) {
        const fry::OtaDecision base = pipeline(kToolManifestPlain, env, cur, key);
        for (const char* m : malformed) {
          const std::string body = withRollout(m);
          char msg[200];
          snprintf(msg, sizeof(msg), "env=%s cur=%s malformed=%s", env, cur, m);
          TEST_ASSERT_EQUAL_MESSAGE((int)base, (int)pipeline(body.c_str(), env, cur, key), msg);
        }
      }
    }
  }
  // the unchanged baseline really is "update" for a chip that has a build (so the loop proves something)
  TEST_ASSERT_EQUAL((int)fry::OtaDecision::Update, (int)pipeline(kToolManifestPlain, "esp32", "0.4.7", "abc"));
  TEST_ASSERT_EQUAL((int)fry::OtaDecision::NoBuild, (int)pipeline(kToolManifestPlain, "esp32s3", "0.4.7", "abc"));
}

void test_boundaries_through_the_pipeline() {
  // "abc" is bucket 19, "FEM-TEST-0001" is bucket 79 (test_ota_rollout), "" bucket 10 but a keyless
  // board is never gated (ota_client.cpp).
  struct Case {
    const char* rollout;
    const char* key;
    fry::OtaDecision want;
  };
  const fry::OtaDecision U = fry::OtaDecision::Update, N = fry::OtaDecision::NotInRollout;
  const Case cases[] = {
      {"{\"bucket_lo\":0,\"bucket_hi\":99}", "abc", U},
      {"{\"bucket_lo\":0,\"bucket_hi\":99}", "FEM-TEST-0001", U},
      {"{\"bucket_lo\":19,\"bucket_hi\":19}", "abc", U},          // lo == hi, hit
      {"{\"bucket_lo\":19,\"bucket_hi\":19}", "FEM-TEST-0001", N},
      {"{\"bucket_lo\":0,\"bucket_hi\":0}", "abc", N},
      {"{\"bucket_lo\":99,\"bucket_hi\":99}", "abc", N},
      {"{\"bucket_lo\":79,\"bucket_hi\":99}", "FEM-TEST-0001", U},
      {"{\"bucket_lo\":0,\"bucket_hi\":78}", "FEM-TEST-0001", N},
      {"{\"bucket_lo\":0,\"bucket_hi\":0,\"allow\":[]}", "abc", N},   // empty allow adds nobody
      {"{\"bucket_lo\":0,\"bucket_hi\":0,\"allow\":[\"ba7816bf8f01cfea\"]}", "abc", U},
      {"{\"bucket_lo\":0,\"bucket_hi\":0,\"allow\":[\"ba7816bf8f01cfea\"]}", "FEM-TEST-0001", N},
      {"{\"bucket_lo\":0,\"bucket_hi\":0}", "", U},                  // no key: not gated
  };
  for (const Case& c : cases) {
    const std::string body = withRollout(c.rollout);
    char msg[200];
    snprintf(msg, sizeof(msg), "%s key=%s", c.rollout, c.key);
    TEST_ASSERT_EQUAL_MESSAGE((int)c.want, (int)pipeline(body.c_str(), "esp32", "0.4.7", c.key), msg);
  }
  // the gate never rescues what 0.4.7 already refused
  const std::string body = withRollout("{\"bucket_lo\":0,\"bucket_hi\":99}");
  TEST_ASSERT_EQUAL((int)fry::OtaDecision::NotNewer, (int)pipeline(body.c_str(), "esp32", "0.4.8", "abc"));
  TEST_ASSERT_EQUAL((int)fry::OtaDecision::NoBuild, (int)pipeline(body.c_str(), "esp32s3", "0.4.7", "abc"));
}

// ---- 3. the tool's manifest ----

void test_tool_manifest_gates_as_designed() {
  // allow: ba7816bf8f01cfea = "abc" (bucket 19, outside 0..10) -> eligible; "FEM-TEST-0001" is listed too
  TEST_ASSERT_EQUAL((int)fry::OtaDecision::Update, (int)pipeline(kToolManifestWithRollout, "esp32", "0.4.7", "abc"));
  TEST_ASSERT_EQUAL((int)fry::OtaDecision::Update,
                    (int)pipeline(kToolManifestWithRollout, "esp8266", "0.4.7", "FEM-TEST-0001"));
  // a key in neither the range nor the allow list is held back
  TEST_ASSERT_EQUAL((int)fry::OtaDecision::NotInRollout,
                    (int)pipeline(kToolManifestWithRollout, "esp32", "0.4.7", "FEM-OTHER-KEY-7"));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_legacy_clients_select_the_same_with_and_without_rollout);
  RUN_TEST(test_legacy_positive_control_they_do_update_and_never_without_a_build);
  RUN_TEST(test_decision_table_matches_v047_exhaustively);
  RUN_TEST(test_absent_or_malformed_rollout_is_the_047_decision);
  RUN_TEST(test_boundaries_through_the_pipeline);
  RUN_TEST(test_tool_manifest_gates_as_designed);
  return UNITY_END();
}
