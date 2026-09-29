// The "fw-hold" kill switch (tools/fw-hold/manifest.json, PROTOCOL.md section 11.8): published as
// the manifest of a normal (non-prerelease) release, it must stop EVERY client from updating:
//   - v0.3.1 and 0.3.3 clients, through their manifest-selection code exactly as it shipped (the
//     verbatim excerpts test_legacy_manifest_select compiles and verify_excerpts.sh re-checks),
//   - 0.4.x clients, through decideOtaUpdate (NotNewer, whatever version and channel they run).
// Asserted on the exact bytes of the committed file, read from the project root at run time.
#include <unity.h>

#include <ArduinoJson.h>

#include <cstdio>
#include <cstring>
#include <string>

#include "ota_health.h"
#include "semver.h"

namespace {

const char kHoldFile[] = "tools/fw-hold/manifest.json";
std::string g_body;

struct NullSerial {
  void println(const char*) {}
} Serial;

struct Selection {
  bool parsed = false;
  bool willUpdate = false;
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

const char* const kEnvs[] = {"esp32", "esp32c3", "esp32s3", "esp8266"};

void test_the_file_is_exactly_the_kill_switch() {
  TEST_ASSERT_EQUAL_STRING("{\"firmware_version\":\"0.0.0\",\"channel\":\"prod\",\"builds\":{}}\n",
                           g_body.c_str());
}

void test_v031_and_033_clients_get_no_url_on_any_chip() {
  const char* installed[] = {"0.3.0", "0.3.1", "0.3.2", "0.3.3"};
  for (auto sel : {select_v031, select_v033}) {
    for (const char* env : kEnvs) {
      for (const char* cur : installed) {
        Selection r = sel(g_body.c_str(), env, cur);
        TEST_ASSERT_TRUE(r.parsed);
        TEST_ASSERT_FALSE(r.willUpdate);
        TEST_ASSERT_EQUAL_STRING("", r.url.c_str());
        TEST_ASSERT_EQUAL_STRING("", r.sha.c_str());
      }
    }
  }
}

void test_04x_clients_see_nothing_newer() {
  JsonDocument doc;
  TEST_ASSERT_FALSE(deserializeJson(doc, g_body));
  const char* latest = doc["firmware_version"] | "";
  const char* channel = doc["channel"] | "";
  const char* running[] = {"0.4.0", "0.4.1-rc.1", "0.4.1", "0.4.90"};
  for (const char* env : kEnvs) {
    JsonObject build = doc["builds"][env];
    const char* url = build["url"] | "";
    const char* sha = build["sha256"] | "";
    for (const char* cur : running) {
      TEST_ASSERT_EQUAL((int)fry::OtaDecision::NotNewer,
                        (int)fry::decideOtaUpdate(channel, "prod", latest, cur, "", url, sha));
    }
    // A *_test board pointed at it by mistake refuses it on the channel alone.
    TEST_ASSERT_EQUAL((int)fry::OtaDecision::WrongChannel,
                      (int)fry::decideOtaUpdate(channel, "test", latest, "0.4.0", "", url, sha));
  }
}

void test_the_kill_switch_clears_strikes_rather_than_keeping_them() {
  // A board holding strikes for 0.4.1 sees 0.0.0: a different latest, so its count restarts and a
  // later re-publish of 0.4.1 is tried again from scratch.
  TEST_ASSERT_TRUE(fry::strikesReset("0.0.0", "0.4.1"));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  FILE* f = fopen(kHoldFile, "rb");
  if (f) {
    char buf[1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) g_body.append(buf, n);
    fclose(f);
  }
  UNITY_BEGIN();
  if (!f) {
    printf("cannot read %s from the project root\n", kHoldFile);
    return UNITY_END() + 1;
  }
  RUN_TEST(test_the_file_is_exactly_the_kill_switch);
  RUN_TEST(test_v031_and_033_clients_get_no_url_on_any_chip);
  RUN_TEST(test_04x_clients_see_nothing_newer);
  RUN_TEST(test_the_kill_switch_clears_strikes_rather_than_keeping_them);
  return UNITY_END();
}
