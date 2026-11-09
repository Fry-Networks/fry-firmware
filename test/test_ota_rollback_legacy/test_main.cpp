// #34: clients already in the field (v0.3.1, 0.3.3) must read a manifest that carries the nested
// builds.<env>.rollback object exactly as they read the same manifest without it. Compiles their
// verbatim selector excerpts (test/test_legacy_manifest_select/*.inc), like that suite does.
#include <unity.h>

#include <ArduinoJson.h>

#include <cstring>
#include <string>

#include "semver.h"

namespace {

struct NullSerial {
  void println(const char*) {}
} Serial;

struct Selection {
  bool parsed = false;
  bool willUpdate = false;
  std::string latest, url, sha;
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

#define ROLLBACK_OBJ \
  R"("rollback":{"version":"0.3.0","url":"https://example.invalid/old.bin","sha256":"9999999999999999999999999999999999999999999999999999999999999999","from":["0.4.0","0.3.3"],"size":1,"x":{"y":[1,2]}})"
const char kPlain[] =
    R"({"builds":{"esp32":{"sha256":"2222222222222222222222222222222222222222222222222222222222222222","url":"https://example.invalid/new.bin"}},"channel":"prod","firmware_version":"0.4.0"})";
const char kWithRollback[] =
    R"({"builds":{"esp32":{"sha256":"2222222222222222222222222222222222222222222222222222222222222222","url":"https://example.invalid/new.bin",)" ROLLBACK_OBJ
    R"(}},"channel":"prod","firmware_version":"0.4.0"})";
// Manifest demoted to the rollback target: legacy clients above it must not move at all.
const char kDemoted[] =
    R"({"builds":{"esp32":{"sha256":"2222222222222222222222222222222222222222222222222222222222222222","url":"https://example.invalid/new.bin",)" ROLLBACK_OBJ
    R"(}},"channel":"prod","firmware_version":"0.3.0"})";

void test_rollback_object_never_changes_a_legacy_selection() {
  const char* const installed[] = {"0.3.0", "0.3.1", "0.3.2", "0.3.3", "0.4.0", "0.4.25"};
  const char* const envs[] = {"esp32", "esp8266"};
  for (int s = 0; s < 2; s++) {
    for (const char* cur : installed) {
      for (const char* env : envs) {
        Selection a = kSelectors[s](kPlain, env, cur);
        Selection b = kSelectors[s](kWithRollback, env, cur);
        TEST_ASSERT_TRUE(b.parsed);
        TEST_ASSERT_EQUAL(a.willUpdate, b.willUpdate);
        TEST_ASSERT_EQUAL_STRING(a.url.c_str(), b.url.c_str());
        TEST_ASSERT_EQUAL_STRING(a.sha.c_str(), b.sha.c_str());
        TEST_ASSERT_EQUAL_STRING(a.latest.c_str(), b.latest.c_str());
      }
    }
  }
}

void test_positive_control_the_selector_does_update_when_newer() {
  for (int s = 0; s < 2; s++) {
    Selection r = kSelectors[s](kWithRollback, "esp32", "0.3.1");
    TEST_ASSERT_TRUE(r.willUpdate);
    TEST_ASSERT_EQUAL_STRING("https://example.invalid/new.bin", r.url.c_str());  // the build url, not the rollback's
  }
}

void test_legacy_clients_never_take_the_rollback_target() {
  const char* const installed[] = {"0.3.1", "0.3.3", "0.4.0", "0.4.25"};
  for (int s = 0; s < 2; s++) {
    for (const char* cur : installed) {
      Selection r = kSelectors[s](kDemoted, "esp32", cur);
      TEST_ASSERT_TRUE(r.parsed);
      TEST_ASSERT_FALSE(r.willUpdate);
      TEST_ASSERT_TRUE(r.url.find("old.bin") == std::string::npos);
    }
  }
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_rollback_object_never_changes_a_legacy_selection);
  RUN_TEST(test_positive_control_the_selector_does_update_when_newer);
  RUN_TEST(test_legacy_clients_never_take_the_rollback_target);
  return UNITY_END();
}
