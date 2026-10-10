// A2 fleet OTA safety: what do boards ALREADY IN THE FIELD do with the new production manifest?
//
// The 0.4.0 prod manifest leaves esp32s3 and esp8266 out of "builds" on purpose (no automatic OTA to
// those chips until a real board passes - tools/ota_channels.json). That is only safe if the OLD
// clients, which nobody can update any more, treat a missing entry as "no update" and never fall
// back to another chip's image. This suite compiles their manifest-selection code EXACTLY as it
// shipped and feeds it the new manifest shape.
//
// legacy_v031_select.inc / legacy_v033_select.inc are verbatim copies, not rewrites:
//   v0.3.1   src/core/ota_client.cpp  blob 58da1129c8b5716747ef55dbeb6561ee271bd378
//            file sha256 d15bb6000f7e714be99cf8081fe0a5d36bb16b9cdf902831ede338fc3027d925, lines 273-289
//   0.3.3    src/core/ota_client.cpp at d7a2433  blob e2d7e5144b339bba708c4e605b0b4c7ed8303254
//            file sha256 966dc1d9a763bd407f3abdbede6023df11b487f5b7cee2848978653c9e51c5fc, lines 292-308
//   both excerpts sha256 8bf3faaed1301c8601dba0ce15c1ef7ae93b7eaf9e385777f0f714623799dbf7 (identical)
// Re-verify with test/test_legacy_manifest_select/verify_excerpts.sh (needs the git tags).
// The fry::isNewerVersion they call is lib/fry_core/semver.cpp, unchanged since v0.3.1 (0.4.0 only
// appends new functions after it). The JSON parser is the same bblanchon/ArduinoJson@^7.4.2 the
// firmware links.
//
// Set FRY_A2_MANIFEST=<path> to run the same assertions against a real manifest file (e.g. the
// exact CI-built release asset) in addition to the synthetic one.
#include <unity.h>

#include <ArduinoJson.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "semver.h"

namespace {

// The excerpts log through Arduino's Serial; nothing here needs to see it.
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

// FRY_BUILD_ENV / FRY_FIRMWARE_VERSION are compile-time macros in the firmware; here they name the
// wrapper's parameters so one binary can play every chip and every installed version.
#define FRY_BUILD_ENV env
#define FRY_FIRMWARE_VERSION current

Selection select_v031(const char* body, const char* env, const char* current) {
  Selection r;
  auto run = [&]() -> bool {
#include "legacy_v031_select.inc"
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
#include "legacy_v033_select.inc"
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
// Versions field boards run today: the GitHub release, and the two Pages flasher builds.
const char* const kInstalled[] = {"0.3.1", "0.3.2", "0.3.3"};

// Exactly the shape tools/make_manifest.py writes for the prod channel (json.dump, indent=2,
// sort_keys): esp32 and esp32c3 only, each with its factory image, plus the new "channel" key.
const char kProdManifest[] = R"({
  "builds": {
    "esp32": {
      "factory": {
        "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
        "url": "https://github.com/Fry-Networks/fry-firmware/releases/download/fw-v0.4.0/firmware-esp32-factory.bin"
      },
      "sha256": "2222222222222222222222222222222222222222222222222222222222222222",
      "url": "https://github.com/Fry-Networks/fry-firmware/releases/download/fw-v0.4.0/firmware-esp32.bin"
    },
    "esp32c3": {
      "factory": {
        "sha256": "3333333333333333333333333333333333333333333333333333333333333333",
        "url": "https://github.com/Fry-Networks/fry-firmware/releases/download/fw-v0.4.0/firmware-esp32c3-factory.bin"
      },
      "sha256": "4444444444444444444444444444444444444444444444444444444444444444",
      "url": "https://github.com/Fry-Networks/fry-firmware/releases/download/fw-v0.4.0/firmware-esp32c3.bin"
    }
  },
  "channel": "prod",
  "firmware_version": "0.4.0"
}
)";

// Positive control: the same manifest with an esp32s3 entry present.
const char kWithS3[] = R"({"builds":{"esp32":{"sha256":"2222222222222222222222222222222222222222222222222222222222222222","url":"https://example.invalid/firmware-esp32.bin"},"esp32s3":{"sha256":"5555555555555555555555555555555555555555555555555555555555555555","url":"https://example.invalid/firmware-esp32s3.bin"}},"channel":"prod","firmware_version":"0.4.0"})";

bool contains(const std::string& s, const char* needle) { return s.find(needle) != std::string::npos; }

// The assertions that make publishing safe, for any manifest that lists only esp32 + esp32c3.
void assertOldClientsSafe(const char* manifest, const char* label) {
  const char* const missing[] = {"esp32s3", "esp8266"};
  const char* const present[] = {"esp32", "esp32c3"};
  for (int s = 0; s < 2; s++) {
    for (const char* cur : kInstalled) {
      for (const char* env : missing) {
        Selection r = kSelectors[s](manifest, env, cur);
        char msg[160];
        snprintf(msg, sizeof(msg), "%s client %s %s on %s", kSelectorNames[s], cur, env, label);
        TEST_ASSERT_TRUE_MESSAGE(r.parsed, msg);
        TEST_ASSERT_FALSE_MESSAGE(r.willUpdate, msg);
        TEST_ASSERT_EQUAL_STRING_MESSAGE("", r.url.c_str(), msg);  // no URL at all ...
        TEST_ASSERT_EQUAL_STRING_MESSAGE("", r.sha.c_str(), msg);  // ... so no other chip's image
      }
      for (const char* env : present) {
        Selection r = kSelectors[s](manifest, env, cur);
        char msg[160];
        snprintf(msg, sizeof(msg), "%s client %s %s on %s", kSelectorNames[s], cur, env, label);
        TEST_ASSERT_TRUE_MESSAGE(r.willUpdate, msg);
        char tail[40];
        snprintf(tail, sizeof(tail), "/firmware-%s.bin", env);
        TEST_ASSERT_TRUE_MESSAGE(r.url.size() > strlen(tail) &&
                                     r.url.compare(r.url.size() - strlen(tail), strlen(tail), tail) == 0,
                                 msg);  // its own chip's app image, never a factory image
        TEST_ASSERT_FALSE_MESSAGE(contains(r.url, "factory"), msg);
        TEST_ASSERT_EQUAL_size_t_MESSAGE(64, r.sha.size(), msg);
      }
    }
  }
}

void test_excerpts_compile_and_parse_the_prod_manifest() {
  Selection r = select_v031(kProdManifest, "esp32", "0.3.1");
  TEST_ASSERT_TRUE(r.parsed);
  TEST_ASSERT_EQUAL_STRING("0.4.0", r.latest.c_str());
  Selection q = select_v033(kProdManifest, "esp32", "0.3.3");
  TEST_ASSERT_TRUE(q.parsed);
  TEST_ASSERT_EQUAL_STRING("0.4.0", q.latest.c_str());
}

void test_old_clients_skip_a_chip_missing_from_the_manifest() {
  assertOldClientsSafe(kProdManifest, "synthetic prod manifest");
}

void test_old_clients_take_their_own_chip_image_with_the_right_sha() {
  for (int s = 0; s < 2; s++) {
    Selection a = kSelectors[s](kProdManifest, "esp32", "0.3.1");
    TEST_ASSERT_EQUAL_STRING("2222222222222222222222222222222222222222222222222222222222222222", a.sha.c_str());
    Selection c = kSelectors[s](kProdManifest, "esp32c3", "0.3.3");
    TEST_ASSERT_EQUAL_STRING("4444444444444444444444444444444444444444444444444444444444444444", c.sha.c_str());
    TEST_ASSERT_TRUE(contains(c.url, "firmware-esp32c3.bin"));
  }
}

void test_positive_control_an_s3_entry_is_found_when_present() {
  // Without this, "no URL for esp32s3" could simply mean the harness never finds anything.
  for (int s = 0; s < 2; s++) {
    Selection r = kSelectors[s](kWithS3, "esp32s3", "0.3.1");
    TEST_ASSERT_TRUE(r.willUpdate);
    TEST_ASSERT_EQUAL_STRING("https://example.invalid/firmware-esp32s3.bin", r.url.c_str());
    TEST_ASSERT_EQUAL_STRING("5555555555555555555555555555555555555555555555555555555555555555", r.sha.c_str());
  }
}

void test_old_clients_never_downgrade_and_reject_garbage() {
  for (int s = 0; s < 2; s++) {
    TEST_ASSERT_FALSE(kSelectors[s](kProdManifest, "esp32", "0.4.0").willUpdate);
    TEST_ASSERT_FALSE(kSelectors[s](kProdManifest, "esp32", "0.5.0").willUpdate);
    Selection bad = kSelectors[s]("{not json", "esp32", "0.3.1");
    TEST_ASSERT_FALSE(bad.parsed);
    TEST_ASSERT_FALSE(bad.willUpdate);
  }
}

void test_optional_real_manifest_file() {
  const char* path = getenv("FRY_A2_MANIFEST");
  if (!path || !*path) {
    printf("FRY_A2_MANIFEST not set - synthetic manifest only\n");
    return;
  }
  FILE* f = fopen(path, "rb");
  TEST_ASSERT_NOT_NULL_MESSAGE(f, path);
  std::string body;
  char buf[4096];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) body.append(buf, n);
  fclose(f);
  printf("FRY_A2_MANIFEST=%s (%u bytes)\n", path, static_cast<unsigned>(body.size()));
  assertOldClientsSafe(body.c_str(), path);
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_excerpts_compile_and_parse_the_prod_manifest);
  RUN_TEST(test_old_clients_skip_a_chip_missing_from_the_manifest);
  RUN_TEST(test_old_clients_take_their_own_chip_image_with_the_right_sha);
  RUN_TEST(test_positive_control_an_s3_entry_is_found_when_present);
  RUN_TEST(test_old_clients_never_downgrade_and_reject_garbage);
  RUN_TEST(test_optional_real_manifest_file);
  return UNITY_END();
}
