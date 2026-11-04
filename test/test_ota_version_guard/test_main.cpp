// A manifest that declares version X while the image it serves really is version Y != X
// (lib/fry_core/ota_version_guard.h, PROTOCOL.md 11.8). The device applies the image, reboots into
// Y, finds pending=X, sees no rollback and used to just clear the flag - then re-downloaded X at
// every check, forever. Now the mismatch counts as one strike for X, like a failed install.
#include <unity.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "ota_health.h"
#include "ota_version_guard.h"

namespace {

// What init() does on one boot with pending != running, minus the NVS writes.
struct Store {
  std::string badver;
  uint8_t badn = 0;
  bool firstCheckAfterRollback = false;
};

// Mirrors the two branches of ota_client.cpp init(): the rollback branch and the mismatch branch.
// Returns how many strikes this single boot added (must never be more than one).
int bootWithPending(Store& s, const char* pending, const char* running, bool rolledBack,
                    bool planned) {
  int added = 0;
  if (fry::shouldRecordBadVersion(pending, running, rolledBack)) {
    bool changed = false;
    const uint8_t n = fry::nextStrikeCount(s.badver.c_str(), s.badn, pending, planned, &changed);
    if (changed) {
      s.badver = pending;
      s.badn = n;
      s.firstCheckAfterRollback = true;
      added++;
    }
  }
  if (fry::shouldRejectManifestVersion(pending, running, rolledBack, planned)) {
    bool changed = false;
    const uint8_t n = fry::nextStrikeCount(s.badver.c_str(), s.badn, pending, false, &changed);
    if (changed) {
      s.badver = pending;
      s.badn = n;
      s.firstCheckAfterRollback = true;
      added++;
    }
  }
  return added;
}

bool skips(Store& s, const char* latest) {
  const bool r = fry::skipBadVersion(latest, s.badver.c_str(), s.badn, s.firstCheckAfterRollback);
  s.firstCheckAfterRollback = false;
  return r;
}

void test_a_mislabelled_image_is_rejected() {
  // The field case: manifest says 0.4.19, the image is a 0.4.15 build.
  TEST_ASSERT_FALSE(fry::shouldRecordBadVersion("0.4.19", "0.4.15", false));  // old behaviour: no record
  TEST_ASSERT_TRUE(fry::shouldRejectManifestVersion("0.4.19", "0.4.15", false, false));
}

void test_a_legitimate_update_is_not_a_mismatch() {
  TEST_ASSERT_FALSE(fry::shouldRejectManifestVersion("0.4.19", "0.4.19", false, false));
}

void test_a_rollback_is_not_a_mismatch() {
  TEST_ASSERT_FALSE(fry::shouldRejectManifestVersion("0.4.19", "0.4.15", true, false));
}

void test_a_planned_restart_is_not_a_mismatch() {
  TEST_ASSERT_FALSE(fry::shouldRejectManifestVersion("0.4.19", "0.4.15", false, true));
}

void test_empty_and_null_never_reject() {
  TEST_ASSERT_FALSE(fry::shouldRejectManifestVersion("", "0.4.15", false, false));
  TEST_ASSERT_FALSE(fry::shouldRejectManifestVersion(nullptr, "0.4.15", false, false));
  TEST_ASSERT_FALSE(fry::shouldRejectManifestVersion("0.4.19", "", false, false));
  TEST_ASSERT_FALSE(fry::shouldRejectManifestVersion("0.4.19", nullptr, false, false));
}

void test_the_two_branches_never_both_strike_on_one_boot() {
  const bool flags[2] = {false, true};
  const char* running[2] = {"0.4.15", "0.4.19"};
  for (bool rolledBack : flags) {
    for (bool planned : flags) {
      for (const char* r : running) {
        const bool a = fry::shouldRecordBadVersion("0.4.19", r, rolledBack);
        const bool b = fry::shouldRejectManifestVersion("0.4.19", r, rolledBack, planned);
        TEST_ASSERT_FALSE(a && b);
        Store s;
        TEST_ASSERT_TRUE(bootWithPending(s, "0.4.19", r, rolledBack, planned) <= 1);
      }
    }
  }
}

void test_three_mismatch_boots_end_in_a_permanent_skip() {
  Store s;
  TEST_ASSERT_EQUAL_INT(1, bootWithPending(s, "0.4.19", "0.4.15", false, false));
  TEST_ASSERT_EQUAL_UINT8(1, s.badn);
  TEST_ASSERT_TRUE(skips(s, "0.4.19"));    // first check after the mismatch boot
  TEST_ASSERT_FALSE(skips(s, "0.4.19"));   // the next 6 h check retries
  TEST_ASSERT_EQUAL_INT(1, bootWithPending(s, "0.4.19", "0.4.15", false, false));
  TEST_ASSERT_EQUAL_UINT8(2, s.badn);
  TEST_ASSERT_TRUE(skips(s, "0.4.19"));
  TEST_ASSERT_FALSE(skips(s, "0.4.19"));
  TEST_ASSERT_EQUAL_INT(1, bootWithPending(s, "0.4.19", "0.4.15", false, false));
  TEST_ASSERT_EQUAL_UINT8(fry::kOtaPermanentStrikes, s.badn);
  for (int i = 0; i < 5; i++) TEST_ASSERT_TRUE(skips(s, "0.4.19"));  // never again
}

void test_a_mismatch_strike_is_never_counted_for_a_planned_restart() {
  Store s;
  TEST_ASSERT_EQUAL_INT(0, bootWithPending(s, "0.4.19", "0.4.15", false, true));
  TEST_ASSERT_EQUAL_UINT8(0, s.badn);
}

void test_a_different_manifest_version_recovers() {
  Store s;
  for (int i = 0; i < 3; i++) bootWithPending(s, "0.4.19", "0.4.15", false, false);
  TEST_ASSERT_TRUE(skips(s, "0.4.19"));
  // A fixed release is published: the manifest names another version, strikes reset.
  TEST_ASSERT_TRUE(fry::strikesReset("0.4.20", s.badver.c_str()));
  s.badver.clear();
  s.badn = 0;
  TEST_ASSERT_FALSE(skips(s, "0.4.20"));
}

void test_a_rollback_still_strikes_exactly_once() {
  Store s;
  TEST_ASSERT_EQUAL_INT(1, bootWithPending(s, "0.4.19", "0.4.15", true, false));
  TEST_ASSERT_EQUAL_UINT8(1, s.badn);
}

// ---- [SOURCE PINS] over src/core/ota_client.cpp (technique of test_heal_fix_wiring) -------------
// The wiring cannot run natively (NVS and the Arduino core), so its position and shape are pinned.

bool readFile(const std::string& path, std::string& out) {
  std::ifstream f(path.c_str(), std::ios::in | std::ios::binary);
  if (!f) return false;
  std::ostringstream ss;
  ss << f.rdbuf();
  out = ss.str();
  return !out.empty();
}

bool loadSource(const std::string& rel, std::string& out) {
  const std::string self = __FILE__;
  const std::string tail = "test/test_ota_version_guard/test_main.cpp";
  std::vector<std::string> prefixes;
  if (self.size() >= tail.size() && self.compare(self.size() - tail.size(), tail.size(), tail) == 0) {
    prefixes.push_back(self.substr(0, self.size() - tail.size()));
  }
  const char* ups[] = {"", "../", "../../", "../../../", "../../../../"};
  for (size_t i = 0; i < sizeof(ups) / sizeof(ups[0]); i++) prefixes.push_back(ups[i]);
  for (size_t i = 0; i < prefixes.size(); i++) {
    if (readFile(prefixes[i] + rel, out)) return true;
  }
  return false;
}

int countOf(const std::string& hay, const std::string& needle) {
  int n = 0;
  for (size_t pos = hay.find(needle); pos != std::string::npos; pos = hay.find(needle, pos + needle.size())) n++;
  return n;
}

void test_the_guard_wiring_is_esp8266_only_and_strikes() {
  std::string src;
  TEST_ASSERT_TRUE(loadSource("src/core/ota_client.cpp", src));
  // Exactly one call, with the rollback and planned-restart markers as the last two arguments.
  TEST_ASSERT_EQUAL_INT(1, countOf(src, "fry::shouldRejectManifestVersion("));
  const size_t call = src.find("fry::shouldRejectManifestVersion(");
  TEST_ASSERT_TRUE(call != std::string::npos);
  const size_t callEnd = src.find(") {", call);
  TEST_ASSERT_TRUE(callEnd != std::string::npos);
  const std::string callText = src.substr(call, callEnd - call);
  TEST_ASSERT_TRUE(callText.find("s_rolledBack || counterRolledBack") != std::string::npos);
  TEST_ASSERT_TRUE(callText.find("plannedRestart") != std::string::npos);
  // It sits inside "#if defined(ARDUINO_ARCH_ESP8266)" ... "#endif" with no nested #if between.
  const std::string open = "#if defined(ARDUINO_ARCH_ESP8266)";
  const size_t ifPos = src.rfind("\n#if", call);
  TEST_ASSERT_TRUE(ifPos != std::string::npos);
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(src.compare(ifPos + 1, open.size(), open)));
  const size_t endifPos = src.find("\n#endif", call);
  TEST_ASSERT_TRUE(endifPos != std::string::npos);
  const std::string block = src.substr(ifPos, endifPos - ifPos);
  TEST_ASSERT_EQUAL_INT(1, countOf(block, "\n#if"));  // only the opening one
  TEST_ASSERT_EQUAL_INT(0, countOf(block, "\n#else"));
  TEST_ASSERT_EQUAL_INT(0, countOf(block, "\n#elif"));
  // The block records the strike and arms the skip on the very next check.
  TEST_ASSERT_EQUAL_INT(1, countOf(block, "s_firstCheckAfterRollback = true;"));
  TEST_ASSERT_EQUAL_INT(1, countOf(block, "fry_config::setOtaStrikes(pending.c_str(), strikes);"));
  TEST_ASSERT_EQUAL_INT(1, countOf(block, "fry::nextStrikeCount("));
  // Control: the block is inside init(), before the "flag cleared" line.
  const size_t initPos = src.find("\nvoid init() {");
  const size_t cleared = src.find("flag cleared", call);
  TEST_ASSERT_TRUE(initPos != std::string::npos && initPos < call);
  TEST_ASSERT_TRUE(cleared != std::string::npos && endifPos < cleared);
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_a_mislabelled_image_is_rejected);
  RUN_TEST(test_a_legitimate_update_is_not_a_mismatch);
  RUN_TEST(test_a_rollback_is_not_a_mismatch);
  RUN_TEST(test_a_planned_restart_is_not_a_mismatch);
  RUN_TEST(test_empty_and_null_never_reject);
  RUN_TEST(test_the_two_branches_never_both_strike_on_one_boot);
  RUN_TEST(test_three_mismatch_boots_end_in_a_permanent_skip);
  RUN_TEST(test_a_mismatch_strike_is_never_counted_for_a_planned_restart);
  RUN_TEST(test_a_different_manifest_version_recovers);
  RUN_TEST(test_a_rollback_still_strikes_exactly_once);
  RUN_TEST(test_the_guard_wiring_is_esp8266_only_and_strikes);
  return UNITY_END();
}
