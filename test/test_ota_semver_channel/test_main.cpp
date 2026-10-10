// OTA version precedence, channel and bad-version selection (lib/fry_core/semver.* and
// lib/fry_core/ota_health.*; PROTOCOL.md section 11.5).
//
// compareSemver ignores pre-release suffixes, so 0.4.1-rc.1 and 0.4.1 compare equal: a board on the
// release candidate would never take the final release, and a board on 0.4.0 treats an rc as the
// release itself. It stays as it is (a pinned test relies on it); OTA selection moves to
// SemVer 2.0 section 11 precedence.
#include <unity.h>

#include "ota_health.h"
#include "semver.h"

using fry::OtaDecision;

namespace {

void test_semver_spec_example_chain_is_strictly_increasing() {
  // The ordering example from SemVer 2.0.0 section 11, verbatim.
  const char* chain[] = {"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
                         "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"};
  const int n = sizeof(chain) / sizeof(chain[0]);
  for (int i = 0; i < n; i++) {
    for (int j = 0; j < n; j++) {
      const int want = i < j ? -1 : (i > j ? 1 : 0);
      TEST_ASSERT_EQUAL_INT_MESSAGE(want, fry::compareSemverPrecedence(chain[i], chain[j]), chain[i]);
    }
  }
}

void test_release_candidate_sits_between_releases() {
  TEST_ASSERT_TRUE(fry::isNewerVersionOta("0.4.1", "0.4.1-rc.1"));
  TEST_ASSERT_FALSE(fry::isNewerVersionOta("0.4.1-rc.1", "0.4.1"));
  TEST_ASSERT_TRUE(fry::isNewerVersionOta("0.4.1-rc.1", "0.4.0"));
  TEST_ASSERT_TRUE(fry::isNewerVersionOta("0.4.1-rc.2", "0.4.1-rc.1"));
  TEST_ASSERT_TRUE(fry::isNewerVersionOta("0.4.1-rc.10", "0.4.1-rc.9"));  // numeric, not text
}

void test_core_ordering_is_numeric_and_forward_only() {
  TEST_ASSERT_EQUAL_INT(-1, fry::compareSemverPrecedence("0.9.0", "0.10.0"));
  TEST_ASSERT_EQUAL_INT(1, fry::compareSemverPrecedence("1.0.0", "0.99.99"));
  TEST_ASSERT_FALSE(fry::isNewerVersionOta("0.3.1", "0.4.0"));  // never downgrade
  TEST_ASSERT_FALSE(fry::isNewerVersionOta("0.4.0", "0.4.0"));
  TEST_ASSERT_TRUE(fry::isNewerVersionOta("0.4.0", "0.3.3"));
}

void test_build_metadata_and_missing_components() {
  TEST_ASSERT_EQUAL_INT(0, fry::compareSemverPrecedence("0.4.1+ci.7", "0.4.1"));
  TEST_ASSERT_EQUAL_INT(0, fry::compareSemverPrecedence("0.4.1-rc.1+x", "0.4.1-rc.1"));
  TEST_ASSERT_EQUAL_INT(0, fry::compareSemverPrecedence("0.4", "0.4.0"));
  TEST_ASSERT_EQUAL_INT(0, fry::compareSemverPrecedence(nullptr, "0.0.0"));
  TEST_ASSERT_EQUAL_INT(-1, fry::compareSemverPrecedence("", "0.0.1"));
  // Numeric identifiers sort below alphanumeric ones.
  TEST_ASSERT_EQUAL_INT(-1, fry::compareSemverPrecedence("1.0.0-1", "1.0.0-a"));
}

void test_existing_compare_is_unchanged() {
  TEST_ASSERT_EQUAL_INT(0, fry::compareSemver("0.4.1-rc.1", "0.4.1"));
}

void test_channel_missing_means_prod() {
  TEST_ASSERT_TRUE(fry::otaChannelAccepted(nullptr, "prod"));
  TEST_ASSERT_TRUE(fry::otaChannelAccepted("", "prod"));
  TEST_ASSERT_TRUE(fry::otaChannelAccepted("prod", "prod"));
  TEST_ASSERT_FALSE(fry::otaChannelAccepted("test", "prod"));
  TEST_ASSERT_TRUE(fry::otaChannelAccepted("test", "test"));
  TEST_ASSERT_FALSE(fry::otaChannelAccepted(nullptr, "test"));
  TEST_ASSERT_FALSE(fry::otaChannelAccepted("prod", "test"));
  TEST_ASSERT_FALSE(fry::otaChannelAccepted("Test", "test"));  // exact
}

void test_bad_version_is_skipped_exactly() {
  TEST_ASSERT_TRUE(fry::isSkippedBadVersion("0.4.1", "0.4.1"));
  TEST_ASSERT_FALSE(fry::isSkippedBadVersion("0.4.2", "0.4.1"));
  TEST_ASSERT_FALSE(fry::isSkippedBadVersion("0.4.1", ""));
  TEST_ASSERT_FALSE(fry::isSkippedBadVersion("0.4.1", nullptr));
  TEST_ASSERT_FALSE(fry::isSkippedBadVersion("", ""));
}

const char kUrl[] = "https://example.invalid/firmware-esp32.bin";
const char kSha[] = "0000000000000000000000000000000000000000000000000000000000000000";

void test_update_decision_order() {
  TEST_ASSERT_EQUAL((int)OtaDecision::Update,
                    (int)fry::decideOtaUpdate("prod", "prod", "0.4.1", "0.4.0", "", kUrl, kSha));
  TEST_ASSERT_EQUAL((int)OtaDecision::Update,
                    (int)fry::decideOtaUpdate(nullptr, "prod", "0.4.1", "0.4.0", nullptr, kUrl, kSha));
  TEST_ASSERT_EQUAL((int)OtaDecision::WrongChannel,
                    (int)fry::decideOtaUpdate("test", "prod", "0.4.1", "0.4.0", "", kUrl, kSha));
  TEST_ASSERT_EQUAL((int)OtaDecision::NotNewer,
                    (int)fry::decideOtaUpdate("prod", "prod", "0.4.0", "0.4.0", "", kUrl, kSha));
  TEST_ASSERT_EQUAL((int)OtaDecision::NotNewer,
                    (int)fry::decideOtaUpdate("prod", "prod", "", "0.4.0", "", kUrl, kSha));
  TEST_ASSERT_EQUAL((int)OtaDecision::BadVersion,
                    (int)fry::decideOtaUpdate("prod", "prod", "0.4.1", "0.4.0", "0.4.1", kUrl, kSha));
  // A newer release than the one that rolled back is taken again.
  TEST_ASSERT_EQUAL((int)OtaDecision::Update,
                    (int)fry::decideOtaUpdate("prod", "prod", "0.4.2", "0.4.0", "0.4.1", kUrl, kSha));
  // Chip excluded from the manifest (C-5): no url or no sha means no update, never another build.
  TEST_ASSERT_EQUAL((int)OtaDecision::NoBuild,
                    (int)fry::decideOtaUpdate("prod", "prod", "0.4.1", "0.4.0", "", "", ""));
  TEST_ASSERT_EQUAL((int)OtaDecision::NoBuild,
                    (int)fry::decideOtaUpdate("prod", "prod", "0.4.1", "0.4.0", "", kUrl, nullptr));
}

void test_decision_names_keep_the_log_grammar() {
  TEST_ASSERT_EQUAL_STRING("update", fry::otaDecisionName(OtaDecision::Update));
  TEST_ASSERT_EQUAL_STRING("not_newer", fry::otaDecisionName(OtaDecision::NotNewer));
  TEST_ASSERT_EQUAL_STRING("wrong_channel", fry::otaDecisionName(OtaDecision::WrongChannel));
  TEST_ASSERT_EQUAL_STRING("bad_version", fry::otaDecisionName(OtaDecision::BadVersion));
  TEST_ASSERT_EQUAL_STRING("no_build", fry::otaDecisionName(OtaDecision::NoBuild));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_semver_spec_example_chain_is_strictly_increasing);
  RUN_TEST(test_release_candidate_sits_between_releases);
  RUN_TEST(test_core_ordering_is_numeric_and_forward_only);
  RUN_TEST(test_build_metadata_and_missing_components);
  RUN_TEST(test_existing_compare_is_unchanged);
  RUN_TEST(test_channel_missing_means_prod);
  RUN_TEST(test_bad_version_is_skipped_exactly);
  RUN_TEST(test_update_decision_order);
  RUN_TEST(test_decision_names_keep_the_log_grammar);
  return UNITY_END();
}
