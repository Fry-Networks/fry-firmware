// #34 manifest-directed rollback (lib/fry_core/ota_health.h decideOtaRollback, ota_rollback_json.h).
// A rollback is honoured ONLY for an explicit builds.<env>.rollback that lists the running version,
// names a strictly older plain-semver target, and carries a url and a 64-hex sha256. No rollback
// object: nothing changes (decideOtaUpdate is untouched).
#include <unity.h>

#include <ArduinoJson.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "ota_health.h"
#include "ota_rollback_json.h"

using fry::OtaDecision;

namespace {

const char kUrl[] = "https://github.com/Fry-Networks/fry-firmware/releases/download/fw-v0.4.24/firmware-esp32.bin";
const char kSha[] = "2222222222222222222222222222222222222222222222222222222222222222";

OtaDecision rb(const char* running, const char* target, bool listed = true, const char* badver = "",
               uint8_t badn = 0, bool first = false, const char* ch = "prod", const char* url = kUrl,
               const char* sha = kSha) {
  return fry::decideOtaRollback(ch, "prod", running, listed, target, badver, badn, first, url, sha);
}

// Parses `json` and reads builds.esp32.rollback for `running`.
bool read(const char* json, const char* running, fry::RollbackEntry* e) {
  static JsonDocument doc;
  doc.clear();
  TEST_ASSERT_TRUE(deserializeJson(doc, json) == DeserializationError::Ok);
  return fry::readRollbackEntry(doc["builds"]["esp32"]["rollback"], running, e);
}

void test_appended_enum_values_do_not_renumber() {
  TEST_ASSERT_EQUAL_INT(0, (int)OtaDecision::Update);
  TEST_ASSERT_EQUAL_INT(5, (int)OtaDecision::NotInRollout);
  TEST_ASSERT_EQUAL_INT(6, (int)OtaDecision::Rollback);
  TEST_ASSERT_EQUAL_INT(7, (int)OtaDecision::RollbackRefused);
  TEST_ASSERT_EQUAL_STRING("rollback", fry::otaDecisionName(OtaDecision::Rollback));
  TEST_ASSERT_EQUAL_STRING("rollback_refused", fry::otaDecisionName(OtaDecision::RollbackRefused));
}

void test_eligible_when_listed_older_and_complete() {
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::Rollback, (int)rb("0.4.25", "0.4.24"));
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::Rollback, (int)rb("0.4.25", "0.4.25-rc.1"));  // pre-release < release
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::Rollback, (int)rb("1.0.0", "0.9.9"));
}

void test_refused_when_running_not_listed() {
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::RollbackRefused, (int)rb("0.4.25", "0.4.24", false));
}

void test_refused_unless_strictly_older_plain_semver() {
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::RollbackRefused, (int)rb("0.4.25", "0.4.25"));  // same
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::RollbackRefused, (int)rb("0.4.25", "0.4.26"));  // newer: not a rollback
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::RollbackRefused, (int)rb("0.4.25", "garbage"));  // would read as 0.0.0
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::RollbackRefused, (int)rb("0.4.25", ""));
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::RollbackRefused, (int)rb("0.4.25", "0.0.0"));  // the fw-hold value
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::RollbackRefused, (int)rb("0.4.25", "0.4"));
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::RollbackRefused, (int)rb("0.4.25", "0.4.x"));
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::RollbackRefused, (int)rb("0.4.25", nullptr));
}

void test_no_cycle_a_chain_only_descends() {
  // 0.4.25 -> 0.4.24 is allowed; from 0.4.24 the same manifest cannot send the board back up or sideways.
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::Rollback, (int)rb("0.4.25", "0.4.24"));
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::RollbackRefused, (int)rb("0.4.24", "0.4.25"));
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::RollbackRefused, (int)rb("0.4.24", "0.4.24"));
}

void test_channel_gate() {
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::WrongChannel,
                        (int)rb("0.4.25", "0.4.24", true, "", 0, false, "test"));
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::Rollback, (int)rb("0.4.25", "0.4.24", true, "", 0, false, ""));  // "" = prod
}

void test_strike_skipped_target_is_refused() {
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::BadVersion, (int)rb("0.4.25", "0.4.24", true, "0.4.24", 3));
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::BadVersion, (int)rb("0.4.25", "0.4.24", true, "0.4.24", 1, true));
  // fewer than 3 strikes, not the first check after a rollback: retried like any update
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::Rollback, (int)rb("0.4.25", "0.4.24", true, "0.4.24", 1, false));
  // strikes held for another version do not matter
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::Rollback, (int)rb("0.4.25", "0.4.24", true, "0.4.20", 3));
}

void test_url_and_sha256_are_mandatory() {
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::NoBuild, (int)rb("0.4.25", "0.4.24", true, "", 0, false, "prod", "", kSha));
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::NoBuild,
                        (int)rb("0.4.25", "0.4.24", true, "", 0, false, "prod", nullptr, kSha));
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::NoBuild, (int)rb("0.4.25", "0.4.24", true, "", 0, false, "prod", kUrl, ""));
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::NoBuild,
                        (int)rb("0.4.25", "0.4.24", true, "", 0, false, "prod", kUrl, nullptr));
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::NoBuild,
                        (int)rb("0.4.25", "0.4.24", true, "", 0, false, "prod", kUrl, "abc123"));  // not 64 hex
  TEST_ASSERT_EQUAL_INT(
      (int)OtaDecision::NoBuild,
      (int)rb("0.4.25", "0.4.24", true, "", 0, false, "prod", kUrl,
              "zz22222222222222222222222222222222222222222222222222222222222222"));  // 64 chars, not hex
}

void test_forward_decision_is_unchanged_by_a_rollback_target() {
  // decideOtaUpdate never downgrades, with or without a rollback object around: still NotNewer.
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::NotNewer,
                        (int)fry::decideOtaUpdate("prod", "prod", "0.4.24", "0.4.25", "", kUrl, kSha));
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::Update,
                        (int)fry::decideOtaUpdate("prod", "prod", "0.4.26", "0.4.25", "", kUrl, kSha));
}

void test_json_well_formed_entry() {
  fry::RollbackEntry e;
  const char* good =
      R"({"builds":{"esp32":{"url":"u","sha256":"s","rollback":{"version":"0.4.24","url":"https://x/y.bin","sha256":"aa","from":["0.4.26","0.4.25"],"size":123,"note":"ok"}}}})";
  TEST_ASSERT_TRUE(read(good, "0.4.25", &e));
  TEST_ASSERT_EQUAL_STRING("0.4.24", e.version);
  TEST_ASSERT_EQUAL_STRING("https://x/y.bin", e.url);
  TEST_ASSERT_EQUAL_STRING("aa", e.sha256);
  TEST_ASSERT_TRUE(read(good, "0.4.26", &e));
  TEST_ASSERT_FALSE_MESSAGE(read(good, "0.4.24", &e), "running version not in from");
  TEST_ASSERT_FALSE(read(good, "", &e));
}

void test_json_malformed_or_absent_degrades_to_no_rollback() {
  fry::RollbackEntry e;
  const char* cases[] = {
      R"({"builds":{"esp32":{"url":"u","sha256":"s"}}})",                                          // absent
      R"({"builds":{"esp32":{"rollback":null}}})",                                                  // null
      R"({"builds":{"esp32":{"rollback":"0.4.24"}}})",                                              // not an object
      R"({"builds":{"esp32":{"rollback":[]}}})",                                                    // array
      R"({"builds":{"esp32":{"rollback":{"version":"0.4.24","url":"u","sha256":"s"}}}})",           // no from
      R"({"builds":{"esp32":{"rollback":{"version":"0.4.24","url":"u","sha256":"s","from":"0.4.25"}}}})",  // from string
      R"({"builds":{"esp32":{"rollback":{"version":"0.4.24","url":"u","sha256":"s","from":[]}}}})",         // empty from
      R"({"builds":{"esp32":{"rollback":{"version":"0.4.24","url":"u","sha256":"s","from":["0.4.25",7]}}}})",  // mixed
      R"({"builds":{"esp32":{"rollback":{"version":"0.4.24","url":"u","from":["0.4.25"]}}}})",      // no sha256
      R"({"builds":{"esp32":{"rollback":{"version":"0.4.24","sha256":"s","from":["0.4.25"]}}}})",   // no url
      R"({"builds":{"esp32":{"rollback":{"url":"u","sha256":"s","from":["0.4.25"]}}}})",            // no version
      R"({"builds":{"esp32":{"rollback":{"version":"","url":"u","sha256":"s","from":["0.4.25"]}}}})",  // empty version
      R"({"builds":{"esp32":{"rollback":{"version":24,"url":"u","sha256":"s","from":["0.4.25"]}}}})",  // numeric version
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    char msg[40];
    snprintf(msg, sizeof(msg), "case %u", (unsigned)i);
    TEST_ASSERT_FALSE_MESSAGE(read(cases[i], "0.4.25", &e), msg);
  }
  // oversize from (17 entries) degrades to no rollback, 16 is accepted
  std::string big = R"({"builds":{"esp32":{"rollback":{"version":"0.4.24","url":"u","sha256":"s","from":[)";
  for (int i = 0; i < 17; i++) big += std::string(i ? "," : "") + "\"0.4." + std::to_string(30 + i) + "\"";
  big += "]}}}}";
  TEST_ASSERT_FALSE(read(big.c_str(), "0.4.30", &e));
  std::string ok = R"({"builds":{"esp32":{"rollback":{"version":"0.4.24","url":"u","sha256":"s","from":[)";
  for (int i = 0; i < 16; i++) ok += std::string(i ? "," : "") + "\"0.4." + std::to_string(30 + i) + "\"";
  ok += "]}}}}";
  TEST_ASSERT_TRUE(read(ok.c_str(), "0.4.30", &e));
}

// The device's own record after a directed rollback is (badver = the version it left, 3 strikes). The
// strike rules that exist today then keep a manifest that still names that version as latest from
// pulling the board forward, and a manifest naming a different version clears the record as before.
void test_strike_interplay_after_a_directed_rollback() {
  const char* bad = "0.4.25";
  const uint8_t n = fry::kOtaPermanentStrikes;
  // now running 0.4.24; manifest still says latest=0.4.25
  TEST_ASSERT_FALSE(fry::strikesReset("0.4.25", bad));
  TEST_ASSERT_TRUE(fry::skipBadVersion("0.4.25", bad, n, false));
  TEST_ASSERT_EQUAL_INT((int)OtaDecision::BadVersion,
                        (int)fry::decideOtaUpdate("prod", "prod", "0.4.25", "0.4.24", bad, kUrl, kSha));
  // a manifest naming another version clears it (unchanged behaviour)
  TEST_ASSERT_TRUE(fry::strikesReset("0.4.26", bad));
}

// ota_client.cpp needs the Arduino core: pin the wiring as source text, like test_ota_stack.
bool loadSource(std::string& out) {
  const std::string self = __FILE__;
  const std::string tail = "test/test_ota_rollback_manifest/test_main.cpp";
  std::vector<std::string> prefixes;
  if (self.size() >= tail.size() && self.compare(self.size() - tail.size(), tail.size(), tail) == 0)
    prefixes.push_back(self.substr(0, self.size() - tail.size()));
  const char* ups[] = {"", "../", "../../", "../../../", "../../../../"};
  for (const char* u : ups) prefixes.push_back(u);
  for (const std::string& p : prefixes) {
    std::ifstream f(p + "src/core/ota_client.cpp", std::ios::binary);
    if (f) {
      std::stringstream ss;
      ss << f.rdbuf();
      out = ss.str();
      return true;
    }
  }
  return false;
}

void test_wiring_in_evaluateManifest() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource(src), "cannot read src/core/ota_client.cpp");
  const size_t a = src.find("static bool evaluateManifest(const String& body, OtaPlan& plan) {");
  TEST_ASSERT_TRUE(a != std::string::npos);
  const size_t dec = src.find("fry::decideOtaUpdate(", a);
  const size_t gate = src.find("decision == fry::OtaDecision::NotNewer", dec);
  const size_t read = src.find("fry::readRollbackEntry(build[\"rollback\"], FRY_FIRMWARE_VERSION", gate);
  const size_t decide = src.find("fry::decideOtaRollback(", read);
  const size_t strikes = src.find("fry_config::setOtaStrikes(FRY_FIRMWARE_VERSION, fry::kOtaPermanentStrikes)", decide);
  const size_t dl = src.find("return downloadAndApply(url, sha, latest);", strikes);
  const size_t reset = src.rfind("fry_config::setOtaStrikes(\"\", 0);", dec);
  TEST_ASSERT_TRUE_MESSAGE(reset != std::string::npos && reset < dec, "strikesReset block precedes the decision");
  TEST_ASSERT_TRUE_MESSAGE(dec != std::string::npos && gate != std::string::npos && read != std::string::npos &&
                               decide != std::string::npos && strikes != std::string::npos && dl != std::string::npos,
                           "update decision, NotNewer gate, rollback read, rollback decision, strikes, download in order");
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_appended_enum_values_do_not_renumber);
  RUN_TEST(test_eligible_when_listed_older_and_complete);
  RUN_TEST(test_refused_when_running_not_listed);
  RUN_TEST(test_refused_unless_strictly_older_plain_semver);
  RUN_TEST(test_no_cycle_a_chain_only_descends);
  RUN_TEST(test_channel_gate);
  RUN_TEST(test_strike_skipped_target_is_refused);
  RUN_TEST(test_url_and_sha256_are_mandatory);
  RUN_TEST(test_forward_decision_is_unchanged_by_a_rollback_target);
  RUN_TEST(test_json_well_formed_entry);
  RUN_TEST(test_json_malformed_or_absent_degrades_to_no_rollback);
  RUN_TEST(test_strike_interplay_after_a_directed_rollback);
  RUN_TEST(test_wiring_in_evaluateManifest);
  return UNITY_END();
}
