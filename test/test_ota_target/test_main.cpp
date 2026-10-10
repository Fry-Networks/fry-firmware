// B4 (IV5): an ESP8266 has one app slot and no rollback, so the board must refuse any OTA image
// not built for its board id and flash layout - before writing a byte. Also pins the per-build
// version rule that stops a 0.3.4 board re-flashing itself every 6 h from a manifest whose top
// level still says 0.4.1 (the version ESP32/C3 run).
#include <unity.h>

#include "ota_target.h"
#include "semver.h"

namespace {

constexpr uint32_t k4M = 4194304;

fry::OtaEntryTarget entry(const char* board, uint32_t flash) {
  fry::OtaEntryTarget e;
  e.boardId = board;
  e.flashSize = flash;
  return e;
}

fry::OtaDeviceFlash bench() {  // the IV5 bench board: ESP8266EX, 4 MB (mfr 1c dev 3016)
  fry::OtaDeviceFlash d;
  d.boardId = "esp8266-4m1m";
  d.flashReal = k4M;
  d.flashHeader = k4M;
  d.isEsp8285 = false;
  return d;
}

void test_matching_board_and_layout_is_accepted() {
  TEST_ASSERT_EQUAL(fry::OtaTargetVerdict::Ok, fry::checkOtaTarget(entry("esp8266-4m1m", k4M), bench()));
}

void test_bigger_real_flash_with_the_same_layout_is_accepted() {
  fry::OtaDeviceFlash d = bench();
  d.flashReal = 4 * k4M;  // a 16 MB module still running the 4 MB-header image
  TEST_ASSERT_EQUAL(fry::OtaTargetVerdict::Ok, fry::checkOtaTarget(entry("esp8266-4m1m", k4M), d));
}

void test_missing_fields_fail_closed() {
  TEST_ASSERT_EQUAL(fry::OtaTargetVerdict::MissingBoardId, fry::checkOtaTarget(entry(nullptr, k4M), bench()));
  TEST_ASSERT_EQUAL(fry::OtaTargetVerdict::MissingBoardId, fry::checkOtaTarget(entry("", k4M), bench()));
  TEST_ASSERT_EQUAL(fry::OtaTargetVerdict::MissingFlashSize, fry::checkOtaTarget(entry("esp8266-4m1m", 0), bench()));
}

void test_other_board_is_refused() {
  TEST_ASSERT_EQUAL(fry::OtaTargetVerdict::BoardMismatch, fry::checkOtaTarget(entry("esp8266-2m", k4M), bench()));
  TEST_ASSERT_EQUAL(fry::OtaTargetVerdict::BoardMismatch, fry::checkOtaTarget(entry("esp32", k4M), bench()));
}

void test_image_for_more_flash_than_the_chip_has_is_refused() {
  TEST_ASSERT_EQUAL(fry::OtaTargetVerdict::FlashTooSmall, fry::checkOtaTarget(entry("esp8266-4m1m", 2 * k4M), bench()));
}

void test_other_layout_is_refused() {
  TEST_ASSERT_EQUAL(fry::OtaTargetVerdict::LayoutMismatch, fry::checkOtaTarget(entry("esp8266-4m1m", k4M / 2), bench()));
  fry::OtaDeviceFlash d = bench();
  d.flashHeader = k4M / 4;  // running a 1 MB-layout image on a 4 MB chip
  TEST_ASSERT_EQUAL(fry::OtaTargetVerdict::LayoutMismatch, fry::checkOtaTarget(entry("esp8266-4m1m", k4M), d));
}

void test_esp8285_is_refused() {
  fry::OtaDeviceFlash d = bench();
  d.isEsp8285 = true;
  TEST_ASSERT_EQUAL(fry::OtaTargetVerdict::Esp8285, fry::checkOtaTarget(entry("esp8266-4m1m", k4M), d));
}

void test_content_length_must_match_the_declared_size() {
  TEST_ASSERT_EQUAL(fry::OtaTargetVerdict::Ok, fry::checkOtaSize(507200, 507200));
  TEST_ASSERT_EQUAL(fry::OtaTargetVerdict::SizeMismatch, fry::checkOtaSize(507200, 507201));
  TEST_ASSERT_EQUAL(fry::OtaTargetVerdict::SizeMismatch, fry::checkOtaSize(507200, -1));
  TEST_ASSERT_EQUAL(fry::OtaTargetVerdict::SizeMismatch, fry::checkOtaSize(0, 507200));
}

void test_reason_tokens() {
  TEST_ASSERT_EQUAL_STRING("ok", fry::otaTargetReason(fry::OtaTargetVerdict::Ok));
  TEST_ASSERT_EQUAL_STRING("board_id_missing", fry::otaTargetReason(fry::OtaTargetVerdict::MissingBoardId));
  TEST_ASSERT_EQUAL_STRING("board_id", fry::otaTargetReason(fry::OtaTargetVerdict::BoardMismatch));
  TEST_ASSERT_EQUAL_STRING("flash_size_missing", fry::otaTargetReason(fry::OtaTargetVerdict::MissingFlashSize));
  TEST_ASSERT_EQUAL_STRING("flash_too_small", fry::otaTargetReason(fry::OtaTargetVerdict::FlashTooSmall));
  TEST_ASSERT_EQUAL_STRING("flash_layout", fry::otaTargetReason(fry::OtaTargetVerdict::LayoutMismatch));
  TEST_ASSERT_EQUAL_STRING("esp8285", fry::otaTargetReason(fry::OtaTargetVerdict::Esp8285));
  TEST_ASSERT_EQUAL_STRING("size", fry::otaTargetReason(fry::OtaTargetVerdict::SizeMismatch));
}

void test_per_build_version_wins_over_top_level() {
  TEST_ASSERT_EQUAL_STRING("0.3.4", fry::selectOtaVersion("0.3.4", "0.4.1"));
  TEST_ASSERT_EQUAL_STRING("0.4.1", fry::selectOtaVersion(nullptr, "0.4.1"));
  TEST_ASSERT_EQUAL_STRING("0.4.1", fry::selectOtaVersion("", "0.4.1"));
}

void test_no_reflash_loop_on_the_iv5_manifest() {
  // The IV5 manifest: top level 0.4.1 (ESP32/C3), builds.esp8266.version 0.3.4.
  // 0.3.3 reads only the top level, so it updates once...
  TEST_ASSERT_TRUE(fry::isNewerVersion("0.4.1", "0.3.3"));
  // ...and 0.3.4, reading its own entry, then stays put instead of re-applying every 6 h.
  TEST_ASSERT_FALSE(fry::isNewerVersion(fry::selectOtaVersion("0.3.4", "0.4.1"), "0.3.4"));
  // A later ESP8266 entry still updates it.
  TEST_ASSERT_TRUE(fry::isNewerVersion(fry::selectOtaVersion("0.3.5", "0.4.1"), "0.3.4"));
}

// ── The pre-download decision, in order (T2 F9) ──────────────────────────────────────────────

fry::OtaManifestEntry iv5Entry() {
  fry::OtaManifestEntry m;
  m.topVersion = "0.4.1";
  m.buildVersion = "0.3.4";
  m.url = "https://example.invalid/fw.bin";
  m.sha256 = "aa";
  m.target = entry("esp8266-4m1m", k4M);
  return m;
}

void test_decide_same_version_is_none() {
  fry::OtaDecision d = fry::decideOtaApply(iv5Entry(), bench(), "0.3.4");
  TEST_ASSERT_EQUAL(fry::OtaAction::None, d.action);
  TEST_ASSERT_EQUAL_STRING("0.3.4", d.version);
}

void test_decide_newer_matching_entry_updates() {
  fry::OtaManifestEntry m = iv5Entry();
  m.buildVersion = "0.3.5-test";
  fry::OtaDecision d = fry::decideOtaApply(m, bench(), "0.3.4");
  TEST_ASSERT_EQUAL(fry::OtaAction::Update, d.action);
  TEST_ASSERT_EQUAL_STRING("0.3.5-test", d.version);
}

void test_decide_refuses_before_any_download() {
  fry::OtaManifestEntry m = iv5Entry();
  m.buildVersion = "0.3.5";
  m.target.boardId = "esp8266-2m";
  fry::OtaDecision d = fry::decideOtaApply(m, bench(), "0.3.4");
  TEST_ASSERT_EQUAL(fry::OtaAction::Refuse, d.action);
  TEST_ASSERT_EQUAL(fry::OtaTargetVerdict::BoardMismatch, d.verdict);
  m.target = entry("esp8266-4m1m", 0);  // fail closed on a missing field too
  TEST_ASSERT_EQUAL(fry::OtaAction::Refuse, fry::decideOtaApply(m, bench(), "0.3.4").action);
}

void test_decide_not_newer_never_refuses() {
  // An entry for some other board that is not newer is simply not an update: no refusal spam.
  fry::OtaManifestEntry m = iv5Entry();
  m.target.boardId = "esp8266-2m";
  TEST_ASSERT_EQUAL(fry::OtaAction::None, fry::decideOtaApply(m, bench(), "0.3.4").action);
}

void test_decide_needs_url_and_sha() {
  fry::OtaManifestEntry m = iv5Entry();
  m.buildVersion = "0.3.5";
  m.url = "";
  TEST_ASSERT_EQUAL(fry::OtaAction::None, fry::decideOtaApply(m, bench(), "0.3.4").action);
  m = iv5Entry();
  m.buildVersion = "0.3.5";
  m.sha256 = nullptr;
  TEST_ASSERT_EQUAL(fry::OtaAction::None, fry::decideOtaApply(m, bench(), "0.3.4").action);
}

void test_decide_falls_back_to_top_level_version() {
  fry::OtaManifestEntry m = iv5Entry();
  m.buildVersion = nullptr;  // a manifest written before IV5
  fry::OtaDecision d = fry::decideOtaApply(m, bench(), "0.3.4");
  TEST_ASSERT_EQUAL(fry::OtaAction::Update, d.action);
  TEST_ASSERT_EQUAL_STRING("0.4.1", d.version);
}

}  // namespace

void setUp() {}

void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_matching_board_and_layout_is_accepted);
  RUN_TEST(test_bigger_real_flash_with_the_same_layout_is_accepted);
  RUN_TEST(test_missing_fields_fail_closed);
  RUN_TEST(test_other_board_is_refused);
  RUN_TEST(test_image_for_more_flash_than_the_chip_has_is_refused);
  RUN_TEST(test_other_layout_is_refused);
  RUN_TEST(test_esp8285_is_refused);
  RUN_TEST(test_content_length_must_match_the_declared_size);
  RUN_TEST(test_reason_tokens);
  RUN_TEST(test_per_build_version_wins_over_top_level);
  RUN_TEST(test_no_reflash_loop_on_the_iv5_manifest);
  RUN_TEST(test_decide_same_version_is_none);
  RUN_TEST(test_decide_newer_matching_entry_updates);
  RUN_TEST(test_decide_refuses_before_any_download);
  RUN_TEST(test_decide_not_newer_never_refuses);
  RUN_TEST(test_decide_needs_url_and_sha);
  RUN_TEST(test_decide_falls_back_to_top_level_version);
  return UNITY_END();
}
