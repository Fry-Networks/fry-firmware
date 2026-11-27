// OTA policy of the non-ESP boards (lib/fry_core/ota_board_policy.h): which manifest build applies and whether it fits.
#include <unity.h>

#include <cstring>

#include "ota_board_policy.h"

using namespace fry::boards;

void setUp() {}
void tearDown() {}

namespace {
const char kSha[] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

OtaInput base() {
  OtaInput in{};
  in.os = "rp2040";
  in.runningVersion = "0.4.31";
  in.manifestVersion = "0.4.32";
  in.channel = nullptr;
  in.buildPresent = true;
  in.url = "https://github.com/Fry-Networks/fry-firmware/releases/download/v0.4.32/fry-rp2040.bin";
  in.sha256 = kSha;
  in.imageBytes = 400000;
  in.freeSlotBytes = 900000;
  in.pendingVersion = nullptr;
  return in;
}
}  // namespace

void test_newer_prod_build_applies() { TEST_ASSERT_EQUAL(OtaDecision::Apply, decideOta(base())); }

void test_same_or_older_version_is_not_newer() {
  OtaInput in = base();
  in.manifestVersion = "0.4.31";
  TEST_ASSERT_EQUAL(OtaDecision::NotNewer, decideOta(in));
  in.manifestVersion = "0.4.30";
  TEST_ASSERT_EQUAL(OtaDecision::NotNewer, decideOta(in));
  in.manifestVersion = "0.4.32-rc.1";
  in.runningVersion = "0.4.32";
  TEST_ASSERT_EQUAL(OtaDecision::NotNewer, decideOta(in));
}

void test_missing_build_for_this_os_never_takes_another_chips_image() {
  OtaInput in = base();
  in.buildPresent = false;
  TEST_ASSERT_EQUAL(OtaDecision::NoBuild, decideOta(in));
}

void test_channel_must_be_prod() {
  OtaInput in = base();
  in.channel = "test";
  TEST_ASSERT_EQUAL(OtaDecision::WrongChannel, decideOta(in));
  in.channel = "prod";
  TEST_ASSERT_EQUAL(OtaDecision::Apply, decideOta(in));
  in.channel = "";
  TEST_ASSERT_EQUAL(OtaDecision::Apply, decideOta(in));
}

void test_url_must_be_https_and_sha_must_be_64_hex() {
  OtaInput in = base();
  in.url = "http://example.com/x.bin";
  TEST_ASSERT_EQUAL(OtaDecision::BadUrl, decideOta(in));
  in = base();
  in.url = nullptr;
  TEST_ASSERT_EQUAL(OtaDecision::BadUrl, decideOta(in));
  in = base();
  in.sha256 = "deadbeef";
  TEST_ASSERT_EQUAL(OtaDecision::BadSha, decideOta(in));
  in.sha256 = "zz23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  TEST_ASSERT_EQUAL(OtaDecision::BadSha, decideOta(in));
}

void test_image_must_fit_the_slot() {
  OtaInput in = base();
  in.imageBytes = 900001;
  TEST_ASSERT_EQUAL(OtaDecision::TooBigForSlot, decideOta(in));
  in.imageBytes = 900000;
  TEST_ASSERT_EQUAL(OtaDecision::Apply, decideOta(in));
  in.imageBytes = 0;  // unknown at manifest time: the download re-checks with Content-Length
  TEST_ASSERT_EQUAL(OtaDecision::Apply, decideOta(in));
}

void test_pending_foreign_version_blocks_a_new_check() {
  OtaInput in = base();
  in.pendingVersion = "0.4.30";  // an image we installed that is not the one running and was not rolled back
  TEST_ASSERT_EQUAL(OtaDecision::RejectedPending, decideOta(in));
  in.pendingVersion = "0.4.31";  // the running image is the pending one: still unconfirmed
  TEST_ASSERT_EQUAL(OtaDecision::RejectedPending, decideOta(in));
  in.pendingVersion = "";
  TEST_ASSERT_EQUAL(OtaDecision::Apply, decideOta(in));
}

void test_image_kind_per_os() {
  TEST_ASSERT_EQUAL(ImageKind::PicoBin, imageKindForOs("rp2040"));
  TEST_ASSERT_EQUAL(ImageKind::PicoBin, imageKindForOs("rp2350"));
  TEST_ASSERT_EQUAL(ImageKind::BkUf2, imageKindForOs("bk7231n"));
  TEST_ASSERT_EQUAL(ImageKind::None, imageKindForOs("esp32"));
}

void test_uf2_header_magic() {
  // UF2 block: magicStart0 "UF2\n" (0x0A324655) and magicStart1 0x9E5D5157, little endian.
  const uint8_t good[] = {0x55, 0x46, 0x32, 0x0A, 0x57, 0x51, 0x5D, 0x9E};
  const uint8_t bad[] = {0x55, 0x46, 0x32, 0x0B, 0x57, 0x51, 0x5D, 0x9E};
  TEST_ASSERT_TRUE(imageHeaderPlausible(ImageKind::BkUf2, good, sizeof(good)));
  TEST_ASSERT_FALSE(imageHeaderPlausible(ImageKind::BkUf2, bad, sizeof(bad)));
  TEST_ASSERT_FALSE(imageHeaderPlausible(ImageKind::BkUf2, good, 7));  // needs both magic words
}

void test_pico_header_rejects_blank_and_ascii_junk() {
  uint8_t blank[256];
  memset(blank, 0xFF, sizeof(blank));
  TEST_ASSERT_FALSE(imageHeaderPlausible(ImageKind::PicoBin, blank, sizeof(blank)));
  memset(blank, 0x00, sizeof(blank));
  TEST_ASSERT_FALSE(imageHeaderPlausible(ImageKind::PicoBin, blank, sizeof(blank)));
  const char html[] = "<!DOCTYPE html><html><body>404 Not Found</body></html>                      ";
  TEST_ASSERT_FALSE(imageHeaderPlausible(ImageKind::PicoBin, reinterpret_cast<const uint8_t*>(html), sizeof(html)));
  uint8_t code[256];
  for (int i = 0; i < 256; i++) code[i] = static_cast<uint8_t>(i * 7 + 3);
  TEST_ASSERT_TRUE(imageHeaderPlausible(ImageKind::PicoBin, code, sizeof(code)));
}

void test_boot_attempt_limit_policy() {
  // Single-slot boards: after the limit of unconfirmed boots there is nothing to roll back to, so the counter only reports.
  TEST_ASSERT_FALSE(bootLimitReached(0, 3));
  TEST_ASSERT_FALSE(bootLimitReached(2, 3));
  TEST_ASSERT_TRUE(bootLimitReached(3, 3));
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_newer_prod_build_applies);
  RUN_TEST(test_same_or_older_version_is_not_newer);
  RUN_TEST(test_missing_build_for_this_os_never_takes_another_chips_image);
  RUN_TEST(test_channel_must_be_prod);
  RUN_TEST(test_url_must_be_https_and_sha_must_be_64_hex);
  RUN_TEST(test_image_must_fit_the_slot);
  RUN_TEST(test_pending_foreign_version_blocks_a_new_check);
  RUN_TEST(test_image_kind_per_os);
  RUN_TEST(test_uf2_header_magic);
  RUN_TEST(test_pico_header_rejects_blank_and_ascii_junk);
  RUN_TEST(test_boot_attempt_limit_policy);
  return UNITY_END();
}
