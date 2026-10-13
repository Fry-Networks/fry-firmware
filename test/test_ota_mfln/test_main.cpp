// ESP8266 OTA from hardwareapi over a 512/512 TLS session. A relay board has 20-30 KB free and can
// never find the 36864-byte contiguous block the GitHub (non-MFLN) path demands; hardwareapi honours
// MFLN, so its OTA must neither use the big buffers nor apply that gate.
#include <unity.h>

#include <cstring>

#include "ota_mfln.h"

namespace {

constexpr uint32_t kBlock = 36864;  // HEAP_GATE_OTA_BLOCK
const char* kHwApi = "https://hardwareapi.frynetworks.com/ota/esp8266/manifest.json";
const char* kGhRel = "https://github.com/Fry-Networks/fry-firmware/releases/latest/download/manifest.json";
const char* kGhAsset = "https://release-assets.githubusercontent.com/github-production-release-asset/1/2?x=y";

void test_host_extraction() {
  char h[64];
  TEST_ASSERT_TRUE(fry::otaUrlHost(kHwApi, h, sizeof(h)));
  TEST_ASSERT_EQUAL_STRING("hardwareapi.frynetworks.com", h);
  TEST_ASSERT_TRUE(fry::otaUrlHost("https://HardwareAPI.FryNetworks.com:443/x", h, sizeof(h)));
  TEST_ASSERT_EQUAL_STRING("hardwareapi.frynetworks.com", h);
  TEST_ASSERT_TRUE(fry::otaUrlHost("http://10.0.0.5:8796/manifest.json", h, sizeof(h)));
  TEST_ASSERT_EQUAL_STRING("10.0.0.5", h);
  TEST_ASSERT_TRUE(fry::otaUrlHost("https://a.example?q=1", h, sizeof(h)));
  TEST_ASSERT_EQUAL_STRING("a.example", h);
}

void test_host_extraction_rejects_bad_urls() {
  char h[16];
  char big[64];
  TEST_ASSERT_FALSE(fry::otaUrlHost(nullptr, h, sizeof(h)));
  TEST_ASSERT_FALSE(fry::otaUrlHost("", h, sizeof(h)));
  TEST_ASSERT_FALSE(fry::otaUrlHost("https:///path", h, sizeof(h)));
  TEST_ASSERT_FALSE(fry::otaUrlHost("no-scheme.example/x", h, sizeof(h)));
  TEST_ASSERT_FALSE(fry::otaUrlHost("https://hardwareapi.frynetworks.com/x", h, sizeof(h)));  // too long
  TEST_ASSERT_FALSE(fry::otaUrlHost("https://hardwareapi.frynetworks.com@evil.example/x", big, sizeof(big)));
}

void test_only_listed_hosts_honour_mfln() {
  TEST_ASSERT_TRUE(fry::otaHostHonoursMfln("hardwareapi.frynetworks.com"));
  TEST_ASSERT_TRUE(fry::otaHostHonoursMfln("HARDWAREAPI.frynetworks.com"));
  TEST_ASSERT_FALSE(fry::otaHostHonoursMfln("github.com"));
  TEST_ASSERT_FALSE(fry::otaHostHonoursMfln("objects.githubusercontent.com"));
  TEST_ASSERT_FALSE(fry::otaHostHonoursMfln("release-assets.githubusercontent.com"));
  TEST_ASSERT_FALSE(fry::otaHostHonoursMfln("hardwareapi.frynetworks.com.evil.example"));
  TEST_ASSERT_FALSE(fry::otaHostHonoursMfln("evil-hardwareapi.frynetworks.com"));
  TEST_ASSERT_FALSE(fry::otaHostHonoursMfln("frynetworks.com"));
  TEST_ASSERT_FALSE(fry::otaHostHonoursMfln(""));
  TEST_ASSERT_FALSE(fry::otaHostHonoursMfln(nullptr));
}

void test_hardwareapi_plan_is_small_buffers_and_no_block_gate() {
  const fry::OtaTlsPlan p = fry::otaTlsPlan(kHwApi, kBlock);
  TEST_ASSERT_TRUE(p.https);
  TEST_ASSERT_TRUE(p.mfln);
  TEST_ASSERT_EQUAL_UINT16(512, p.rx);
  TEST_ASSERT_EQUAL_UINT16(512, p.tx);
  TEST_ASSERT_EQUAL_UINT32(0, p.minBlock);
}

void test_github_plan_keeps_the_big_buffers_and_block_gate() {
  const char* urls[] = {kGhRel, kGhAsset};
  for (const char* u : urls) {
    const fry::OtaTlsPlan p = fry::otaTlsPlan(u, kBlock);
    TEST_ASSERT_TRUE(p.https);
    TEST_ASSERT_FALSE(p.mfln);
    TEST_ASSERT_EQUAL_UINT16(16384, p.rx);
    TEST_ASSERT_EQUAL_UINT16(512, p.tx);
    TEST_ASSERT_EQUAL_UINT32(kBlock, p.minBlock);
  }
}

void test_plain_http_has_no_tls_buffers_or_block_gate() {
  const fry::OtaTlsPlan p = fry::otaTlsPlan("http://10.0.0.5:8796/manifest.json", kBlock);
  TEST_ASSERT_FALSE(p.https);
  TEST_ASSERT_FALSE(p.mfln);
  TEST_ASSERT_EQUAL_UINT16(0, p.rx);
  TEST_ASSERT_EQUAL_UINT32(0, p.minBlock);
}

void test_plain_http_to_a_listed_host_is_not_a_tls_plan() {
  const fry::OtaTlsPlan p = fry::otaTlsPlan("http://hardwareapi.frynetworks.com/x", kBlock);
  TEST_ASSERT_FALSE(p.https);
  TEST_ASSERT_FALSE(p.mfln);
}

void test_unparseable_url_takes_the_conservative_path() {
  const fry::OtaTlsPlan p = fry::otaTlsPlan("https://", kBlock);
  TEST_ASSERT_FALSE(p.mfln);
  TEST_ASSERT_EQUAL_UINT32(kBlock, p.minBlock);
}

void test_staged_image_cleared_unless_fully_applied() {
  TEST_ASSERT_FALSE(fry::otaMustClearStaged(1000, 1000, true, true));
  TEST_ASSERT_TRUE(fry::otaMustClearStaged(1000, 1000, false, true));   // sha mismatch, complete
  TEST_ASSERT_TRUE(fry::otaMustClearStaged(1000, 1000, true, false));   // Update.end(true) failed
  TEST_ASSERT_TRUE(fry::otaMustClearStaged(900, 1000, true, true));     // short
  TEST_ASSERT_TRUE(fry::otaMustClearStaged(512, 1000, false, false));   // write error
  TEST_ASSERT_TRUE(fry::otaMustClearStaged(0, 1000, false, false));
}

void test_every_failure_skips_to_the_next_scheduled_check() {
  const fry::OtaFailKind kinds[] = {fry::OtaFailKind::ConnectOrHandshake, fry::OtaFailKind::HttpError,
                                    fry::OtaFailKind::ManifestParse, fry::OtaFailKind::GateFailed};
  for (fry::OtaFailKind k : kinds)
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(fry::OtaFailAction::SkipToNextCheck),
                            static_cast<uint8_t>(fry::otaFailureAction(k)));
}

}  // namespace

int main() {
  UNITY_BEGIN();
  RUN_TEST(test_host_extraction);
  RUN_TEST(test_host_extraction_rejects_bad_urls);
  RUN_TEST(test_only_listed_hosts_honour_mfln);
  RUN_TEST(test_hardwareapi_plan_is_small_buffers_and_no_block_gate);
  RUN_TEST(test_github_plan_keeps_the_big_buffers_and_block_gate);
  RUN_TEST(test_plain_http_has_no_tls_buffers_or_block_gate);
  RUN_TEST(test_plain_http_to_a_listed_host_is_not_a_tls_plan);
  RUN_TEST(test_unparseable_url_takes_the_conservative_path);
  RUN_TEST(test_staged_image_cleared_unless_fully_applied);
  RUN_TEST(test_every_failure_skips_to_the_next_scheduled_check);
  return UNITY_END();
}
