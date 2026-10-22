// The OTA manifest check must not take a 16 KB TLS receive buffer when its replies are small.
//
// Measured 2026-10-22 (bench sweep "C", lines lo/c1-c9-*.lines.txt): the 3-hop GitHub manifest GET at forced 16384/512
// needs a post-constructor largest free block in (25992, 27992] and a lower heap does not fail cleanly - it crashes
// the board (reset reason 4 = OOM panic in BearSSL's throwing make_shared, reason 2 = memcpy to NULL). One session is
// 21080 B: 3774 B of contexts + 16709 B receive buffer + 597 B send buffer.
//
// Host probe of the same hosts (tools-side c1/tools/mfln_probe.py, ClientHello with SNI and MFLN 512 like BearSSL's):
//   github.com                              honours MFLN 512, Certificate (2730 B) arrives as 512 B records
//   hardwareapi.frynetworks.com             honours MFLN 512 (control)
//   release-assets.githubusercontent.com    does NOT honour it; largest first-flight record 4146 B (Certificate)
// so the manifest (a ~2 KB JSON, redirected github.com -> github.com -> release-assets) needs a receive buffer of
// ~4.5 KB, not 16 KB; only the image download streams 16 KB records. 8192 is 1.98x the largest record seen. A bigger
// record fails cleanly (BearSSL BR_ERR_TOO_LARGE -> HTTP -1 -> the check is skipped), it never overruns.
//
// ota_client.cpp needs the Arduino core, so the call-site pins read the source (same technique as test_ota_stack and
// test_ota_session): THE IMAGE DOWNLOAD MUST NOT GET THE MEDIUM BUFFERS - a 16 KB record into an 8 KB buffer would
// abort the download.
#include <unity.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "tls_sizing.h"

namespace {

// include/config.h
constexpr uint32_t kMinFree = 20000;   // HEAP_GATE_OTA
constexpr uint32_t kMinBlock = 36864;  // HEAP_GATE_OTA_BLOCK

const bool kGithub = false;      // peerMightHonourMfln: the compiled-in manifest URL's last hop does not
const bool kHardwareApi = true;  // hardwareapi.frynetworks.com honours it
const bool kSmallReply = true;

constexpr uint32_t kLargestRecordSeen = 4146;  // release-assets.githubusercontent.com Certificate record
constexpr uint32_t kBearsslInOverhead = 325;   // WiFiClientSecureCtx::setBufferSizes MAX_IN_OVERHEAD

void test_a_non_mfln_peer_with_a_small_reply_gets_the_medium_buffers_when_the_heap_affords_it() {
  const fry::TlsPlan p = fry::planTls({41344, 40584}, kMinFree, kMinBlock, kGithub, kSmallReply);
  TEST_ASSERT_TRUE(p.affordable);
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TlsSizing::Medium), static_cast<int>(p.sizing));
}

void test_a_non_mfln_peer_with_a_small_reply_is_still_refused_on_a_short_heap_never_512_512() {
  const fry::HeapSample samples[] = {{41344, 34000}, {19999, 40584}, {0, 0}, {41344, 24240}};
  for (const fry::HeapSample& s : samples) {
    const fry::TlsPlan p = fry::planTls(s, kMinFree, kMinBlock, kGithub, kSmallReply);
    TEST_ASSERT_FALSE(p.affordable);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TlsSizing::Refuse), static_cast<int>(p.sizing));
  }
}

void test_without_the_small_reply_flag_nothing_changes() {
  // The fourth argument form every existing caller and test_tls_sizing uses.
  const fry::TlsPlan big = fry::planTls({41344, 40584}, kMinFree, kMinBlock, kGithub);
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TlsSizing::Big), static_cast<int>(big.sizing));
  const fry::TlsPlan off = fry::planTls({41344, 40584}, kMinFree, kMinBlock, kGithub, false);
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TlsSizing::Big), static_cast<int>(off.sizing));
  const fry::TlsPlan refused = fry::planTls({41344, 34000}, kMinFree, kMinBlock, kGithub);
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TlsSizing::Refuse), static_cast<int>(refused.sizing));
}

void test_an_mfln_peer_ignores_the_small_reply_flag() {
  const fry::HeapSample samples[] = {{41344, 40584}, {36912, 28320}, {0, 0}};
  for (const fry::HeapSample& s : samples) {
    const fry::TlsPlan a = fry::planTls(s, kMinFree, kMinBlock, kHardwareApi);
    const fry::TlsPlan b = fry::planTls(s, kMinFree, kMinBlock, kHardwareApi, kSmallReply);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(a.sizing), static_cast<int>(b.sizing));
    TEST_ASSERT_EQUAL(a.affordable, b.affordable);
  }
}

void test_the_medium_receive_buffer_holds_the_largest_record_seen_with_about_2x_headroom() {
  const uint32_t rx = fry::kTlsMediumRxBytes;
  TEST_ASSERT_TRUE_MESSAGE(rx * 10 >= kLargestRecordSeen * 19,
                           "the medium receive buffer must hold ~twice (>= 1.9x) the largest measured record");
  TEST_ASSERT_TRUE_MESSAGE(rx + kBearsslInOverhead < fry::kTlsBigRxBytes + kBearsslInOverhead,
                           "medium must be smaller than the big buffer or it saves nothing");
  TEST_ASSERT_EQUAL_UINT32(512, fry::kTlsTxBytes);  // unchanged: the send side is what makes BearSSL ask for MFLN
}

// ---- call-site pins (source text; ota_client.cpp needs the core) -----------------------------------------------------

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
  const std::string tail = "test/test_tls_medium/test_main.cpp";
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

void test_only_the_manifest_fetch_asks_for_the_small_reply_buffers() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/core/ota_client.cpp", src), "cannot read src/core/ota_client.cpp");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "otaBeginUrl(http, sec, plain, manifestUrl, /*smallReply=*/true)"),
                                "checkNow()'s manifest GET must ask for the small-reply buffers (once)");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "otaBeginUrl(http, sec, plain, url, /*smallReply=*/false)"),
                                "downloadAndApply() must NOT: 16 KB image records need the 16384 receive buffer");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "/*smallReply=*/true"), "no other call may ask for small replies");
}

void test_the_medium_branch_sizes_the_buffers_from_the_shared_constants() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/esp8266/http_tls.cpp", src), "cannot read src/esp8266/http_tls.cpp");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "sec.setBufferSizes(fry::kTlsMediumRxBytes, fry::kTlsTxBytes)"),
                                "the Medium case must size the buffers from the tested constants");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "case fry::TlsSizing::Medium:"), "one Medium case");
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_a_non_mfln_peer_with_a_small_reply_gets_the_medium_buffers_when_the_heap_affords_it);
  RUN_TEST(test_a_non_mfln_peer_with_a_small_reply_is_still_refused_on_a_short_heap_never_512_512);
  RUN_TEST(test_without_the_small_reply_flag_nothing_changes);
  RUN_TEST(test_an_mfln_peer_ignores_the_small_reply_flag);
  RUN_TEST(test_the_medium_receive_buffer_holds_the_largest_record_seen_with_about_2x_headroom);
  RUN_TEST(test_only_the_manifest_fetch_asks_for_the_small_reply_buffers);
  RUN_TEST(test_the_medium_branch_sizes_the_buffers_from_the_shared_constants);
  return UNITY_END();
}
