// The download's first floor sample must not see the previous session's closing connection, and must not carry the digest state in its work block.
//
// Captures of the redirect chain on a board: the sample after the manifest came in ~450 B under the same sample of a run whose manifest connection had
// finished closing. Two causes, both measured in the device heap map: the connection (188 B pcb + 108 B pbuf) was still in LAST_ACK below the large
// block, so the block-only settle returned at once; and the work block of the download carried a Sha256, a digest and its hex (216 B) that the
// manifest's block does not. This test pins the closing-pcb decision (hold while any is left, release at the bound) and the wiring: both settles
// wait on it, and the digest state is a separate nothrow block taken just before streaming that fails like the download buffer.
#include <unity.h>

#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "ota_settle.h"

namespace {

const uint32_t kMax = fry::kOtaSettleMaxMs;
const int kHold = static_cast<int>(fry::SettleHold::Hold);
const int kProceed = static_cast<int>(fry::SettleHold::Proceed);

int decide(uint32_t closing, uint32_t held) { return static_cast<int>(fry::decideClosingSettle(closing, held, kMax)); }

void test_it_holds_while_a_connection_is_still_closing() {
  TEST_ASSERT_EQUAL_INT_MESSAGE(kHold, decide(1, 0), "one pcb in LAST_ACK: wait");
  TEST_ASSERT_EQUAL_INT(kHold, decide(3, 100));
  TEST_ASSERT_EQUAL_INT_MESSAGE(kHold, decide(1, kMax - 1), "one ms before the bound: still wait");
}

void test_it_proceeds_when_nothing_is_closing() {
  TEST_ASSERT_EQUAL_INT(kProceed, decide(0, 0));
  TEST_ASSERT_EQUAL_INT(kProceed, decide(0, kMax));
}

void test_the_wait_is_bounded() {
  TEST_ASSERT_EQUAL_INT_MESSAGE(kProceed, decide(1, kMax), "at the bound the download goes on");
  TEST_ASSERT_EQUAL_INT(kProceed, decide(5, kMax + 1));
  TEST_ASSERT_EQUAL_INT(kProceed, decide(UINT32_MAX, UINT32_MAX));
}

void test_a_pcb_that_drains_inside_the_bound_releases_by_draining() {
  uint32_t t = 0;
  for (;; t += fry::kOtaSettlePollMs) {
    if (decide(t < 700 ? 1u : 0u, t) == kProceed) break;
    TEST_ASSERT_TRUE_MESSAGE(t < kMax, "never released");
  }
  TEST_ASSERT_TRUE_MESSAGE(t >= 700 && t < 700 + fry::kOtaSettlePollMs, "released by the drain, not by the bound");
}

void test_a_pcb_that_never_drains_cannot_starve_the_download() {
  uint32_t t = 0;
  for (;; t += fry::kOtaSettlePollMs) {
    if (decide(1, t) == kProceed) break;
    TEST_ASSERT_TRUE_MESSAGE(t <= kMax, "starved past the bound");
  }
  TEST_ASSERT_TRUE(t >= kMax && t < kMax + fry::kOtaSettlePollMs);
}

// ---- wiring -----------------------------------------------------------------------------------------------------------------------
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
  const std::string tail = "test/test_ota_closing_settle/test_main.cpp";
  std::vector<std::string> prefixes;
  if (self.size() >= tail.size() && self.compare(self.size() - tail.size(), tail.size(), tail) == 0) prefixes.push_back(self.substr(0, self.size() - tail.size()));
  const char* ups[] = {"", "../", "../../", "../../../", "../../../../"};
  for (size_t i = 0; i < sizeof(ups) / sizeof(ups[0]); i++) prefixes.push_back(ups[i]);
  for (size_t i = 0; i < prefixes.size(); i++)
    if (readFile(prefixes[i] + rel, out)) return true;
  return false;
}

std::string bodyAfter(const std::string& src, const std::string& head, const char* end = "\n}\n") {
  const size_t a = src.find(head);
  if (a == std::string::npos) return std::string();
  const size_t b = src.find(end, a);
  return b == std::string::npos ? std::string() : src.substr(a, b - a);
}

bool has(const std::string& s, const char* n) { return s.find(n) != std::string::npos; }

void test_both_settles_wait_for_the_closing_pcbs_within_their_bound() {
  std::string src;
  TEST_ASSERT_TRUE(loadSource("src/core/ota_client.cpp", src));
  const char* heads[] = {"static unsigned long settleAfterHop(uint32_t blkBaseline) {", "static void settleAfterManifest(uint32_t blkBefore) {"};
  for (size_t i = 0; i < 2; i++) {
    const std::string fn = bodyAfter(src, heads[i]);
    TEST_ASSERT_TRUE_MESSAGE(!fn.empty(), heads[i]);
    TEST_ASSERT_TRUE_MESSAGE(has(fn, "fry::decideClosingSettle("), heads[i]);
    TEST_ASSERT_TRUE_MESSAGE(has(fn, "fry::countClosingPcbs()"), heads[i]);
    TEST_ASSERT_TRUE_MESSAGE(has(fn, "fry::kOtaSettleMaxMs"), heads[i]);
    TEST_ASSERT_TRUE_MESSAGE(has(fn, "fry::decideHeapSettle("), "the block criterion stays");
  }
}

void test_the_digest_state_is_not_in_the_download_work_block() {
  std::string src;
  TEST_ASSERT_TRUE(loadSource("src/core/ota_client.cpp", src));
  const std::string dw = bodyAfter(src, "struct DownloadWork {", "\n};");
  TEST_ASSERT_TRUE(!dw.empty());
  TEST_ASSERT_FALSE_MESSAGE(has(dw, "Sha256"), "DownloadWork carries no Sha256");
  TEST_ASSERT_FALSE_MESSAGE(has(dw, "digest"), "...no digest");
  TEST_ASSERT_FALSE_MESSAGE(has(dw, "hex"), "...no hex");
  const std::string dg = bodyAfter(src, "struct DigestWork {", "\n};");
  TEST_ASSERT_TRUE_MESSAGE(!dg.empty() && has(dg, "Sha256") && has(dg, "digest[32]") && has(dg, "hex[65]"), "DigestWork holds them");
}

void test_the_digest_block_is_taken_nothrow_before_the_first_update_and_fails_like_the_buffer() {
  std::string src;
  TEST_ASSERT_TRUE(loadSource("src/core/ota_client.cpp", src));
  const size_t alloc = src.find("new (std::nothrow) DigestWork");
  TEST_ASSERT_TRUE_MESSAGE(alloc != std::string::npos, "nothrow allocation");
  const size_t buf = src.find("new (std::nothrow) uint8_t[kBufBytes]");
  const size_t upd = src.find("sha.update(buf, r)");
  TEST_ASSERT_TRUE(buf != std::string::npos && upd != std::string::npos);
  TEST_ASSERT_TRUE_MESSAGE(alloc < upd, "before the first hash update");
  const size_t nul = src.find("if (!bufHeap || !digestWork) {", alloc);
  TEST_ASSERT_TRUE_MESSAGE(nul != std::string::npos && nul < upd, "checked for null");
  const std::string fail = bodyAfter(src.substr(nul), "if (!bufHeap || !digestWork) {", "\n  }\n");
  TEST_ASSERT_TRUE_MESSAGE(has(fail, "upd.discard();") && has(fail, "http.end();") && has(fail, "return false;"), "the buffer's own failure path, unchanged");
  TEST_ASSERT_FALSE_MESSAGE(has(fail, "Update."), "no new Update state");
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_it_holds_while_a_connection_is_still_closing);
  RUN_TEST(test_it_proceeds_when_nothing_is_closing);
  RUN_TEST(test_the_wait_is_bounded);
  RUN_TEST(test_a_pcb_that_drains_inside_the_bound_releases_by_draining);
  RUN_TEST(test_a_pcb_that_never_drains_cannot_starve_the_download);
  RUN_TEST(test_both_settles_wait_for_the_closing_pcbs_within_their_bound);
  RUN_TEST(test_the_digest_state_is_not_in_the_download_work_block);
  RUN_TEST(test_the_digest_block_is_taken_nothrow_before_the_first_update_and_fails_like_the_buffer);
  return UNITY_END();
}
