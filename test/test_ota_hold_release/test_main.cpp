// The registration-failure hold of an OTA check on ESP8266 releases as soon as free heap AND the largest block meet the
// download gate, in the pre-constructor units the hold samples in (42280 free / 36816 block), instead of waiting out
// TIME_WAIT up to kOtaTimeWaitMaxHoldMs. The bound is unchanged and the check is never skipped. Pure decision: ota_hold_release.h.
#include <unity.h>

#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>

#include "ota_heap_budget.h"
#include "ota_hold_release.h"
#include "ota_timewait.h"
#include "tls_sizing.h"

namespace {

const uint32_t kMax = fry::kOtaTimeWaitMaxHoldMs;
// Pre-constructor units: the hold samples before the TLS clients exist, so it compares with the gate itself (42280 / 36816),
// not with tlsFloorsAtBegin() (35560 / 30096, the same bar after the constructor took 6720 B).
const fry::TlsFloors kF = {fry::ota_heap::kDownloadGateFree, fry::ota_heap::kDownloadGateBlock};

int d(uint32_t pcbs, uint32_t held, uint32_t freeNow, uint32_t blk) {
  return static_cast<int>(fry::decideHoldRelease(pcbs, held, kMax, freeNow, blk));
}
const int kHold = static_cast<int>(fry::TwHold::Hold);
const int kGo = static_cast<int>(fry::TwHold::Proceed);

void test_floors_are_the_download_gate_in_pre_constructor_units() {
  TEST_ASSERT_EQUAL_UINT32(42280, kF.freeTotal);
  TEST_ASSERT_EQUAL_UINT32(36816, kF.block);
  const fry::TlsFloors post = fry::tlsFloorsAtBegin(kF.freeTotal, kF.block, false);
  TEST_ASSERT_EQUAL_UINT32(35560, post.freeTotal);
  TEST_ASSERT_EQUAL_UINT32(30096, post.block);
  TEST_ASSERT_TRUE(fry::kOtaHoldReleaseFree > post.freeTotal && fry::kOtaHoldReleaseBlock > post.block);
  TEST_ASSERT_EQUAL_UINT32(kF.freeTotal, fry::kOtaHoldReleaseFree);
  TEST_ASSERT_EQUAL_UINT32(kF.block, fry::kOtaHoldReleaseBlock);
}

void test_releases_when_both_floors_met_even_with_pcbs_remaining() {
  TEST_ASSERT_EQUAL_INT(kGo, d(2, 0, kF.freeTotal, kF.block));
  TEST_ASSERT_EQUAL_INT(kGo, d(3, 5000, kF.freeTotal + 1000, kF.block + 1000));
}

void test_no_release_when_either_floor_is_short() {
  TEST_ASSERT_EQUAL_INT(kHold, d(2, 0, kF.freeTotal - 1, kF.block));
  TEST_ASSERT_EQUAL_INT(kHold, d(2, 0, kF.freeTotal, kF.block - 1));
  TEST_ASSERT_EQUAL_INT(kHold, d(2, 0, 0, 0));
  // the observed bench-case heap (blk 32680, free 34872) and a heap at the POST-constructor floors are not enough before the constructor
  TEST_ASSERT_EQUAL_INT(kHold, d(2, 100000, 34872, 32680));
  TEST_ASSERT_EQUAL_INT(kHold, d(2, 0, 35560, 30096));
}

void test_no_pcbs_proceeds_whatever_the_heap() {
  TEST_ASSERT_EQUAL_INT(kGo, d(0, 0, 0, 0));
}

void test_the_bound_still_applies_whatever_the_heap() {
  TEST_ASSERT_EQUAL_INT(kHold, d(2, kMax - 1, 0, 0));
  TEST_ASSERT_EQUAL_INT(kGo, d(2, kMax, 0, 0));
  TEST_ASSERT_EQUAL_INT(kGo, d(2, UINT32_MAX, 0, 0));
}

void test_the_check_is_never_skipped() {
  // A starved heap: held for kMax at most, then Proceed. Never Hold past the bound for any pcbs/heap.
  uint32_t t = 0;
  for (; t <= kMax + 1000; t += 250) {
    if (fry::decideHoldRelease(2, t, kMax, 100, 100) == fry::TwHold::Proceed) break;
  }
  TEST_ASSERT_EQUAL_UINT32(kMax, t);
  for (uint32_t pcbs = 0; pcbs < 4; pcbs++)
    for (uint32_t f = 0; f < 50000; f += 7000)
      TEST_ASSERT_EQUAL_INT(kGo, d(pcbs, kMax + 5, f, f));
}

void test_wrap_safe_millis() {
  // holdForTimeWait computes heldMs = uint32(now - since); across the 32-bit wrap it must stay small.
  const uint32_t since = 0xFFFFFF00u, now = 0x00000100u;
  const uint32_t held = static_cast<uint32_t>(now - since);
  TEST_ASSERT_EQUAL_UINT32(0x200u, held);
  TEST_ASSERT_EQUAL_INT(kHold, d(2, held, kF.freeTotal - 1, kF.block));
  TEST_ASSERT_EQUAL_INT(kGo, d(2, held, kF.freeTotal, kF.block));
  const uint32_t heldLong = static_cast<uint32_t>((since + kMax) - since);
  TEST_ASSERT_EQUAL_INT(kGo, d(2, heldLong, 0, 0));
}

bool loadSrc(std::string& out) {
  std::string self = __FILE__;
  const std::string tail = "test/test_ota_hold_release/test_main.cpp";
  const char* ups[] = {"", "../", "../../", "../../../"};
  std::string pre;
  if (self.size() >= tail.size() && self.compare(self.size() - tail.size(), tail.size(), tail) == 0) pre = self.substr(0, self.size() - tail.size());
  for (int i = -1; i < 4; i++) {
    std::string p = (i < 0 ? pre : std::string(ups[i])) + "src/core/ota_client.cpp";
    std::ifstream f(p.c_str(), std::ios::binary);
    if (!f) continue;
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
  }
  return false;
}

void test_holdForTimeWait_uses_the_release_decision_and_keeps_the_timewait_one() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSrc(src), "cannot read src/core/ota_client.cpp");
  const size_t b = src.find("static bool holdForTimeWait(unsigned long now) {");
  TEST_ASSERT_TRUE(b != std::string::npos);
  const size_t e = src.find("\n}\n", b);
  const std::string body = src.substr(b, e - b);
  TEST_ASSERT_TRUE_MESSAGE(body.find("fry::decideHoldRelease(") != std::string::npos, "holdForTimeWait must call decideHoldRelease");
  TEST_ASSERT_TRUE(body.find("fry::decideTimeWaitHold(tw + closing, heldMs, fry::kOtaTimeWaitMaxHoldMs)") != std::string::npos);
  TEST_ASSERT_TRUE(body.find("ESP.getFreeHeap()") != std::string::npos);
  TEST_ASSERT_TRUE(body.find("fry::queryMaxFreeBlock()") != std::string::npos);
  TEST_ASSERT_TRUE_MESSAGE(body.find("released early") != std::string::npos, "early release must be logged");
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_floors_are_the_download_gate_in_pre_constructor_units);
  RUN_TEST(test_releases_when_both_floors_met_even_with_pcbs_remaining);
  RUN_TEST(test_no_release_when_either_floor_is_short);
  RUN_TEST(test_no_pcbs_proceeds_whatever_the_heap);
  RUN_TEST(test_the_bound_still_applies_whatever_the_heap);
  RUN_TEST(test_the_check_is_never_skipped);
  RUN_TEST(test_wrap_safe_millis);
  RUN_TEST(test_holdForTimeWait_uses_the_release_decision_and_keeps_the_timewait_one);
  return UNITY_END();
}
