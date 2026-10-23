// A GitHub (non-MFLN) host must never be handed 512/512 buffers, and the buffer choice must come
// from the SAME heap sample as the affordability verdict.
//
// The 0.3.3 fleet image (and 217c2bb = 0.4.9, src/esp8266/http_tls.cpp:62-78) passed the OTA gate in
// checkNow, then re-gated inside beginHttpsUrl, found the heap short and fell back to
// setBufferSizes(512, 512) for a peer that does not honour MFLN. Bench log (0.3.3, lo/e8266-033ck-*):
//   "tls: low contiguous heap - MFLN probe skipped, 512/512" followed by
//   Soft WDT reset (Exception 4) x2 and "ota: manifest fetch HTTP -5 (blk=24240)" x1 in 3 checks.
// An unaffordable heap is right to fall back to 512/512 for hardwareapi (it honours MFLN: register,
// lease, PoC and telemetry rely on that), and wrong for GitHub.
#include <unity.h>

#include "tls_sizing.h"

namespace {

// include/config.h
constexpr uint32_t kMinFree = 20000;    // HEAP_GATE_OTA
constexpr uint32_t kMinBlock = 36864;   // HEAP_GATE_OTA_BLOCK

const bool kGithub = false;       // peerMightHonourMfln: GitHub does not
const bool kHardwareApi = true;   // hardwareapi.frynetworks.com may honour it

void test_a_non_mfln_host_is_never_given_512_512_whatever_the_heap() {
  // Samples from the bench logs (esp5/0.3.3 and 217c2bb) plus the boundaries around the gate.
  const fry::HeapSample samples[] = {
      {41344, 40584},  // 0.3.3 idle plateau at up~150 s: the sample gate #1 passed
      {36912, 28320},  // 217c2bb at the boot check
      {41392, 32880},  // 0.3.3 at the boot check
      {41344, 34000},  // just under the 36864 gate with ample total heap
      {41344, 24240},  // the blk the failed 512/512 attempt left behind
      {19999, 40584},  // total heap one byte short
      {0, 0},
      {200000, 200000},
  };
  for (const fry::HeapSample& s : samples) {
    const fry::TlsPlan p = fry::planTls(s, kMinFree, kMinBlock, kGithub);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(static_cast<int>(fry::TlsSizing::Small),
                                  static_cast<int>(p.sizing),
                                  "GitHub was handed 512/512 buffers: BearSSL cannot complete the handshake");
  }
}

void test_an_unaffordable_check_against_github_is_refused_before_any_handshake() {
  const fry::TlsPlan p = fry::planTls({41344, 34000}, kMinFree, kMinBlock, kGithub);
  TEST_ASSERT_FALSE(p.affordable);
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TlsSizing::Refuse), static_cast<int>(p.sizing));
}

void test_an_affordable_check_against_github_gets_the_big_buffers_without_a_probe() {
  const fry::TlsPlan p = fry::planTls({41344, 40584}, kMinFree, kMinBlock, kGithub);
  TEST_ASSERT_TRUE(p.affordable);
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TlsSizing::Big), static_cast<int>(p.sizing));
}

void test_hardwareapi_keeps_its_512_512_fallback_on_a_short_heap() {
  // Registration, lease, PoC and telemetry run on a fragmented heap and must not be refused.
  const fry::TlsPlan p = fry::planTls({36912, 28320}, kMinFree, kMinBlock, kHardwareApi);
  TEST_ASSERT_FALSE(p.affordable);
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TlsSizing::Small), static_cast<int>(p.sizing));
}

void test_an_mfln_capable_peer_with_heap_is_still_probed() {
  const fry::TlsPlan p = fry::planTls({41344, 40584}, kMinFree, kMinBlock, kHardwareApi);
  TEST_ASSERT_TRUE(p.affordable);
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TlsSizing::ProbeFirst), static_cast<int>(p.sizing));
}

void test_an_mfln_capable_peer_is_never_refused() {
  const uint32_t frees[] = {0, 19999, 20000, 41344, 200000};
  const uint32_t blocks[] = {0, 24240, 36863, 36864, 40584, 200000};
  for (uint32_t f : frees) {
    for (uint32_t b : blocks) {
      const fry::TlsPlan p = fry::planTls({f, b}, kMinFree, kMinBlock, kHardwareApi);
      TEST_ASSERT_NOT_EQUAL(static_cast<int>(fry::TlsSizing::Refuse), static_cast<int>(p.sizing));
    }
  }
}

void test_verdict_and_sizing_come_from_one_sample() {
  // The affordability verdict is heapGatePass() on the very sample the sizing was derived from, and
  // the sizing agrees with it: Small/Refuse only when unaffordable, Big/ProbeFirst only when
  // affordable. Walks the boundary grid in both directions for both peers.
  const uint32_t frees[] = {0, 19999, 20000, 20001, 41344, 200000};
  const uint32_t blocks[] = {0, 24240, 36863, 36864, 36865, 40584, 200000};
  for (uint32_t f : frees) {
    for (uint32_t b : blocks) {
      for (int mfln = 0; mfln < 2; mfln++) {
        const fry::TlsPlan p = fry::planTls({f, b}, kMinFree, kMinBlock, mfln != 0);
        const bool gate = f >= kMinFree && b >= kMinBlock;
        TEST_ASSERT_EQUAL_INT(gate ? 1 : 0, p.affordable ? 1 : 0);
        const bool bigPath = p.sizing == fry::TlsSizing::Big || p.sizing == fry::TlsSizing::ProbeFirst;
        TEST_ASSERT_EQUAL_INT(gate ? 1 : 0, bigPath ? 1 : 0);
      }
    }
  }
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_a_non_mfln_host_is_never_given_512_512_whatever_the_heap);
  RUN_TEST(test_an_unaffordable_check_against_github_is_refused_before_any_handshake);
  RUN_TEST(test_an_affordable_check_against_github_gets_the_big_buffers_without_a_probe);
  RUN_TEST(test_hardwareapi_keeps_its_512_512_fallback_on_a_short_heap);
  RUN_TEST(test_an_mfln_capable_peer_with_heap_is_still_probed);
  RUN_TEST(test_an_mfln_capable_peer_is_never_refused);
  RUN_TEST(test_verdict_and_sizing_come_from_one_sample);
  return UNITY_END();
}
