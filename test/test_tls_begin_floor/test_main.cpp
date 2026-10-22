// The OTA manifest check must not be refused by beginHttpsUrl() right after its own gate let it through.
//
// Bench 2026-10-22 (production-env images, lo/c1-p2-121154.ota.txt and lo/c1-p-122054.ota.txt): the heap gate in
// checkNow() passed, and 8 of 8 checks then logged "ota: manifest fetch begin failed" about 15 ms later, with no GET.
// The failure is a refusal, not a transport error: HTTPClient::begin(WiFiClient&, const String&) of core 3.30102.0
// can only return false for a URL without "scheme:" or with a scheme other than http/https, and
// fry_http::beginHttpsUrl() has exactly one other `return false`, the TlsSizing::Refuse case of fry::planTls().
//
// Why Refuse: checkNow() samples the heap BEFORE its clients exist (HEAP_GATE_OTA 20000 / HEAP_GATE_OTA_BLOCK 36864),
// beginHttpsUrl() samples AFTER (the constructor of the first WiFiClientSecure mallocs BearSSL's 6200 B stack thunk,
// 6208 B with the allocator's rounding, and the clients are one more block) and used to compare that second sample with
// the SAME two numbers. A heap that has only just passed the gate is 6.7 KB short of them by then. 217c2bb had the same
// second sample but answered a short heap with 512/512, which soft-reset the board in a handshake with GitHub (0.3.3
// bench); 8340cc4 turned that into a refusal, which is what the 05ffb66..1b1cd59 images then did on every check.
//
// The fix gives beginHttpsUrl() the gate's floors as seen from the other side of the constructor
// (fry::tlsFloorsAtBegin). The effective bar on the heap BEFORE the clients exist stays exactly the gate's number: the
// last test pins that the floors plus what the constructor takes equal the gate to the byte, so the begin-time check is
// never a lower bar than the gate (the gate value itself is a separate, measured decision).
#include <unity.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "tls_sizing.h"

namespace {

// include/config.h
constexpr uint32_t kGateFree = 20000;   // HEAP_GATE_OTA
constexpr uint32_t kGateBlock = 36864;  // HEAP_GATE_OTA_BLOCK

const bool kGithub = false;      // peerMightHonourMfln: the compiled-in manifest URL's last hop does not
const bool kHardwareApi = true;  // hardwareapi.frynetworks.com honours it

constexpr uint32_t kCtor = fry::kBearsslStackThunkBytes + fry::kOtaClientsBytes;

// The heap after the constructor, from a heap sampled before it, when the thunk and the clients both come out of the
// largest free block (the worst case for the contiguous floor).
fry::HeapSample afterCtor(const fry::HeapSample& before) {
  return {before.freeTotal - kCtor, before.maxBlock - kCtor};
}

fry::TlsPlan beginPlan(const fry::HeapSample& afterTheCtor, bool peerMightHonourMfln, bool smallReply) {
  const fry::TlsFloors f = fry::tlsFloorsAtBegin(kGateFree, kGateBlock, peerMightHonourMfln);
  return fry::planTls(afterTheCtor, f.freeTotal, f.block, peerMightHonourMfln, smallReply);
}

void test_a_heap_that_just_passed_the_gate_is_not_refused_at_begin_for_the_manifest() {
  const fry::HeapSample passesTheGate = {kGateFree, kGateBlock};  // exactly on both floors
  const fry::TlsPlan p = beginPlan(afterCtor(passesTheGate), kGithub, /*smallReply=*/true);
  TEST_ASSERT_TRUE(p.affordable);
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TlsSizing::Medium), static_cast<int>(p.sizing));
}

void test_a_heap_that_just_passed_the_gate_is_not_refused_at_begin_for_the_download() {
  const fry::HeapSample passesTheGate = {kGateFree, kGateBlock};
  const fry::TlsPlan p = beginPlan(afterCtor(passesTheGate), kGithub, /*smallReply=*/false);
  TEST_ASSERT_TRUE(p.affordable);
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TlsSizing::Big), static_cast<int>(p.sizing));
}

void test_the_bench_heaps_seen_on_the_production_image_are_not_refused() {
  // checkNow() gated at about these (free, blk) once the TIME_WAIT pcbs had cleared; a post-constructor sample is
  // kCtor lower in both.
  const fry::HeapSample gated[] = {{37688, 36864}, {41000, 37200}, {40500, 36900}};
  for (const fry::HeapSample& g : gated) {
    const fry::TlsPlan p = beginPlan(afterCtor(g), kGithub, true);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TlsSizing::Medium), static_cast<int>(p.sizing));
  }
}

void test_a_non_mfln_peer_is_still_refused_below_the_floors_never_512_512() {
  const fry::TlsFloors f = fry::tlsFloorsAtBegin(kGateFree, kGateBlock, kGithub);
  const fry::HeapSample shortBlock = {kGateFree, f.block - 1};
  const fry::HeapSample shortFree = {f.freeTotal - 1, kGateBlock};
  const fry::HeapSample empty = {0, 0};
  const fry::HeapSample shorts[] = {shortBlock, shortFree, empty};
  for (const fry::HeapSample& s : shorts) {
    for (int small = 0; small < 2; small++) {
      const fry::TlsPlan p = beginPlan(s, kGithub, small != 0);
      TEST_ASSERT_FALSE(p.affordable);
      TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TlsSizing::Refuse), static_cast<int>(p.sizing));
    }
  }
}

void test_a_peer_that_may_honour_mfln_keeps_the_gate_floors_for_its_probe() {
  // The 32 KB probe allocates after the constructor, so its sample is already in the probe's terms.
  const fry::TlsFloors f = fry::tlsFloorsAtBegin(kGateFree, kGateBlock, kHardwareApi);
  TEST_ASSERT_EQUAL_UINT32(kGateFree, f.freeTotal);
  TEST_ASSERT_EQUAL_UINT32(kGateBlock, f.block);
  const fry::TlsPlan probe = beginPlan({kGateFree, kGateBlock}, kHardwareApi, false);
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TlsSizing::ProbeFirst), static_cast<int>(probe.sizing));
  const fry::TlsPlan small = beginPlan({kGateFree, kGateBlock - 1}, kHardwareApi, false);
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TlsSizing::Small), static_cast<int>(small.sizing));
}

void test_the_adjusted_floors_saturate_at_zero_instead_of_wrapping() {
  const fry::TlsFloors f = fry::tlsFloorsAtBegin(100, 200, kGithub);
  TEST_ASSERT_EQUAL_UINT32(0, f.freeTotal);
  TEST_ASSERT_EQUAL_UINT32(0, f.block);
}

void test_the_begin_floors_are_never_a_lower_bar_than_the_gate() {
  // floors + what the constructor takes == the gate, to the byte: a heap the gate refused is refused here too.
  const fry::TlsFloors f = fry::tlsFloorsAtBegin(kGateFree, kGateBlock, kGithub);
  TEST_ASSERT_EQUAL_UINT32(kGateFree, f.freeTotal + kCtor);
  TEST_ASSERT_EQUAL_UINT32(kGateBlock, f.block + kCtor);
  const fry::HeapSample refusedByTheGate[] = {{kGateFree - 1, kGateBlock}, {kGateFree, kGateBlock - 1}};
  for (const fry::HeapSample& g : refusedByTheGate) {
    const fry::TlsPlan p = beginPlan(afterCtor(g), kGithub, true);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TlsSizing::Refuse), static_cast<int>(p.sizing));
  }
}

// ---- call-site pins (source text; http_tls.cpp and ota_client.cpp need the core) ---------------------------------------

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
  const std::string tail = "test/test_tls_begin_floor/test_main.cpp";
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

void test_beginHttpsUrl_plans_with_the_begin_floors_not_the_raw_gate() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/esp8266/http_tls.cpp", src), "cannot read src/esp8266/http_tls.cpp");
  TEST_ASSERT_EQUAL_INT_MESSAGE(
      1, countOf(src, "fry::tlsFloorsAtBegin(HEAP_GATE_OTA, HEAP_GATE_OTA_BLOCK, mflnProbeWorthwhile)"),
      "the floors must come from tlsFloorsAtBegin() applied to the gate's own numbers");
  TEST_ASSERT_EQUAL_INT_MESSAGE(
      1, countOf(src, "fry::planTls(heap, floors.freeTotal, floors.block, mflnProbeWorthwhile, smallReply)"),
      "planTls() must be given those floors");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(src, "planTls(heap, HEAP_GATE_OTA"),
                                "the raw gate numbers must not reach planTls() again");
}

void test_the_ota_clients_fit_the_block_the_floors_assume() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/core/ota_client.cpp", src), "cannot read src/core/ota_client.cpp");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "static_assert(sizeof(DownloadWork) + 16 <= fry::kOtaClientsBytes"),
                                "DownloadWork (the larger set) must be checked against kOtaClientsBytes at build time");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "static_assert(sizeof(ManifestClients) + 16 <= fry::kOtaClientsBytes"),
                                "ManifestClients must be checked against kOtaClientsBytes at build time");
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_a_heap_that_just_passed_the_gate_is_not_refused_at_begin_for_the_manifest);
  RUN_TEST(test_a_heap_that_just_passed_the_gate_is_not_refused_at_begin_for_the_download);
  RUN_TEST(test_the_bench_heaps_seen_on_the_production_image_are_not_refused);
  RUN_TEST(test_a_non_mfln_peer_is_still_refused_below_the_floors_never_512_512);
  RUN_TEST(test_a_peer_that_may_honour_mfln_keeps_the_gate_floors_for_its_probe);
  RUN_TEST(test_the_adjusted_floors_saturate_at_zero_instead_of_wrapping);
  RUN_TEST(test_the_begin_floors_are_never_a_lower_bar_than_the_gate);
  RUN_TEST(test_beginHttpsUrl_plans_with_the_begin_floors_not_the_raw_gate);
  RUN_TEST(test_the_ota_clients_fit_the_block_the_floors_assume);
  return UNITY_END();
}
