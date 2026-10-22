// The ESP8266 OTA manifest check's heap gate is derived from a MEASURED need, in the units the gate samples.
//
// Bench 2026-10-22 (decoy sweep C2, lo/c1-c2a-123102.lines.txt + lo/c1-c2b-123905.lines.txt): the 3-hop GitHub manifest
// GET on the 8192/512 session passed 3/3 with the largest free block forced (after the TLS clients exist) to 23992, 21992,
// 19992 and 18992 B, and FAILED at 17992 (-1 x2, one OOM panic: `last failed alloc call: 402177BB(1496)` =
// BearSSL::WiFiClientSecureCtx::_installClientX509Validator()). Need: post-constructor blk in (17992, 18992].
//
// checkNow() samples BEFORE its clients exist, so the gate is the need (upper bound) + a 4096 B margin + what the
// constructors take (BearSSL stack thunk 6208 + clients block 512): 29808 blk, 29976 free (lib/fry_core/ota_heap_budget.h).
// The 16384/512 numbers (HEAP_GATE_OTA 20000 / HEAP_GATE_OTA_BLOCK 36864, include/config.h) are unchanged: the image
// download keeps them, and so does every other chip.
#include <unity.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "heap_gate.h"
#include "ota_heap_budget.h"
#include "tls_sizing.h"

namespace {

namespace budget = fry::ota_heap;

void test_the_gate_is_the_measured_need_plus_margin_plus_what_the_constructors_take() {
  TEST_ASSERT_EQUAL_UINT32(18992, budget::kManifestNeedBlk);   // lowest forced blk that passed 3/3
  TEST_ASSERT_EQUAL_UINT32(19160, budget::kManifestNeedFree);  // total free at that point
  TEST_ASSERT_EQUAL_UINT32(4096, budget::kMarginBytes);
  TEST_ASSERT_EQUAL_UINT32(6208, fry::kBearsslStackThunkBytes);
  TEST_ASSERT_EQUAL_UINT32(6208 + 512, budget::kCtorBytes);
  TEST_ASSERT_EQUAL_UINT32(18992 + 4096 + 6208 + 512, budget::kManifestGateBlock);
  TEST_ASSERT_EQUAL_UINT32(29808, budget::kManifestGateBlock);
  TEST_ASSERT_EQUAL_UINT32(19160 + 4096 + 6208 + 512, budget::kManifestGateFree);
  TEST_ASSERT_EQUAL_UINT32(29976, budget::kManifestGateFree);
}

void test_seen_from_after_the_constructors_the_gate_is_exactly_need_plus_margin() {
  const fry::TlsFloors f = fry::tlsFloorsAtBegin(budget::kManifestGateFree, budget::kManifestGateBlock, false);
  TEST_ASSERT_EQUAL_UINT32(budget::kManifestNeedBlk + budget::kMarginBytes, f.block);    // 23088
  TEST_ASSERT_EQUAL_UINT32(budget::kManifestNeedFree + budget::kMarginBytes, f.freeTotal);  // 23256
}

void test_the_gate_refuses_every_heap_whose_post_constructor_block_is_inside_need_plus_margin() {
  // Worst case: thunk and clients both come out of the largest free block. The failing band, the 3/3 PASS points of the
  // sweep and everything up to one byte under need + margin must all be refused BEFORE a session is opened.
  const uint32_t postCtorBlocks[] = {0, 17992, 18992, 19992, 21992, 22992, 23087};
  for (uint32_t post : postCtorBlocks) {
    const uint32_t pre = post + budget::kCtorBytes;
    TEST_ASSERT_FALSE_MESSAGE(
        fry::heapGatePass(pre + 168, pre, budget::kManifestGateFree, budget::kManifestGateBlock),
        "a heap that would leave less than need + margin after the constructors must not pass the gate");
  }
}

void test_the_gate_passes_from_need_plus_margin_up() {
  const uint32_t pre = budget::kManifestNeedBlk + budget::kMarginBytes + budget::kCtorBytes;  // 29808
  TEST_ASSERT_TRUE(fry::heapGatePass(budget::kManifestGateFree, pre, budget::kManifestGateFree, budget::kManifestGateBlock));
  TEST_ASSERT_FALSE(fry::heapGatePass(budget::kManifestGateFree, pre - 1, budget::kManifestGateFree, budget::kManifestGateBlock));
  TEST_ASSERT_FALSE(fry::heapGatePass(budget::kManifestGateFree - 1, pre, budget::kManifestGateFree, budget::kManifestGateBlock));
  // What the production-env bench heap showed once the TIME_WAIT pcbs had cleared (the old gate already passed it).
  TEST_ASSERT_TRUE(fry::heapGatePass(37688, 36864, budget::kManifestGateFree, budget::kManifestGateBlock));
}

void test_the_gate_is_a_function_of_the_measurement_not_of_the_old_constant() {
  // The old 36864 was a 16384/512 number; the manifest check no longer opens that session.
  TEST_ASSERT_TRUE(budget::kManifestGateBlock < 36864);
  TEST_ASSERT_TRUE(budget::kManifestGateFree > 20000);  // the total-free floor goes UP: 19160 measured + margin + ctor
  // ...and a heap the old gate refused at 34272 (COM11, test_ota_heap_gate) is admitted only because its post-constructor
  // block, 27552, is 8560 B over the measured need, not because the bar was dropped.
  const uint32_t post = 34272 - budget::kCtorBytes;
  TEST_ASSERT_TRUE(post >= budget::kManifestNeedBlk + budget::kMarginBytes);
}

// ---- wiring pins (source text; these files need the Arduino core or the PlatformIO tool chain) -----------------------

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
  const std::string tail = "test/test_ota_heap_budget/test_main.cpp";
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

// The text of one [section] of platformio.ini, up to the next section header.
std::string iniSection(const std::string& ini, const std::string& header) {
  const size_t at = ini.find("\n" + header + "\n");
  if (at == std::string::npos) return "";
  const size_t from = at + 1;
  const size_t next = ini.find("\n[", from);
  return ini.substr(from, next == std::string::npos ? std::string::npos : next - from);
}

void test_only_env_esp8266_carries_the_new_gate_numbers() {
  std::string ini;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("platformio.ini", ini), "cannot read platformio.ini");
  const std::string blk = "-DHEAP_GATE_OTA_MANIFEST_BLOCK=29808";
  const std::string fre = "-DHEAP_GATE_OTA_MANIFEST=29976";
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(ini, blk), "the block gate is set once in the whole file");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(ini, fre), "the free gate is set once in the whole file");
  const std::string env = iniSection(ini, "[env:esp8266]");
  TEST_ASSERT_FALSE_MESSAGE(env.empty(), "no [env:esp8266] section");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(env, blk), "...and it is in [env:esp8266] (the *_lab/_test/_olostep ESP8266 envs extend it)");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(env, fre), "...likewise the free gate");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(iniSection(ini, "[embedded]"), "HEAP_GATE_OTA"), "not in the shared [embedded] flags");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(iniSection(ini, "[esp32common]"), "HEAP_GATE_OTA"), "not in the ESP32 family flags");
}

void test_config_h_keeps_the_16384_numbers_and_defaults_the_new_ones_to_them() {
  std::string cfg;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("include/config.h", cfg), "cannot read include/config.h");
  TEST_ASSERT_EQUAL_INT(1, countOf(cfg, "#define HEAP_GATE_OTA 20000"));
  TEST_ASSERT_EQUAL_INT(1, countOf(cfg, "#define HEAP_GATE_OTA_BLOCK 36864"));
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(cfg, "#define HEAP_GATE_OTA_MANIFEST HEAP_GATE_OTA\n"),
                                "any build that does not set the manifest gate keeps the old free gate");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(cfg, "#define HEAP_GATE_OTA_MANIFEST_BLOCK HEAP_GATE_OTA_BLOCK\n"),
                                "any build that does not set the manifest gate keeps the old block gate");
}

void test_checkNow_gates_with_the_manifest_numbers_and_nothing_else_changed() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/core/ota_client.cpp", src), "cannot read src/core/ota_client.cpp");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "fry::waitForHeapGate(HEAP_GATE_OTA_MANIFEST, HEAP_GATE_OTA_MANIFEST_BLOCK, 1)"),
                                "checkNow()'s manifest gate uses the measured numbers");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(src, "waitForHeapGate(HEAP_GATE_OTA, HEAP_GATE_OTA_BLOCK, 1)"),
                                "...and not the 16384/512 ones");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "fry::waitForHeapGate(HEAP_GATE_OTA, minBlock)"),
                                "the image download's gate is not touched by this change");
  TEST_ASSERT_EQUAL_INT_MESSAGE(
      1, countOf(src, "static_assert(HEAP_GATE_OTA_MANIFEST_BLOCK == fry::ota_heap::kManifestGateBlock"),
      "the -D must equal the table's derived value");
  TEST_ASSERT_EQUAL_INT_MESSAGE(
      1, countOf(src, "static_assert(HEAP_GATE_OTA_MANIFEST == fry::ota_heap::kManifestGateFree"),
      "the -D must equal the table's derived value");
}

void test_beginHttpsUrl_takes_its_floors_from_the_session_it_sizes() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/esp8266/http_tls.cpp", src), "cannot read src/esp8266/http_tls.cpp");
  TEST_ASSERT_EQUAL_INT_MESSAGE(
      1, countOf(src, "const uint32_t gateFree = smallReply ? HEAP_GATE_OTA_MANIFEST : HEAP_GATE_OTA;"),
      "the manifest (small reply, Medium session) is judged by the manifest gate, the download by the old one");
  TEST_ASSERT_EQUAL_INT_MESSAGE(
      1, countOf(src, "const uint32_t gateBlock = smallReply ? HEAP_GATE_OTA_MANIFEST_BLOCK : HEAP_GATE_OTA_BLOCK;"),
      "likewise the block floor");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "fry::tlsFloorsAtBegin(gateFree, gateBlock, mflnProbeWorthwhile)"),
                                "the floors still come from tlsFloorsAtBegin()");
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_gate_is_the_measured_need_plus_margin_plus_what_the_constructors_take);
  RUN_TEST(test_seen_from_after_the_constructors_the_gate_is_exactly_need_plus_margin);
  RUN_TEST(test_the_gate_refuses_every_heap_whose_post_constructor_block_is_inside_need_plus_margin);
  RUN_TEST(test_the_gate_passes_from_need_plus_margin_up);
  RUN_TEST(test_the_gate_is_a_function_of_the_measurement_not_of_the_old_constant);
  RUN_TEST(test_only_env_esp8266_carries_the_new_gate_numbers);
  RUN_TEST(test_config_h_keeps_the_16384_numbers_and_defaults_the_new_ones_to_them);
  RUN_TEST(test_checkNow_gates_with_the_manifest_numbers_and_nothing_else_changed);
  RUN_TEST(test_beginHttpsUrl_takes_its_floors_from_the_session_it_sizes);
  return UNITY_END();
}
