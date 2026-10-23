// The ESP8266 OTA manifest check's heap gate is derived from a MEASURED need, in the units the gate samples.
//
// Bench 2026-10-22 (decoy sweep C2, lo/c1-c2a-123102.lines.txt + lo/c1-c2b-123905.lines.txt): the 3-hop GitHub manifest
// GET on the 8192/512 session passed 3/3 with the largest free block forced (after the TLS clients exist) to 23992, 21992,
// 19992 and 18992 B, and FAILED at 17992 (-1 x2, one OOM panic: `last failed alloc call: 402177BB(1496)` =
// BearSSL::WiFiClientSecureCtx::_installClientX509Validator()). Need: post-constructor blk in (17992, 18992].
//
// checkNow() samples BEFORE its clients exist, so the gate is the need (upper bound) + a 4096 B margin + what the
// constructors take (BearSSL stack thunk 6208 + clients block 512): 29808 blk, 29976 free (lib/fry_core/ota_heap_budget.h).
// The 16384/512 numbers (HEAP_GATE_OTA 20000 / HEAP_GATE_OTA_BLOCK 36864, include/config.h) are unchanged for every other
// chip and for the MFLN-probe path.
//
// The image download (Big 16384/512, no smaller buffer can carry its 16400 B records) is derived the same way from the
// whole-stream sweeps dl-30 .. dl-32b2 (worst session use at the stream gate 25560 + the stream gate 5376; PASS 3/3 at every
// largest-block target from 31000 down to 26000): begin-time floors 35032 free / 30096 block, i.e. 41752 / 36816 in the
// pre-constructor units (sweep C, GET only, had given 32704 / 32088, i.e. 39424 / 38808). The post-connect gate of
// downloadAndApply() used to demand 20000 free and a
// 36864 B contiguous block AFTER BearSSL had allocated its 16 KB buffer: it could not pass on this chip; it now asks only
// for what streaming still allocates (kStreamGateFree).
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

void test_the_download_gate_is_derived_the_same_way_from_the_16384_sweep() {
  TEST_ASSERT_EQUAL_UINT32(26000, budget::kDownloadNeedBlk);   // whole-stream sweep dl-32b2: PASS 3/3 at every target down to it
  TEST_ASSERT_EQUAL_UINT32(30936, budget::kDownloadNeedFree);  // worst session use at the stream gate 25560 + 5376
  TEST_ASSERT_EQUAL_UINT32(25000, budget::kDownloadFailBlk);   // 2/3
  TEST_ASSERT_EQUAL_UINT32(26000 + 4096 + 6208 + 512, budget::kDownloadGateBlock);
  TEST_ASSERT_EQUAL_UINT32(36816, budget::kDownloadGateBlock);
  TEST_ASSERT_EQUAL_UINT32(30936 + 4096 + 6208 + 512, budget::kDownloadGateFree);
  TEST_ASSERT_EQUAL_UINT32(41752, budget::kDownloadGateFree);
  const fry::TlsFloors f = fry::tlsFloorsAtBegin(budget::kDownloadGateFree, budget::kDownloadGateBlock, false);
  TEST_ASSERT_EQUAL_UINT32(26000 + 4096, f.block);      // 30096
  TEST_ASSERT_EQUAL_UINT32(30936 + 4096, f.freeTotal);  // 35032
}

void test_the_big_session_is_refused_in_the_crash_band_and_just_above_it() {
  // Begin-time sample (after the constructors) for the download: the 16384/512 session. Every post-ctor block the sweep
  // crashed at, the one it only half survived, and the lowest one it passed 3/3 are all below need + margin.
  const fry::TlsFloors f = fry::tlsFloorsAtBegin(budget::kDownloadGateFree, budget::kDownloadGateBlock, false);
  const uint32_t blocks[] = {23992, 25992, 27992, 28912, 32087};
  for (uint32_t b : blocks) {
    const fry::TlsPlan p = fry::planTls({b + 168, b}, f.freeTotal, f.block, /*peerMightHonourMfln=*/false);
    TEST_ASSERT_EQUAL_INT_MESSAGE(static_cast<int>(fry::TlsSizing::Refuse), static_cast<int>(p.sizing),
                                  "a Big session below need + margin must be refused, never 512/512");
  }
  const fry::TlsPlan ok = fry::planTls({35032, 30096}, f.freeTotal, f.block, false);
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TlsSizing::Big), static_cast<int>(ok.sizing));
}

void test_the_download_floors_are_higher_than_the_manifest_floors() {
  // Same chip, same hosts: the 16 KB buffer costs more than the 8 KB one, so its floors must be the higher.
  TEST_ASSERT_TRUE(budget::kDownloadGateBlock > budget::kManifestGateBlock);
  TEST_ASSERT_TRUE(budget::kDownloadGateFree > budget::kManifestGateFree);
  // The old 36864 was a field-crash number the gate started from, below need + margin; the whole-stream measurement puts the gate 48 B below it.
  TEST_ASSERT_EQUAL_UINT32(36864 - 48, budget::kDownloadGateBlock);
}

void test_the_stream_gate_is_what_streaming_allocates_plus_margin() {
  TEST_ASSERT_EQUAL_UINT32(1024 + 256, budget::kStreamNeedBytes);  // download buffer + the Updater's smallest buffer
  TEST_ASSERT_EQUAL_UINT32(1024 + 256 + 4096, budget::kStreamGateFree);
  TEST_ASSERT_EQUAL_UINT32(5376, budget::kStreamGateFree);
  // At the lowest heap the download is admitted (begin-time free 32704), the session leaves this much free after the connect
  // (sweep C at post-ctor 27992: 5592 B free at the end of the last hop, plus the 4096 B of margin the admission adds):
  const uint32_t freeAfterConnectAtAdmission = 5592 + 4096;
  TEST_ASSERT_TRUE_MESSAGE(freeAfterConnectAtAdmission >= budget::kStreamGateFree,
                           "a download admitted at its floor must still pass the post-connect gate");
  // ...and the old post-connect gate (20000 free) could never pass on this chip: nothing admitted ever has 20000 free
  // once the session holds 21 KB of a ~40 KB heap.
  TEST_ASSERT_TRUE(freeAfterConnectAtAdmission < 20000);
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
  const std::string dlb = "-DHEAP_GATE_OTA_DOWNLOAD_BLOCK=36816";
  const std::string dlf = "-DHEAP_GATE_OTA_DOWNLOAD=41752";
  const std::string stf = "-DHEAP_GATE_OTA_STREAM=5376";
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(ini, blk), "the block gate is set once in the whole file");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(ini, fre), "the free gate is set once in the whole file");
  const std::string env = iniSection(ini, "[env:esp8266]");
  TEST_ASSERT_FALSE_MESSAGE(env.empty(), "no [env:esp8266] section");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(env, blk), "...and it is in [env:esp8266] (the *_lab/_test/_olostep ESP8266 envs extend it)");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(env, fre), "...likewise the free gate");
  const std::string* more[] = {&dlb, &dlf, &stf};
  for (const std::string* m : more) {
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(ini, *m), "each download/stream gate number is set once in the whole file");
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(env, *m), "...in [env:esp8266]");
  }
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
  TEST_ASSERT_EQUAL_INT(1, countOf(cfg, "#define HEAP_GATE_OTA_DOWNLOAD HEAP_GATE_OTA\n"));
  TEST_ASSERT_EQUAL_INT(1, countOf(cfg, "#define HEAP_GATE_OTA_DOWNLOAD_BLOCK HEAP_GATE_OTA_BLOCK\n"));
  TEST_ASSERT_EQUAL_INT(1, countOf(cfg, "#define HEAP_GATE_OTA_STREAM HEAP_GATE_OTA\n"));
}

void test_checkNow_gates_with_the_manifest_numbers_and_nothing_else_changed() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/core/ota_client.cpp", src), "cannot read src/core/ota_client.cpp");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "fry::waitForHeapGate(HEAP_GATE_OTA_MANIFEST, HEAP_GATE_OTA_MANIFEST_BLOCK, 1)"),
                                "checkNow()'s manifest gate uses the measured numbers");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(src, "waitForHeapGate(HEAP_GATE_OTA, HEAP_GATE_OTA_BLOCK, 1)"),
                                "...and not the 16384/512 ones");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "fry::waitForHeapGate(minFree, minBlock)"),
                                "the post-connect gate takes its floors from the lines above it");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(src, "waitForHeapGate(HEAP_GATE_OTA, minBlock)"),
                                "...not the 20000 / 36864 pair it asked for after BearSSL had allocated its buffer");
  TEST_ASSERT_EQUAL_INT_MESSAGE(
      1, countOf(src, "static_assert(HEAP_GATE_OTA_MANIFEST_BLOCK == fry::ota_heap::kManifestGateBlock"),
      "the -D must equal the table's derived value");
  TEST_ASSERT_EQUAL_INT_MESSAGE(
      1, countOf(src, "static_assert(HEAP_GATE_OTA_MANIFEST == fry::ota_heap::kManifestGateFree"),
      "the -D must equal the table's derived value");
  TEST_ASSERT_EQUAL_INT(1, countOf(src, "static_assert(HEAP_GATE_OTA_DOWNLOAD_BLOCK == fry::ota_heap::kDownloadGateBlock"));
  TEST_ASSERT_EQUAL_INT(1, countOf(src, "static_assert(HEAP_GATE_OTA_DOWNLOAD == fry::ota_heap::kDownloadGateFree"));
  TEST_ASSERT_EQUAL_INT(1, countOf(src, "static_assert(HEAP_GATE_OTA_STREAM == fry::ota_heap::kStreamGateFree"));
  // ESP8266: no contiguous block after the connect, and the stream floor only for https (plain http opens no session).
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "const uint32_t minFree = isHttps ? HEAP_GATE_OTA_STREAM : HEAP_GATE_OTA;"),
                                "ESP8266: the post-connect free floor is the stream's, for https");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "const uint32_t minFree = HEAP_GATE_OTA;"),
                                "every other chip keeps its free floor");
}

void test_beginHttpsUrl_takes_its_floors_from_the_session_it_sizes() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/esp8266/http_tls.cpp", src), "cannot read src/esp8266/http_tls.cpp");
  // Three sessions: the manifest (Medium), the image download (Big, a peer that does not honour MFLN), and the rest
  // (a peer that may honour MFLN: its 32 KB probe allocates after the constructor, the old numbers are its own).
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "uint32_t gateFree = HEAP_GATE_OTA;"), "the probe path keeps the old floors");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "uint32_t gateBlock = HEAP_GATE_OTA_BLOCK;"), "likewise the block floor");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "if (smallReply) {"), "the manifest session");
  TEST_ASSERT_EQUAL_INT(1, countOf(src, "gateFree = HEAP_GATE_OTA_MANIFEST;"));
  TEST_ASSERT_EQUAL_INT(1, countOf(src, "gateBlock = HEAP_GATE_OTA_MANIFEST_BLOCK;"));
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "} else if (!mflnProbeWorthwhile) {"), "the download session");
  TEST_ASSERT_EQUAL_INT(1, countOf(src, "gateFree = HEAP_GATE_OTA_DOWNLOAD;"));
  TEST_ASSERT_EQUAL_INT(1, countOf(src, "gateBlock = HEAP_GATE_OTA_DOWNLOAD_BLOCK;"));
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
  RUN_TEST(test_the_download_gate_is_derived_the_same_way_from_the_16384_sweep);
  RUN_TEST(test_the_big_session_is_refused_in_the_crash_band_and_just_above_it);
  RUN_TEST(test_the_download_floors_are_higher_than_the_manifest_floors);
  RUN_TEST(test_the_stream_gate_is_what_streaming_allocates_plus_margin);
  RUN_TEST(test_only_env_esp8266_carries_the_new_gate_numbers);
  RUN_TEST(test_config_h_keeps_the_16384_numbers_and_defaults_the_new_ones_to_them);
  RUN_TEST(test_checkNow_gates_with_the_manifest_numbers_and_nothing_else_changed);
  RUN_TEST(test_beginHttpsUrl_takes_its_floors_from_the_session_it_sizes);
  return UNITY_END();
}
