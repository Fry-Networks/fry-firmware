// Regression: an ESP32 could never take an OTA update.
//
// The OTA download gate demanded HEAP_GATE_OTA_BLOCK (36864) bytes of CONTIGUOUS heap for any
// https download. That constant was derived from ESP8266 BearSSL, which allocates a single
// 16384-byte rx buffer as one block. The gate runs AFTER the HTTPS GET has returned headers, so
// on ESP32 it measures the heap while mbedtls already holds its working buffers -- and fails.
//
// Measured on a T-Beam (COM14) running a build that believed it was 0.2.9 against a 0.3.0
// manifest: "ota: manifest check cur=0.2.9 latest=0.3.0 action=update" followed by
// "ota: heap gate failed", while the health line reported blk=110580 idle. Every ESP32 in the
// field would have been unable to self-update to the fix they needed.
#include <unity.h>

#include "heap_gate.h"

namespace {

// The real configured value from include/config.h.
constexpr uint32_t kConfiguredBlock = 36864;

void test_esp8266_https_still_requires_the_contiguous_block() {
    // The ESP8266 evidence is unchanged and must stay enforced: a board with 42,712 free but a
    // 34,152-byte largest block really did crash.
    TEST_ASSERT_EQUAL_UINT32(
        kConfiguredBlock, fry::otaMinContiguousBlock(true, true, kConfiguredBlock));
}

void test_esp32_https_requires_no_contiguous_block() {
    // mbedtls has already allocated by the time the gate runs; there is no second 16 KB buffer.
    TEST_ASSERT_EQUAL_UINT32(0, fry::otaMinContiguousBlock(true, false, kConfiguredBlock));
}

void test_plain_http_never_requires_the_contiguous_block() {
    // No TLS buffer at all on either chip. Already true before this change; pinned so it stays.
    TEST_ASSERT_EQUAL_UINT32(0, fry::otaMinContiguousBlock(false, true, kConfiguredBlock));
    TEST_ASSERT_EQUAL_UINT32(0, fry::otaMinContiguousBlock(false, false, kConfiguredBlock));
}

void test_the_measured_esp32_heap_now_passes_the_gate() {
    // Real numbers from the reproduction: 149,908 free, 110,580 largest block, 20000 total-free
    // minimum. With the contiguous requirement correctly zero for ESP32, this passes.
    const uint32_t minBlock = fry::otaMinContiguousBlock(true, false, kConfiguredBlock);
    TEST_ASSERT_TRUE(fry::heapGatePass(149908, 110580, 20000, minBlock));
}

void test_a_genuinely_exhausted_esp32_heap_is_still_refused() {
    // Dropping the contiguous requirement must not disable the gate: total free still governs.
    const uint32_t minBlock = fry::otaMinContiguousBlock(true, false, kConfiguredBlock);
    TEST_ASSERT_FALSE(fry::heapGatePass(9000, 8000, 20000, minBlock));
}

void test_the_esp8266_crash_case_is_still_refused() {
    // 42,712 free / 34,152 largest block -- the exact state that crashed a board in the field.
    const uint32_t minBlock = fry::otaMinContiguousBlock(true, true, kConfiguredBlock);
    TEST_ASSERT_FALSE(fry::heapGatePass(42712, 34152, 20000, minBlock));
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}

void tearDown() {}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_esp8266_https_still_requires_the_contiguous_block);
    RUN_TEST(test_esp32_https_requires_no_contiguous_block);
    RUN_TEST(test_plain_http_never_requires_the_contiguous_block);
    RUN_TEST(test_the_measured_esp32_heap_now_passes_the_gate);
    RUN_TEST(test_a_genuinely_exhausted_esp32_heap_is_still_refused);
    RUN_TEST(test_the_esp8266_crash_case_is_still_refused);
    return UNITY_END();
}
