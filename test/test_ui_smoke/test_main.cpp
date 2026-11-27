// Smoke test proving the native_ui env runs: new headers compile on the host, FNV snapshot hash is
// deterministic and sensitive to its fields, miner-key validator follows PROTOCOL.md 11.1.
#include <string.h>
#include <unity.h>

#include "config_snapshot.h"
#include "fry_display_hal.h"
#include "fry_touch_ui.h"

using namespace fry;

void setUp() {}
void tearDown() {}

static cfg::Snapshot empty() {
  cfg::Snapshot s;
  memset(&s, 0, sizeof s);
  return s;
}

void test_enum_values() {
  TEST_ASSERT_EQUAL_UINT8(0, (uint8_t)cfg::DisplayMode::Auto);
  TEST_ASSERT_EQUAL_UINT8(3, (uint8_t)cfg::DisplayMode::Touch);
  TEST_ASSERT_EQUAL_UINT8(2, (uint8_t)disp::FRY_DISP_TOUCHSCREEN);
  TEST_ASSERT_EQUAL_UINT8(6, (uint8_t)ui::MinerState::Error);
}

void test_empty_snapshot_hash_is_deterministic() {
  const cfg::Snapshot a = empty(), b = empty();
  TEST_ASSERT_EQUAL_UINT32(cfg::snapshotGeneration(a), cfg::snapshotGeneration(b));
  TEST_ASSERT_NOT_EQUAL(0u, cfg::snapshotGeneration(a));
}

void test_hash_ignores_generation_and_tracks_fields() {
  cfg::Snapshot a = empty(), b = empty();
  b.generation = 99;
  TEST_ASSERT_EQUAL_UINT32(cfg::snapshotGeneration(a), cfg::snapshotGeneration(b));
  b = empty();
  strcpy(b.ssid, "home");
  TEST_ASSERT_NOT_EQUAL(cfg::snapshotGeneration(a), cfg::snapshotGeneration(b));
  b = empty();
  b.displayMode = cfg::DisplayMode::Touch;
  TEST_ASSERT_NOT_EQUAL(cfg::snapshotGeneration(a), cfg::snapshotGeneration(b));
  b = empty();
  b.provDone = true;
  TEST_ASSERT_NOT_EQUAL(cfg::snapshotGeneration(a), cfg::snapshotGeneration(b));
}

void test_valid_miner_key() {
  TEST_ASSERT_TRUE(cfg::validMinerKey("FEM-0123456789ABCDEF0123456789ABCDEF"));
  TEST_ASSERT_TRUE(cfg::validMinerKey("FEM-0123456789abcdef0123456789abcdef"));
  TEST_ASSERT_FALSE(cfg::validMinerKey("IOT-0123456789ABCDEF0123456789ABCDEF"));
  TEST_ASSERT_FALSE(cfg::validMinerKey("FEM-0123456789ABCDEF0123456789ABCDE"));
  TEST_ASSERT_FALSE(cfg::validMinerKey("FEM-0123456789ABCDEF0123456789ABCDEF0"));
  TEST_ASSERT_FALSE(cfg::validMinerKey("FEM-0123456789ABCDEF0123456789ABCDE!"));
  TEST_ASSERT_FALSE(cfg::validMinerKey(""));
  TEST_ASSERT_FALSE(cfg::validMinerKey(0));
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_enum_values);
  RUN_TEST(test_empty_snapshot_hash_is_deterministic);
  RUN_TEST(test_hash_ignores_generation_and_tracks_fields);
  RUN_TEST(test_valid_miner_key);
  return UNITY_END();
}
