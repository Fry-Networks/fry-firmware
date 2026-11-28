// Fleet-safety scope of the boot probe (unified default images): a miner with unknown wiring only ever gets the
// bounded I2C probe on the default I2C pins. SPI / TFT / XPT2046 probing needs a board preset or an explicit
// display_mode (screen / touch). NONE leaves nothing to poll. S3 forbidden pins (GPIO19-20, 26-37) are never used.
#include <unity.h>

#include "../../include/fry_config_store.h"
#include "../../lib/fry_ui/display_presets.h"
#include "../support/display_mock.h"

using namespace fry;
using namespace fry::disp;
using fry::cfg::DisplayMode;

void setUp(void) {}
void tearDown(void) {}

namespace {
struct CountHook : BusHook {
  int selects = 0, releases = 0;
  void select(uint8_t, const BoardPins&) override { selects++; }
  void release(const BoardPins&) override { releases++; }
};

void cydPanel(disptest::MockBus& b) {
  b.tftMode = 1;
  b.idD3[0] = 0x00; b.idD3[1] = 0x93; b.idD3[2] = 0x41;
  b.id04[0] = 0x00; b.id04[1] = 0x93; b.id04[2] = 0x41;
  b.xptPresent = true;
}
const uint8_t kEsp32Cands[2] = {PRESET_ESP32_OLED, PRESET_ESP32_CYD};
const uint8_t kS3Cands[3] = {PRESET_ESP32S3_CAPTOUCH, PRESET_ESP32S3_TFT, PRESET_ESP32S3_OLED};
}  // namespace

void test_scope_policy() {
  TEST_ASSERT_EQUAL_UINT8((uint8_t)ProbeScope::I2cDefault, (uint8_t)probeScope(0, (uint8_t)DisplayMode::Auto));
  TEST_ASSERT_EQUAL_UINT8((uint8_t)ProbeScope::Off, (uint8_t)probeScope(0, (uint8_t)DisplayMode::None));
  TEST_ASSERT_EQUAL_UINT8((uint8_t)ProbeScope::Off, (uint8_t)probeScope(PRESET_ESP32_CYD, (uint8_t)DisplayMode::None));
  TEST_ASSERT_EQUAL_UINT8((uint8_t)ProbeScope::Preset, (uint8_t)probeScope(PRESET_ESP32_CYD, (uint8_t)DisplayMode::Auto));
  TEST_ASSERT_EQUAL_UINT8((uint8_t)ProbeScope::Candidates, (uint8_t)probeScope(0, (uint8_t)DisplayMode::Screen));
  TEST_ASSERT_EQUAL_UINT8((uint8_t)ProbeScope::Candidates, (uint8_t)probeScope(0, (uint8_t)DisplayMode::Touch));
}

void test_no_preset_auto_issues_no_spi_ops_even_with_a_cyd_attached() {
  disptest::MockBus b;
  cydPanel(b);  // a CYD is wired up, but nothing says so
  Info best;
  BoardPins pins;
  bool have = false;
  const uint8_t r = bootProbe(0, (uint8_t)DisplayMode::Auto, PRESET_ESP32_OLED, kEsp32Cands, 2, b, nullptr, 400, best, pins, have);
  TEST_ASSERT_EQUAL_UINT8(0, r);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_NONE, best.mode);
  TEST_ASSERT_FALSE(have);
  TEST_ASSERT_EQUAL_INT(0, b.spiReads);
  TEST_ASSERT_EQUAL_INT(0, b.pullSets);
  TEST_ASSERT_EQUAL_INT(0, b.xptSamples);
  // only the default I2C pins 21 / 22 were ever used
  for (int i = 0; i < b.nPins; i++) TEST_ASSERT_TRUE(b.pinsUsed[i] == 21 || b.pinsUsed[i] == 22);
  TEST_ASSERT_TRUE(b.i2cBegins >= 1);
}

void test_no_preset_auto_finds_i2c_oled_on_default_pins() {
  disptest::MockBus b;
  b.oled3C = true;
  Info best;
  BoardPins pins;
  bool have = false;
  const uint8_t r = bootProbe(0, (uint8_t)DisplayMode::Auto, PRESET_ESP32_OLED, kEsp32Cands, 2, b, nullptr, 400, best, pins, have);
  TEST_ASSERT_EQUAL_UINT8(PRESET_ESP32_OLED, r);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_SCREEN_ONLY, best.mode);
  TEST_ASSERT_TRUE(have);
  TEST_ASSERT_EQUAL_INT(-1, pins.spiSck);
  TEST_ASSERT_EQUAL_INT(-1, pins.tftCs);
  TEST_ASSERT_EQUAL_INT(0, b.spiReads);
  TEST_ASSERT_EQUAL_INT(0, b.xptSamples);
}

void test_none_result_means_resolve_none_and_no_polling() {
  disptest::MockBus b;  // nothing wired
  Info best;
  BoardPins pins;
  bool have = false;
  bootProbe(0, (uint8_t)DisplayMode::Auto, PRESET_ESP32_OLED, kEsp32Cands, 2, b, nullptr, 400, best, pins, have);
  const Info res = resolve(best, (uint8_t)DisplayMode::Auto, 0);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_NONE, res.mode);
  TEST_ASSERT_FALSE(shouldPoll(res.mode));
  TEST_ASSERT_FALSE(wantsTouchPolling(res.mode));
  TEST_ASSERT_EQUAL_UINT32(0, loopIntervalMs(res.mode));
}

void test_display_mode_none_touches_nothing_at_all() {
  disptest::MockBus b;
  cydPanel(b);
  b.oled3C = true;
  Info best;
  BoardPins pins;
  bool have = false;
  bootProbe(PRESET_ESP32_CYD, (uint8_t)DisplayMode::None, PRESET_ESP32_OLED, kEsp32Cands, 2, b, nullptr, 400, best, pins, have);
  TEST_ASSERT_EQUAL_INT(0, b.calls);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_NONE, best.mode);
}

void test_preset_enables_spi_probe() {
  disptest::MockBus b;
  cydPanel(b);
  CountHook h;
  Info best;
  BoardPins pins;
  bool have = false;
  const uint8_t r = bootProbe(PRESET_ESP32_CYD, (uint8_t)DisplayMode::Auto, PRESET_ESP32_OLED, kEsp32Cands, 2, b, &h, 400, best, pins, have);
  TEST_ASSERT_EQUAL_UINT8(PRESET_ESP32_CYD, r);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_TOUCHSCREEN, best.mode);
  TEST_ASSERT_TRUE(b.spiReads > 0);
  TEST_ASSERT_TRUE(b.xptSamples > 0);
  TEST_ASSERT_EQUAL_INT(1, h.selects);
}

void test_explicit_screen_mode_without_preset_tries_candidates() {
  disptest::MockBus b;
  cydPanel(b);
  Info best;
  BoardPins pins;
  bool have = false;
  const uint8_t r = bootProbe(0, (uint8_t)DisplayMode::Touch, PRESET_ESP32_OLED, kEsp32Cands, 2, b, nullptr, 400, best, pins, have);
  TEST_ASSERT_EQUAL_UINT8(PRESET_ESP32_CYD, r);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_TOUCHSCREEN, best.mode);
  TEST_ASSERT_TRUE(b.spiReads > 0);
}

void test_s3_auto_never_touches_forbidden_or_spi_pins() {
  disptest::MockBus b;
  cydPanel(b);
  Info best;
  BoardPins pins;
  bool have = false;
  bootProbe(0, (uint8_t)DisplayMode::Auto, PRESET_ESP32S3_OLED, kS3Cands, 3, b, nullptr, 400, best, pins, have);
  TEST_ASSERT_EQUAL_INT(0, b.spiReads);
  TEST_ASSERT_EQUAL_INT(0, b.xptSamples);
  for (int i = 0; i < b.nPins; i++) {
    const int p = b.pinsUsed[i];
    TEST_ASSERT_TRUE(p == 8 || p == 9);
    TEST_ASSERT_FALSE(p == 19 || p == 20 || (p >= 26 && p <= 37));
  }
}

void test_s3_explicit_candidates_never_touch_forbidden_pins() {
  disptest::MockBus b;
  b.everythingTimesOut = false;
  Info best;
  BoardPins pins;
  bool have = false;
  bootProbe(0, (uint8_t)DisplayMode::Screen, PRESET_ESP32S3_OLED, kS3Cands, 3, b, nullptr, 400, best, pins, have);
  for (int i = 0; i < b.nPins; i++) {
    const int p = b.pinsUsed[i];
    TEST_ASSERT_FALSE(p == 19 || p == 20 || (p >= 26 && p <= 37));
  }
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_scope_policy);
  RUN_TEST(test_no_preset_auto_issues_no_spi_ops_even_with_a_cyd_attached);
  RUN_TEST(test_no_preset_auto_finds_i2c_oled_on_default_pins);
  RUN_TEST(test_none_result_means_resolve_none_and_no_polling);
  RUN_TEST(test_display_mode_none_touches_nothing_at_all);
  RUN_TEST(test_preset_enables_spi_probe);
  RUN_TEST(test_explicit_screen_mode_without_preset_tries_candidates);
  RUN_TEST(test_s3_auto_never_touches_forbidden_or_spi_pins);
  RUN_TEST(test_s3_explicit_candidates_never_touch_forbidden_pins);
  return UNITY_END();
}
