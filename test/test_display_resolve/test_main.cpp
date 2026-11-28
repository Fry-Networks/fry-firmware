// resolve(): config override + board preset; NONE mode zero polling; presets; boot log line; autodetect.
#include <stdio.h>
#include <unity.h>

#include "../../include/fry_config_store.h"
#include "../../lib/fry_ui/display_presets.h"
#include "../support/display_mock.h"

using namespace fry;
using namespace fry::disp;
using fry::cfg::DisplayMode;

void setUp(void) {}
void tearDown(void) {}

static Info probed(Mode m, Panel p, Touch t) {
  Info i;
  memset(&i, 0, sizeof(i));
  i.mode = m;
  i.panel = p;
  i.touch = t;
  return i;
}

void test_auto_follows_probe() {
  Info r = resolve(probed(FRY_DISP_TOUCHSCREEN, Panel::ILI9341_240x320, Touch::XPT2046), (uint8_t)DisplayMode::Auto, 0);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_TOUCHSCREEN, r.mode);
  r = resolve(probed(FRY_DISP_SCREEN_ONLY, Panel::SSD1306_128x64, Touch::None), (uint8_t)DisplayMode::Auto, 0);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_SCREEN_ONLY, r.mode);
  r = resolve(probed(FRY_DISP_NONE, Panel::None, Touch::None), (uint8_t)DisplayMode::Auto, 0);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_NONE, r.mode);
}

void test_none_override_wins_over_everything() {
  Info r = resolve(probed(FRY_DISP_TOUCHSCREEN, Panel::ILI9341_240x320, Touch::XPT2046), (uint8_t)DisplayMode::None, PRESET_ESP32_CYD);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_NONE, r.mode);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::None, (uint8_t)r.panel);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::None, (uint8_t)r.touch);
}

void test_screen_override_drops_touch() {
  Info r = resolve(probed(FRY_DISP_TOUCHSCREEN, Panel::ILI9341_240x320, Touch::XPT2046), (uint8_t)DisplayMode::Screen, 0);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_SCREEN_ONLY, r.mode);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::None, (uint8_t)r.touch);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::ILI9341_240x320, (uint8_t)r.panel);
}

void test_screen_override_with_nothing_probed_and_no_preset_stays_none() {
  Info r = resolve(probed(FRY_DISP_NONE, Panel::None, Touch::None), (uint8_t)DisplayMode::Screen, 0);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_NONE, r.mode);
}

void test_preset_supplies_hardware_when_probe_finds_nothing() {
  Info r = resolve(probed(FRY_DISP_NONE, Panel::None, Touch::None), (uint8_t)DisplayMode::Auto, PRESET_ESP32_CYD);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_TOUCHSCREEN, r.mode);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::ILI9341_240x320, (uint8_t)r.panel);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::XPT2046, (uint8_t)r.touch);
  r = resolve(probed(FRY_DISP_NONE, Panel::None, Touch::None), (uint8_t)DisplayMode::Auto, PRESET_ESP32_OLED);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_SCREEN_ONLY, r.mode);
  TEST_ASSERT_TRUE(r.mono);
}

void test_touch_override_without_touch_hardware_falls_back_to_screen() {
  Info r = resolve(probed(FRY_DISP_SCREEN_ONLY, Panel::ILI9341_240x320, Touch::None), (uint8_t)DisplayMode::Touch, 0);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_SCREEN_ONLY, r.mode);
  r = resolve(probed(FRY_DISP_SCREEN_ONLY, Panel::ILI9341_240x320, Touch::None), (uint8_t)DisplayMode::Touch, PRESET_ESP32_CYD);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_TOUCHSCREEN, r.mode);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::XPT2046, (uint8_t)r.touch);
}

void test_unknown_preset_ignored() {
  Info r = resolve(probed(FRY_DISP_NONE, Panel::None, Touch::None), (uint8_t)DisplayMode::Auto, 200);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_NONE, r.mode);
}

void test_none_mode_zero_polling() {
  TEST_ASSERT_FALSE(shouldPoll(FRY_DISP_NONE));
  TEST_ASSERT_EQUAL_UINT32(0, loopIntervalMs(FRY_DISP_NONE));
  TEST_ASSERT_TRUE(shouldPoll(FRY_DISP_SCREEN_ONLY));
  TEST_ASSERT_TRUE(shouldPoll(FRY_DISP_TOUCHSCREEN));
  TEST_ASSERT_TRUE(loopIntervalMs(FRY_DISP_TOUCHSCREEN) > 0);
  TEST_ASSERT_FALSE(wantsTouchPolling(FRY_DISP_SCREEN_ONLY));
  TEST_ASSERT_TRUE(wantsTouchPolling(FRY_DISP_TOUCHSCREEN));
}

void test_s3_forbidden_list_is_exactly_19_20_and_26_to_37() {
  TEST_ASSERT_EQUAL_UINT32(14, kEsp32S3ForbiddenCount);
  for (int p = 0; p < 50; p++) {
    const bool want = p == 19 || p == 20 || (p >= 26 && p <= 37);
    bool got = false;
    for (size_t i = 0; i < kEsp32S3ForbiddenCount; i++) got |= kEsp32S3Forbidden[i] == p;
    TEST_ASSERT_EQUAL_INT_MESSAGE(want, got, "S3 forbidden set wrong");
  }
}

void test_s3_presets_use_no_forbidden_pin() {
  const uint8_t s3[2] = {PRESET_ESP32S3_TFT, PRESET_ESP32S3_CAPTOUCH};
  for (int k = 0; k < 2; k++) {
    BoardPins p;
    TEST_ASSERT_TRUE(presetPins(s3[k], p));
    TEST_ASSERT_EQUAL_PTR(kEsp32S3Forbidden, p.forbidden);
    const int all[] = {p.sda, p.scl, p.spiSck, p.spiMosi, p.spiMiso, p.tftCs, p.tftDc, p.tftRst, p.tftBl, p.touchCs,
                       p.touchIrq, p.touchSda, p.touchScl, p.touchRst};
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++) {
      TEST_ASSERT_FALSE(all[i] == 19 || all[i] == 20 || (all[i] >= 26 && all[i] <= 37));
    }
    TEST_ASSERT_TRUE(pinsAllowed(p));
  }
}

void test_pin_forbidden_helper() {
  BoardPins p;
  presetPins(PRESET_ESP32S3_TFT, p);
  TEST_ASSERT_TRUE(pinForbidden(p, 19));
  TEST_ASSERT_TRUE(pinForbidden(p, 20));
  TEST_ASSERT_TRUE(pinForbidden(p, 26));
  TEST_ASSERT_TRUE(pinForbidden(p, 37));
  TEST_ASSERT_FALSE(pinForbidden(p, 18));
  TEST_ASSERT_FALSE(pinForbidden(p, 21));
  TEST_ASSERT_FALSE(pinForbidden(p, 38));
  TEST_ASSERT_FALSE(pinForbidden(p, -1));  // unused pin is not a touch
  presetPins(PRESET_ESP32_CYD, p);         // classic ESP32: GPIO 6-11 are the flash bus
  TEST_ASSERT_TRUE(pinForbidden(p, 6));
  TEST_ASSERT_TRUE(pinForbidden(p, 11));
  TEST_ASSERT_FALSE(pinForbidden(p, 33));  // valid on classic ESP32 (CYD touch CS)
  presetPins(PRESET_RPIPICOW_OLED, p);
  TEST_ASSERT_TRUE(pinForbidden(p, 23));   // CYW43 radio pins
  TEST_ASSERT_TRUE(pinForbidden(p, 25));
}

void test_preset_info_matches_declared_hardware() {
  Info i;
  TEST_ASSERT_TRUE(presetInfo(PRESET_ESP32_CYD, i));
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_TOUCHSCREEN, i.mode);
  TEST_ASSERT_EQUAL_UINT16(240, i.width);
  TEST_ASSERT_EQUAL_UINT16(320, i.height);
  TEST_ASSERT_TRUE(presetInfo(PRESET_ESP32S3_CAPTOUCH, i));
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_TOUCHSCREEN, i.mode);
  TEST_ASSERT_TRUE(presetInfo(PRESET_ESP32S3_TFT, i));
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_SCREEN_ONLY, i.mode);
  TEST_ASSERT_FALSE(presetInfo(0, i));
  TEST_ASSERT_FALSE(presetInfo(PRESET_COUNT, i));
  // CYD bench pins (ESP32-2432S028R): TFT SCK14 MOSI13 MISO12 CS15 DC2 BL21, XPT2046 CS33 IRQ36
  BoardPins p;
  TEST_ASSERT_TRUE(presetPins(PRESET_ESP32_CYD, p));
  TEST_ASSERT_EQUAL_INT(14, p.spiSck);
  TEST_ASSERT_EQUAL_INT(13, p.spiMosi);
  TEST_ASSERT_EQUAL_INT(12, p.spiMiso);
  TEST_ASSERT_EQUAL_INT(15, p.tftCs);
  TEST_ASSERT_EQUAL_INT(2, p.tftDc);
  TEST_ASSERT_EQUAL_INT(21, p.tftBl);
  TEST_ASSERT_EQUAL_INT(33, p.touchCs);
  TEST_ASSERT_EQUAL_INT(36, p.touchIrq);
}

void test_boot_log_line_has_mode_drivers_pins() {
  Info i;
  presetInfo(PRESET_ESP32_CYD, i);
  BoardPins p;
  presetPins(PRESET_ESP32_CYD, p);
  char line[200];
  size_t n = formatBootLine(line, sizeof(line), i, "LovyanGFX", p);
  TEST_ASSERT_TRUE(n > 0 && n < sizeof(line));
  TEST_ASSERT_NOT_NULL(strstr(line, "[ui] mode=TOUCHSCREEN"));
  TEST_ASSERT_NOT_NULL(strstr(line, "panel=ILI9341"));
  TEST_ASSERT_NOT_NULL(strstr(line, "touch=XPT2046"));
  TEST_ASSERT_NOT_NULL(strstr(line, "drv=LovyanGFX"));
  TEST_ASSERT_NOT_NULL(strstr(line, "cs=15"));
  TEST_ASSERT_NOT_NULL(strstr(line, "tcs=33"));
  Info none = probed(FRY_DISP_NONE, Panel::None, Touch::None);
  formatBootLine(line, sizeof(line), none, "-", p);
  TEST_ASSERT_NOT_NULL(strstr(line, "mode=NONE"));
  // tiny buffer: truncates safely, always NUL terminated
  char small[12];
  formatBootLine(small, sizeof(small), i, "LovyanGFX", p);
  TEST_ASSERT_EQUAL_CHAR(0, small[sizeof(small) - 1]);
}

void test_autodetect_picks_first_working_candidate_and_stops() {
  disptest::MockBus b;
  b.oled3C = true;
  const uint8_t cands[2] = {PRESET_ESP32_OLED, PRESET_ESP32_CYD};
  Info best;
  const uint8_t chosen = autodetect(cands, 2, b, 400, best);
  TEST_ASSERT_EQUAL_UINT8(PRESET_ESP32_OLED, chosen);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_SCREEN_ONLY, best.mode);
  TEST_ASSERT_EQUAL_INT(0, b.spiReads);  // never touched the CYD pins after a hit
}

void test_autodetect_prefers_touchscreen_candidate_and_nothing_found_is_none() {
  disptest::MockBus b;
  b.tftMode = 1;
  b.idD3[0] = 0x00; b.idD3[1] = 0x93; b.idD3[2] = 0x41;
  b.id04[0] = 0x00; b.id04[1] = 0x93; b.id04[2] = 0x41;
  b.xptPresent = true;
  const uint8_t cands[2] = {PRESET_ESP32_OLED, PRESET_ESP32_CYD};
  Info best;
  TEST_ASSERT_EQUAL_UINT8(PRESET_ESP32_CYD, autodetect(cands, 2, b, 400, best));
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_TOUCHSCREEN, best.mode);
  disptest::MockBus empty;
  TEST_ASSERT_EQUAL_UINT8(0, autodetect(cands, 2, empty, 400, best));
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_NONE, best.mode);
}

void test_autodetect_total_budget_bounded() {
  disptest::MockBus b;
  b.everythingTimesOut = true;
  const uint8_t cands[3] = {PRESET_ESP32_OLED, PRESET_ESP32_CYD, PRESET_ESP32S3_CAPTOUCH};
  Info best;
  autodetect(cands, 3, b, 200, best);
  TEST_ASSERT_TRUE_MESSAGE(b.spentUs <= 200u * 1000u + 20000u, "autodetect overran total budget");
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_auto_follows_probe);
  RUN_TEST(test_none_override_wins_over_everything);
  RUN_TEST(test_screen_override_drops_touch);
  RUN_TEST(test_screen_override_with_nothing_probed_and_no_preset_stays_none);
  RUN_TEST(test_preset_supplies_hardware_when_probe_finds_nothing);
  RUN_TEST(test_touch_override_without_touch_hardware_falls_back_to_screen);
  RUN_TEST(test_unknown_preset_ignored);
  RUN_TEST(test_none_mode_zero_polling);
  RUN_TEST(test_s3_forbidden_list_is_exactly_19_20_and_26_to_37);
  RUN_TEST(test_s3_presets_use_no_forbidden_pin);
  RUN_TEST(test_pin_forbidden_helper);
  RUN_TEST(test_preset_info_matches_declared_hardware);
  RUN_TEST(test_boot_log_line_has_mode_drivers_pins);
  RUN_TEST(test_autodetect_picks_first_working_candidate_and_stops);
  RUN_TEST(test_autodetect_prefers_touchscreen_candidate_and_nothing_found_is_none);
  RUN_TEST(test_autodetect_total_budget_bounded);
  return UNITY_END();
}
