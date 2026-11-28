// Bench CYD diagnostics (attempt 2): the XPT2046 on its separate bus is read even when the TFT id read fails, and an ILI9341 clone
// that does not return 00 93 41 is accepted LovyanGFX-style (RDDID byte0 == 0 and driven RDDST) without weakening the anti-floating rules.
// Uses only the BusOps surface that exists on the parent commits; assertions go through the public probe() / formatProbeRaw().
#include <string.h>
#include <unity.h>

#include "../../lib/fry_ui/display_presets.h"
#include "../support/cyd_mock.h"

using namespace fry;
using namespace fry::disp;
using fry::disptest::CydBus;

void setUp(void) {}
void tearDown(void) {}

static Info probeCyd(CydBus& b) {
  BoardPins p;
  TEST_ASSERT_TRUE(presetPins(PRESET_ESP32_CYD, p));
  return probe(p, b, 400);
}

// Observed bench failure: TFT id reads give nothing. The touch bus must still be read and confirmed.
void test_tft_read_fails_but_touch_bus_is_read_and_confirmed() {
  CydBus b;
  b.panelKind = CydBus::NONE;  // TFT MISO floating
  b.xptBusPresent = true;
  Info i = probeCyd(b);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::None, (uint8_t)i.panel);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_NONE, i.mode);  // a screen is still required for a mode
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::XPT2046, (uint8_t)i.touch);
  TEST_ASSERT_EQUAL_UINT8(6, i.raw.nXpt);
  TEST_ASSERT_EQUAL_INT(1, i.raw.xptVerdict);
  char line[220];
  formatProbeRaw(line, sizeof(line), i);
  TEST_ASSERT_NOT_NULL(strstr(line, "xpt=3D9,3DA,C1C,5DC,C,FAA xn=6 xv=1"));
}

void test_tft_stuck_low_and_touch_floating_both_diagnosed() {
  CydBus b;
  b.panelKind = CydBus::STUCK_LOW;
  b.floatLevel = 0;  // GPIO39 floating low
  Info i = probeCyd(b);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_NONE, i.mode);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::None, (uint8_t)i.touch);
  TEST_ASSERT_EQUAL_UINT8(6, i.raw.nXpt);
  TEST_ASSERT_EQUAL_INT(0, i.raw.xptVerdict);
}

// Candidates scope (explicit display mode, no preset): a CYD candidate with no screen but a live XPT is not a touchscreen.
void test_candidate_without_panel_stays_none_even_with_live_touch() {
  CydBus b;
  b.xptBusPresent = true;
  Info best;
  BoardPins pins;
  bool have = false;
  const uint8_t cands[1] = {PRESET_ESP32_CYD};
  const uint8_t r = bootProbe(0, 3 /*Touch*/, PRESET_ESP32_OLED, cands, 1, b, nullptr, 400, best, pins, have);
  TEST_ASSERT_EQUAL_UINT8(0, r);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_NONE, best.mode);
}

void test_no_preset_and_none_scopes_stay_zero_spi_with_no_panel() {
  CydBus b;
  b.xptBusPresent = true;  // a live touch bus on a board whose scope forbids touching it
  Info best;
  BoardPins pins;
  bool have = false;
  const uint8_t cands[1] = {PRESET_ESP32_CYD};
  bootProbe(0, 0 /*Auto*/, PRESET_ESP32_OLED, cands, 1, b, nullptr, 400, best, pins, have);
  TEST_ASSERT_EQUAL_INT(0, b.spiReads);
  TEST_ASSERT_EQUAL_INT(0, b.xptSamples + b.xptChannelCalls);
  TEST_ASSERT_EQUAL_INT(0, b.pullSets);
  CydBus n;
  n.xptBusPresent = true;
  bootProbe(PRESET_ESP32_CYD, 1 /*None*/, PRESET_ESP32_OLED, cands, 1, n, nullptr, 400, best, pins, have);
  TEST_ASSERT_EQUAL_INT(0, n.calls);
}

void test_gated_touch_bus_is_not_read_without_a_panel() {
  CydBus b;
  b.xptBusPresent = true;
  BoardPins p;
  presetPins(PRESET_ESP32_CYD, p);
  p.forbidden = kEsp32S3Forbidden;  // GPIO32 (touch MOSI) is the S3 flash bus
  p.nForbidden = kEsp32S3ForbiddenCount;
  BoardPins g = gateTouchBus(PRESET_ESP32_CYD, p);
  Info i = probe(g, b, 400);
  TEST_ASSERT_EQUAL_INT(0, b.xptChannelCalls + b.xptSamples);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::None, (uint8_t)i.touch);
  TEST_ASSERT_EQUAL_INT(-1, i.raw.xptVerdict);
}

// ILI9341 clone: 0xD3 returns no 00 93 41, RDDID is 00 00 00, RDDST is a driven non-zero status (LovyanGFX's CYD rule).
void test_ili9341_clone_without_d3_id_is_detected_via_status() {
  CydBus b;
  b.panelKind = CydBus::ILI9341;
  b.d3Works = false;
  b.xptBusPresent = true;
  Info i = probeCyd(b);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::ILI9341_240x320, (uint8_t)i.panel);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_TOUCHSCREEN, i.mode);
  char line[220];
  formatProbeRaw(line, sizeof(line), i);
  TEST_ASSERT_NOT_NULL(strstr(line, " st=61000000"));
}

void test_status_fallback_rejects_undriven_or_pull_following_status() {
  {  // RDDID is 0 but RDDST is all zero: a stuck-low-looking line, not a panel
    CydBus b;
    b.panelKind = CydBus::ILI9341;
    b.d3Works = false;
    b.statusPresent = false;
    TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::None, (uint8_t)probeCyd(b).panel);
  }
  {  // status differs between the two pulls: floating
    CydBus b;
    b.panelKind = CydBus::ILI9341;
    b.d3Works = false;
    b.statusFollowsPull = true;
    TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::None, (uint8_t)probeCyd(b).panel);
  }
  for (int k = 0; k < 3; k++) {  // nothing driven / stuck low / stuck high
    CydBus b;
    b.panelKind = k == 0 ? CydBus::NONE : (k == 1 ? CydBus::STUCK_LOW : CydBus::STUCK_HIGH);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::None, (uint8_t)probeCyd(b).panel);
  }
}

// The 00 93 41 stream must be present under BOTH pulls: a pattern that appears under only one pull is not a driven device.
void test_id_pattern_under_only_one_pull_is_rejected() {
  for (int k = -1; k <= 1; k += 2) {
    CydBus b;
    b.panelKind = CydBus::ILI9341;
    b.d3OnlyUnderPull = k;
    b.statusPresent = false;
    TEST_ASSERT_EQUAL_UINT8_MESSAGE((uint8_t)Panel::None, (uint8_t)probeCyd(b).panel, k < 0 ? "pull-down only" : "pull-up only");
  }
  CydBus ok;
  ok.panelKind = CydBus::ILI9341;
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::ILI9341_240x320, (uint8_t)probeCyd(ok).panel);
}

void test_diag_probe_stays_bounded() {
  CydBus b;
  b.xptBusPresent = true;
  probeCyd(b);
  TEST_ASSERT_TRUE(b.calls < 40);
  TEST_ASSERT_TRUE(b.spentUs < 20000u);
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_tft_read_fails_but_touch_bus_is_read_and_confirmed);
  RUN_TEST(test_tft_stuck_low_and_touch_floating_both_diagnosed);
  RUN_TEST(test_candidate_without_panel_stays_none_even_with_live_touch);
  RUN_TEST(test_no_preset_and_none_scopes_stay_zero_spi_with_no_panel);
  RUN_TEST(test_gated_touch_bus_is_not_read_without_a_panel);
  RUN_TEST(test_ili9341_clone_without_d3_id_is_detected_via_status);
  RUN_TEST(test_status_fallback_rejects_undriven_or_pull_following_status);
  RUN_TEST(test_id_pattern_under_only_one_pull_is_rejected);
  RUN_TEST(test_diag_probe_stays_bounded);
  return UNITY_END();
}
