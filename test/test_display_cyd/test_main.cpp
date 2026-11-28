// Bench CYD (ESP32-2432S028R) probe: the failure seen on real hardware (panel id read 0, mode only from the preset) and the
// fixed path. Uses only the pre-existing BusOps surface + the realistic bus model in test/support/cyd_mock.h.
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

// RED before the fix: serial showed "probe preset=esp32-cyd panel=none id=0x000000 touch=none".
void test_cyd_ili9341_real_stream_is_detected() {
  CydBus b;
  b.panelKind = CydBus::ILI9341;
  b.xptBusPresent = true;
  Info i = probeCyd(b);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::ILI9341_240x320, (uint8_t)i.panel);
  TEST_ASSERT_EQUAL_UINT32(0x009341u, i.panelId & 0xFFFFFFu);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::XPT2046, (uint8_t)i.touch);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_TOUCHSCREEN, i.mode);
}

void test_cyd_ili9341_without_dummy_byte_also_detected() {
  CydBus b;
  b.panelKind = CydBus::ILI9341;
  b.d3HasDummyByte = false;
  b.xptBusPresent = true;
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::ILI9341_240x320, (uint8_t)probeCyd(b).panel);
}

void test_cyd_ili9341_stable_dummy_byte_detected() {
  CydBus b;
  b.panelKind = CydBus::ILI9341;
  b.dummyFollowsPull = false;
  b.xptBusPresent = true;
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_TOUCHSCREEN, probeCyd(b).mode);
}

void test_cyd_st7789_batch_detected_with_and_without_dummy_byte() {
  for (int k = 0; k < 2; k++) {
    CydBus b;
    b.panelKind = CydBus::ST7789;
    b.st7789HasDummyByte = k == 1;
    b.xptBusPresent = true;
    Info i = probeCyd(b);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::ST7789_240x240, (uint8_t)i.panel);
    TEST_ASSERT_EQUAL_UINT8(FRY_DISP_TOUCHSCREEN, i.mode);
  }
}

// Anti-floating-MISO guard is intact.
void test_cyd_floating_miso_is_not_a_panel() {
  CydBus b;  // panelKind NONE: MISO follows the pull
  b.xptBusPresent = true;
  Info i = probeCyd(b);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_NONE, i.mode);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::None, (uint8_t)i.panel);
  TEST_ASSERT_EQUAL_INT(0, b.pull);
  TEST_ASSERT_EQUAL_INT(0, b.xptSamples);  // no screen -> the touch bus is never driven
}

void test_cyd_stuck_lines_are_not_a_panel() {
  for (int k = 0; k < 2; k++) {
    CydBus b;
    b.panelKind = k ? CydBus::STUCK_HIGH : CydBus::STUCK_LOW;
    b.xptBusPresent = true;
    Info i = probeCyd(b);
    TEST_ASSERT_EQUAL_UINT8(FRY_DISP_NONE, i.mode);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::None, (uint8_t)i.panel);
  }
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_cyd_ili9341_real_stream_is_detected);
  RUN_TEST(test_cyd_ili9341_without_dummy_byte_also_detected);
  RUN_TEST(test_cyd_ili9341_stable_dummy_byte_detected);
  RUN_TEST(test_cyd_st7789_batch_detected_with_and_without_dummy_byte);
  RUN_TEST(test_cyd_floating_miso_is_not_a_panel);
  RUN_TEST(test_cyd_stuck_lines_are_not_a_panel);
  return UNITY_END();
}
