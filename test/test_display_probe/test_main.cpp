// Bounded boot probe: 3 modes, floating buses, NACK, timeout, forbidden pins.
#include <unity.h>

#include "../../lib/fry_ui/display_presets.h"
#include "../support/display_mock.h"

using namespace fry;
using namespace fry::disp;
using fry::disptest::MockBus;

void setUp(void) {}
void tearDown(void) {}

static BoardPins pins(int sda, int scl, int sck, int mosi, int miso, int cs, int dc, int rst, int bl, int tcs, int tirq,
                      int tsda, int tscl, int trst) {
  BoardPins p;
  p.sda = sda; p.scl = scl; p.spiSck = sck; p.spiMosi = mosi; p.spiMiso = miso; p.tftCs = cs; p.tftDc = dc;
  p.tftRst = rst; p.tftBl = bl; p.touchCs = tcs; p.touchIrq = tirq; p.touchSda = tsda; p.touchScl = tscl;
  p.touchRst = trst;
  p.forbidden = nullptr;
  p.nForbidden = 0;
  return p;
}
static BoardPins i2cOnly() { return pins(21, 22, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1); }
static BoardPins spiTft() { return pins(-1, -1, 14, 13, 12, 15, 2, -1, 21, -1, -1, -1, -1, -1); }
static BoardPins cyd() { return pins(-1, -1, 14, 13, 12, 15, 2, -1, 21, 33, 36, -1, -1, -1); }
static BoardPins capTouch() { return pins(-1, -1, 12, 11, 13, 10, 9, 8, 14, -1, 7, 4, 5, 6); }

static void ili(MockBus& b) {
  b.tftMode = 1;
  b.idD3[0] = 0x00; b.idD3[1] = 0x93; b.idD3[2] = 0x41;
  b.id04[0] = 0x00; b.id04[1] = 0x93; b.id04[2] = 0x41;
}

// ---- NONE / empty ------------------------------------------------------------------------------------
void test_empty_bus_is_none_and_bounded() {
  MockBus b;
  Info i = probe(i2cOnly(), b, 300);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_NONE, i.mode);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::None, (uint8_t)i.panel);
  TEST_ASSERT_TRUE(b.calls < 40);
  TEST_ASSERT_TRUE(b.spentUs <= 300u * 1000u);
}

void test_no_pins_configured_touches_nothing() {
  MockBus b;
  BoardPins p = pins(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1);
  Info i = probe(p, b, 300);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_NONE, i.mode);
  TEST_ASSERT_EQUAL_INT(0, b.calls);
}

// ---- SCREEN_ONLY ---------------------------------------------------------------------------------------
void test_oled_3c_is_screen_only() {
  MockBus b;
  b.oled3C = true;
  Info i = probe(i2cOnly(), b, 300);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_SCREEN_ONLY, i.mode);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::SSD1306_128x64, (uint8_t)i.panel);
  TEST_ASSERT_EQUAL_UINT8(0x3C, i.i2cAddr);
  TEST_ASSERT_TRUE(i.mono);
  TEST_ASSERT_EQUAL_UINT16(128, i.width);
  TEST_ASSERT_EQUAL_UINT16(64, i.height);
}

void test_oled_3d_is_screen_only() {
  MockBus b;
  b.oled3D = true;
  Info i = probe(i2cOnly(), b, 300);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_SCREEN_ONLY, i.mode);
  TEST_ASSERT_EQUAL_UINT8(0x3D, i.i2cAddr);
}

void test_ili9341_without_touch_is_screen_only() {
  MockBus b;
  ili(b);
  Info i = probe(spiTft(), b, 300);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_SCREEN_ONLY, i.mode);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::ILI9341_240x320, (uint8_t)i.panel);
  TEST_ASSERT_EQUAL_UINT16(240, i.width);
  TEST_ASSERT_EQUAL_UINT16(320, i.height);
  TEST_ASSERT_FALSE(i.mono);
  TEST_ASSERT_EQUAL_UINT32(0x009341u, i.panelId & 0xFFFFFFu);
}

void test_st7789_and_st7735_ids() {
  MockBus b;
  b.tftMode = 1;
  b.id04[0] = 0x85; b.id04[1] = 0x85; b.id04[2] = 0x52;
  b.idD3[0] = 0x85; b.idD3[1] = 0x85; b.idD3[2] = 0x52;
  Info i = probe(spiTft(), b, 300);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::ST7789_240x240, (uint8_t)i.panel);
  MockBus c;
  c.tftMode = 1;
  c.id04[0] = 0x7C; c.id04[1] = 0x89; c.id04[2] = 0xF0;
  c.idD3[0] = 0x7C; c.idD3[1] = 0x89; c.idD3[2] = 0xF0;
  i = probe(spiTft(), c, 300);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::ST7735_128x160, (uint8_t)i.panel);
}

// ---- TOUCHSCREEN ---------------------------------------------------------------------------------------
void test_cyd_ili9341_plus_xpt2046_is_touchscreen() {
  MockBus b;
  ili(b);
  b.xptPresent = true;
  Info i = probe(cyd(), b, 300);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_TOUCHSCREEN, i.mode);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::XPT2046, (uint8_t)i.touch);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::ILI9341_240x320, (uint8_t)i.panel);
}

void test_xpt2046_floating_samples_do_not_count() {
  MockBus b;
  ili(b);
  b.xptFloatMode = 1;  // reads all zero
  Info i = probe(cyd(), b, 300);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_SCREEN_ONLY, i.mode);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::None, (uint8_t)i.touch);
  MockBus c;
  ili(c);
  c.xptFloatMode = 2;  // reads all 0xFFF
  i = probe(cyd(), c, 300);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_SCREEN_ONLY, i.mode);
}

void test_xpt2046_absent_is_screen_only() {
  MockBus b;
  ili(b);
  Info i = probe(cyd(), b, 300);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_SCREEN_ONLY, i.mode);
}

void test_cst816s_detected() {
  MockBus b;
  ili(b);
  b.addReg(0x15, 0xA7, 0xB5);
  Info i = probe(capTouch(), b, 300);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_TOUCHSCREEN, i.mode);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::CST816S, (uint8_t)i.touch);
  TEST_ASSERT_EQUAL_UINT8(0x15, i.touchAddr);
}

void test_ft6336_detected_by_a8_or_a3() {
  MockBus b;
  ili(b);
  b.addReg(0x38, 0xA8, 0x11);
  Info i = probe(capTouch(), b, 300);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::FT6236, (uint8_t)i.touch);
  TEST_ASSERT_EQUAL_UINT8(0x38, i.touchAddr);
  MockBus c;
  ili(c);
  c.addReg(0x38, 0xA3, 0x64);
  i = probe(capTouch(), c, 300);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::FT6236, (uint8_t)i.touch);
}

void test_gt911_at_both_addresses() {
  MockBus b;
  ili(b);
  b.addReg(0x5D, 0x8140, '9', '1', '1', 0, 4);
  Info i = probe(capTouch(), b, 300);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::GT911, (uint8_t)i.touch);
  TEST_ASSERT_EQUAL_UINT8(0x5D, i.touchAddr);
  MockBus c;
  ili(c);
  c.addReg(0x14, 0x8140, '9', '1', '1', 0, 4);
  i = probe(capTouch(), c, 300);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::GT911, (uint8_t)i.touch);
  TEST_ASSERT_EQUAL_UINT8(0x14, i.touchAddr);
}

void test_wrong_gt911_product_id_rejected() {
  MockBus b;
  ili(b);
  b.addReg(0x5D, 0x8140, 'x', 'y', 'z', 0, 4);
  Info i = probe(capTouch(), b, 300);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::None, (uint8_t)i.touch);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_SCREEN_ONLY, i.mode);
}

void test_i2c_floating_register_values_do_not_count() {
  const uint8_t bad[2] = {0x00, 0xFF};
  for (int k = 0; k < 2; k++) {
    MockBus b;
    ili(b);
    b.addReg(0x15, 0xA7, bad[k]);
    b.addReg(0x38, 0xA8, bad[k]);
    b.addReg(0x38, 0xA3, bad[k]);
    Info i = probe(capTouch(), b, 300);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::None, (uint8_t)i.touch);
    TEST_ASSERT_EQUAL_UINT8(FRY_DISP_SCREEN_ONLY, i.mode);
  }
}

// ---- floating SPI MISO guard ----------------------------------------------------------------------------
void test_floating_miso_never_counts() {
  MockBus b;  // tftMode 0: line follows the pull -> pull-up and pull-down reads differ
  Info i = probe(spiTft(), b, 300);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_NONE, i.mode);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::None, (uint8_t)i.panel);
  TEST_ASSERT_TRUE(b.pullSets >= 2);
  TEST_ASSERT_EQUAL_INT(0, b.pull);  // pull restored to none
}

void test_stuck_low_and_stuck_high_miso_never_count() {
  MockBus lo;
  lo.tftMode = 2;
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_NONE, probe(spiTft(), lo, 300).mode);
  MockBus hi;
  hi.tftMode = 3;
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_NONE, probe(spiTft(), hi, 300).mode);
}

void test_unknown_nonfloating_id_not_a_known_panel() {
  MockBus b;
  b.tftMode = 1;
  b.id04[0] = 0x12; b.id04[1] = 0x34; b.id04[2] = 0x56;
  b.idD3[0] = 0x12; b.idD3[1] = 0x34; b.idD3[2] = 0x56;
  Info i = probe(spiTft(), b, 300);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_NONE, i.mode);
  TEST_ASSERT_EQUAL_UINT32(0x123456u, i.panelId & 0xFFFFFFu);  // raw id kept for the log
}

// ---- I2C failure modes -------------------------------------------------------------------------------------
void test_i2c_nack_everywhere() {
  MockBus b;
  Info i = probe(capTouch(), b, 300);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_NONE, i.mode);
}

void test_i2c_ack_then_read_fail_recovers_bus_bounded() {
  MockBus b;
  ili(b);
  b.addReg(0x15, 0xA7, 0xB5);
  b.ackOnlyNoRead = true;
  Info i = probe(capTouch(), b, 300);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::None, (uint8_t)i.touch);
  TEST_ASSERT_TRUE(b.recovers >= 1);
  TEST_ASSERT_TRUE(b.recovers <= 4);
}

void test_i2c_total_timeout_is_bounded_by_budget() {
  MockBus b;
  b.everythingTimesOut = true;
  Info i = probe(capTouch(), b, 100);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_NONE, i.mode);
  // Worst case charged by the mock must stay within the budget plus one operation's slack.
  TEST_ASSERT_TRUE_MESSAGE(b.spentUs <= 100u * 1000u + 12000u, "probe overran its time budget");
  TEST_ASSERT_TRUE(b.recovers <= 4);
}

void test_i2c_stuck_bus_ack_all_is_not_a_display() {
  MockBus b;
  ili(b);
  b.i2cAckAll = true;  // SDA stuck low "ACKs" every address; reads come back 0xFF
  Info i = probe(capTouch(), b, 300);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::None, (uint8_t)i.touch);
  TEST_ASSERT_TRUE(b.recovers >= 1);
}

// ---- forbidden pins -----------------------------------------------------------------------------------------
void test_forbidden_i2c_pin_blocks_whole_bus() {
  MockBus b;
  b.oled3C = true;
  BoardPins p = pins(26, 22, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1);  // GPIO26 is S3 flash
  p.forbidden = kEsp32S3Forbidden;
  p.nForbidden = kEsp32S3ForbiddenCount;
  Info i = probe(p, b, 300);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_NONE, i.mode);
  TEST_ASSERT_EQUAL_INT(0, b.i2cBegins);
  TEST_ASSERT_EQUAL_INT(0, b.calls);
}

void test_forbidden_spi_pin_blocks_tft_and_xpt() {
  for (int bad = 0; bad < 3; bad++) {
    MockBus b;
    ili(b);
    b.xptPresent = true;
    BoardPins p = cyd();
    if (bad == 0) p.tftCs = 33;        // S3 PSRAM pin
    if (bad == 1) p.spiMiso = 19;      // USB D-
    if (bad == 2) p.touchCs = 37;
    p.forbidden = kEsp32S3Forbidden;
    p.nForbidden = kEsp32S3ForbiddenCount;
    Info i = probe(p, b, 300);
    if (bad == 2) {
      TEST_ASSERT_EQUAL_UINT8(FRY_DISP_SCREEN_ONLY, i.mode);  // TFT bus fine, XPT blocked
      TEST_ASSERT_EQUAL_INT(0, b.xptSamples);
    } else {
      TEST_ASSERT_EQUAL_UINT8(FRY_DISP_NONE, i.mode);
      TEST_ASSERT_EQUAL_INT(0, b.spiReads);
    }
    for (size_t k = 0; k < kEsp32S3ForbiddenCount; k++)
      TEST_ASSERT_FALSE(b.pinWasUsed(kEsp32S3Forbidden[k]));
  }
}

void test_no_preset_ever_probes_a_forbidden_pin() {
  for (uint8_t pr = 1; pr < PRESET_COUNT; pr++) {
    BoardPins p;
    TEST_ASSERT_TRUE(presetPins(pr, p));
    TEST_ASSERT_TRUE_MESSAGE(pinsAllowed(p), presetName(pr));
    MockBus b;
    ili(b);
    b.oled3C = true;
    b.xptPresent = true;
    b.addReg(0x15, 0xA7, 0xB5);
    probe(p, b, 300);
    for (int k = 0; k < b.nPins; k++) TEST_ASSERT_FALSE_MESSAGE(pinForbidden(p, b.pinsUsed[k]), presetName(pr));
  }
}

void test_forbidden_pin_probe_does_not_leak_into_other_bus() {
  MockBus b;
  b.oled3C = true;
  BoardPins p = pins(21, 22, -1, -1, 12, 15, 2, -1, -1, -1, -1, -1, -1, -1);
  p.forbidden = kEsp32S3Forbidden;
  p.nForbidden = kEsp32S3ForbiddenCount;
  Info i = probe(p, b, 300);  // I2C pins 21/22 are fine on S3; SPI MISO 12/CS 15 also fine
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_SCREEN_ONLY, i.mode);
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_empty_bus_is_none_and_bounded);
  RUN_TEST(test_no_pins_configured_touches_nothing);
  RUN_TEST(test_oled_3c_is_screen_only);
  RUN_TEST(test_oled_3d_is_screen_only);
  RUN_TEST(test_ili9341_without_touch_is_screen_only);
  RUN_TEST(test_st7789_and_st7735_ids);
  RUN_TEST(test_cyd_ili9341_plus_xpt2046_is_touchscreen);
  RUN_TEST(test_xpt2046_floating_samples_do_not_count);
  RUN_TEST(test_xpt2046_absent_is_screen_only);
  RUN_TEST(test_cst816s_detected);
  RUN_TEST(test_ft6336_detected_by_a8_or_a3);
  RUN_TEST(test_gt911_at_both_addresses);
  RUN_TEST(test_wrong_gt911_product_id_rejected);
  RUN_TEST(test_i2c_floating_register_values_do_not_count);
  RUN_TEST(test_floating_miso_never_counts);
  RUN_TEST(test_stuck_low_and_stuck_high_miso_never_count);
  RUN_TEST(test_unknown_nonfloating_id_not_a_known_panel);
  RUN_TEST(test_i2c_nack_everywhere);
  RUN_TEST(test_i2c_ack_then_read_fail_recovers_bus_bounded);
  RUN_TEST(test_i2c_total_timeout_is_bounded_by_budget);
  RUN_TEST(test_i2c_stuck_bus_ack_all_is_not_a_display);
  RUN_TEST(test_forbidden_i2c_pin_blocks_whole_bus);
  RUN_TEST(test_forbidden_spi_pin_blocks_tft_and_xpt);
  RUN_TEST(test_no_preset_ever_probes_a_forbidden_pin);
  RUN_TEST(test_forbidden_pin_probe_does_not_leak_into_other_bus);
  return UNITY_END();
}
