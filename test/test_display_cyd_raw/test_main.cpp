// Bench CYD: separate XPT2046 bus, channel-based touch plausibility, forbidden touch-bus pins, scope safety and the
// '[ui] probe raw' diagnostic line.
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

static void goodCyd(CydBus& b) {
  b.panelKind = CydBus::ILI9341;
  b.xptBusPresent = true;
}

void test_touch_bus_is_separate_for_cyd_only() {
  int clk = 0, mosi = 0, miso = 0;
  TEST_ASSERT_TRUE(presetTouchBus(PRESET_ESP32_CYD, &clk, &mosi, &miso));
  TEST_ASSERT_EQUAL_INT(25, clk);
  TEST_ASSERT_EQUAL_INT(32, mosi);
  TEST_ASSERT_EQUAL_INT(39, miso);
  for (uint8_t pr = 1; pr < PRESET_COUNT; pr++)
    if (pr != PRESET_ESP32_CYD) TEST_ASSERT_FALSE_MESSAGE(presetTouchBus(pr, &clk, &mosi, &miso), presetName(pr));
  BoardPins p;
  presetPins(PRESET_ESP32_CYD, p);
  TEST_ASSERT_EQUAL_INT(14, p.spiSck);
  TEST_ASSERT_EQUAL_INT(13, p.spiMosi);
  TEST_ASSERT_EQUAL_INT(12, p.spiMiso);
  TEST_ASSERT_EQUAL_INT(15, p.tftCs);
  TEST_ASSERT_EQUAL_INT(2, p.tftDc);
  TEST_ASSERT_EQUAL_INT(21, p.tftBl);
  TEST_ASSERT_EQUAL_INT(33, p.touchCs);
  TEST_ASSERT_EQUAL_INT(36, p.touchIrq);
}

void test_cyd_detected_via_channels_and_xpt_confirmed() {
  CydBus b;
  goodCyd(b);
  Info i = probeCyd(b);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_TOUCHSCREEN, i.mode);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::ILI9341_240x320, (uint8_t)i.panel);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::XPT2046, (uint8_t)i.touch);
  TEST_ASSERT_TRUE(b.xptChannelCalls >= 1);
  TEST_ASSERT_EQUAL_INT(0, b.xptSamples);  // channel read replaced the legacy sample
  TEST_ASSERT_EQUAL_UINT8(6, i.raw.nXpt);
  TEST_ASSERT_EQUAL_INT(1, i.raw.xptVerdict);
  TEST_ASSERT_TRUE(b.spentUs <= 400u * 1000u);
}

void test_floating_gpio39_is_not_a_touch_controller() {
  const uint16_t levels[4] = {0, 0xFFF, 1500, 2047};  // saturated, saturated, stable-mid (all channels equal), stable-mid
  for (int k = 0; k < 4; k++) {
    CydBus b;
    b.panelKind = CydBus::ILI9341;
    b.floatLevel = levels[k];
    Info i = probeCyd(b);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::ILI9341_240x320, (uint8_t)i.panel);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::None, (uint8_t)i.touch);
    TEST_ASSERT_EQUAL_UINT8(FRY_DISP_SCREEN_ONLY, i.mode);
    TEST_ASSERT_EQUAL_INT(0, i.raw.xptVerdict);
  }
}

void test_noisy_floating_gpio39_is_not_a_touch_controller() {
  for (int seed = 0; seed < 40; seed++) {
    CydBus b;
    b.panelKind = CydBus::ILI9341;
    b.floatNoisy = true;
    b.lfsr = 0x1000u + (uint32_t)seed * 7919u;
    Info i = probeCyd(b);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::None, (uint8_t)i.touch);
  }
}

void test_channels_must_be_two_consistent_reads() {
  // temp0 reads 985 then 1700: not the same die temperature twice
  struct Jumpy : CydBus {
    int n = 0;
    int xpt2046Channels(int cs, uint16_t out[6]) override {
      CydBus::xpt2046Channels(cs, out);
      out[1] = (n++ % 2) ? 985 : 1700;
      out[0] = 985;
      return 1;
    }
  } b;
  goodCyd(b);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::None, (uint8_t)probeCyd(b).touch);
}

void test_legacy_sample_fallback_still_confirms_xpt() {
  CydBus b;
  goodCyd(b);
  b.supportChannels = false;  // a bus without the channel read uses the x/y/z sample rule
  Info i = probeCyd(b);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::XPT2046, (uint8_t)i.touch);
  TEST_ASSERT_TRUE(b.xptSamples >= 1);
  TEST_ASSERT_EQUAL_UINT8(3, i.raw.nXpt);
}

void test_forbidden_touch_bus_pin_blocks_xpt_but_not_tft() {
  CydBus b;
  goodCyd(b);
  BoardPins p;
  presetPins(PRESET_ESP32_CYD, p);
  BoardPins s3 = p;
  s3.forbidden = kEsp32S3Forbidden;  // GPIO32 (touch MOSI) is the S3 flash bus
  s3.nForbidden = kEsp32S3ForbiddenCount;
  BoardPins g = gateTouchBus(PRESET_ESP32_CYD, s3);
  TEST_ASSERT_EQUAL_INT(-1, g.touchCs);
  // classic ESP32 list: 25/32/39 are fine, nothing is gated
  BoardPins ok = gateTouchBus(PRESET_ESP32_CYD, p);
  TEST_ASSERT_EQUAL_INT(33, ok.touchCs);
  // a gated touch bus is never driven by a preset boot probe
  struct NoHook : BusHook {
    void select(uint8_t, const BoardPins&) override {}
    void release(const BoardPins&) override {}
  } h;
  Info best;
  BoardPins pins;
  bool have = false;
  bootProbe(PRESET_ESP32_CYD, 0, PRESET_ESP32_OLED, nullptr, 0, b, &h, 400, best, pins, have);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::XPT2046, (uint8_t)best.touch);
  CydBus b2;
  goodCyd(b2);
  Info i2 = probe(g, b2, 400);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::ILI9341_240x320, (uint8_t)i2.panel);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::None, (uint8_t)i2.touch);
  TEST_ASSERT_EQUAL_INT(0, b2.xptChannelCalls + b2.xptSamples);
  for (size_t k = 0; k < kEsp32S3ForbiddenCount; k++) TEST_ASSERT_FALSE(b2.pinWasUsed(kEsp32S3Forbidden[k]));
}

void test_no_preset_scope_never_touches_spi_or_xpt() {
  CydBus b;
  goodCyd(b);
  Info best;
  BoardPins pins;
  bool have = false;
  const uint8_t cands[2] = {PRESET_ESP32_OLED, PRESET_ESP32_CYD};
  bootProbe(0, 0 /*Auto*/, PRESET_ESP32_OLED, cands, 2, b, nullptr, 400, best, pins, have);
  TEST_ASSERT_EQUAL_INT(0, b.spiReads);
  TEST_ASSERT_EQUAL_INT(0, b.xptSamples + b.xptChannelCalls);
  TEST_ASSERT_EQUAL_INT(0, b.pullSets);
  CydBus n;
  goodCyd(n);
  bootProbe(PRESET_ESP32_CYD, 1 /*None*/, PRESET_ESP32_OLED, cands, 2, n, nullptr, 400, best, pins, have);
  TEST_ASSERT_EQUAL_INT(0, n.calls);
}

void test_preset_bootprobe_detects_cyd_and_boot_line_matches() {
  CydBus b;
  goodCyd(b);
  Info best;
  BoardPins pins;
  bool have = false;
  const uint8_t r = bootProbe(PRESET_ESP32_CYD, 0, PRESET_ESP32_OLED, nullptr, 0, b, nullptr, 400, best, pins, have);
  TEST_ASSERT_EQUAL_UINT8(PRESET_ESP32_CYD, r);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_TOUCHSCREEN, best.mode);
  const Info res = resolve(best, 0, PRESET_ESP32_CYD);
  char line[200];
  formatBootLine(line, sizeof(line), res, "LovyanGFX", pins);
  TEST_ASSERT_EQUAL_STRING(
      "[ui] mode=TOUCHSCREEN panel=ILI9341_240x320 touch=XPT2046 drv=LovyanGFX sda=- scl=- sck=14 mosi=13 miso=12 cs=15 dc=2 rst=- bl=21 "
      "tcs=33 tirq=36 tsda=- tscl=-",
      line);
}

void test_probe_raw_line_shows_bytes() {
  CydBus b;
  goodCyd(b);
  Info i = probeCyd(b);
  char line[200];
  size_t n = formatProbeRaw(line, sizeof(line), i);
  TEST_ASSERT_TRUE(n > 0 && n < sizeof(line));
  TEST_ASSERT_EQUAL_STRING(
      "[ui] probe raw d3u=FF0093410000 d3d=000093410000 d3bit=8 04u=- 04d=- 04bit=-1 xpt=3D9,3DA,C1C,5DC,C,FAA xn=6 xv=1 st=-", line);
  // failed read: the same line still carries the bytes the lead needs
  CydBus f;
  f.panelKind = CydBus::STUCK_LOW;
  Info j = probeCyd(f);
  formatProbeRaw(line, sizeof(line), j);
  TEST_ASSERT_NOT_NULL(strstr(line, "d3u=000000000000"));
  TEST_ASSERT_NOT_NULL(strstr(line, "04u=000000000000"));
  TEST_ASSERT_NOT_NULL(strstr(line, "xn=6 xv=0"));  // touch bus is read (and rejected: floating) even though the TFT read failed
  char small[20];
  size_t m = formatProbeRaw(small, sizeof(small), j);
  TEST_ASSERT_TRUE(m < sizeof(small));
  TEST_ASSERT_EQUAL_CHAR(0, small[sizeof(small) - 1]);
}

void test_cyd_probe_is_bounded() {
  CydBus b;
  goodCyd(b);
  Info i = probeCyd(b);
  (void)i;
  TEST_ASSERT_TRUE(b.calls < 40);
  TEST_ASSERT_TRUE(b.spentUs < 20000u);
  CydBus f;  // nothing attached: still cheap
  Info j = probeCyd(f);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_NONE, j.mode);
  TEST_ASSERT_TRUE(f.spentUs < 20000u);
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_touch_bus_is_separate_for_cyd_only);
  RUN_TEST(test_cyd_detected_via_channels_and_xpt_confirmed);
  RUN_TEST(test_floating_gpio39_is_not_a_touch_controller);
  RUN_TEST(test_noisy_floating_gpio39_is_not_a_touch_controller);
  RUN_TEST(test_channels_must_be_two_consistent_reads);
  RUN_TEST(test_legacy_sample_fallback_still_confirms_xpt);
  RUN_TEST(test_forbidden_touch_bus_pin_blocks_xpt_but_not_tft);
  RUN_TEST(test_no_preset_scope_never_touches_spi_or_xpt);
  RUN_TEST(test_preset_bootprobe_detects_cyd_and_boot_line_matches);
  RUN_TEST(test_probe_raw_line_shows_bytes);
  RUN_TEST(test_cyd_probe_is_bounded);
  return UNITY_END();
}
