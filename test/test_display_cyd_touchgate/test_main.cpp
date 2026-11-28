// CYD touch-bus safety wiring and the real-hardware raw bytes of the bench CYD (lead bench of de47169):
//  - every touch pin (own CLK / MOSI / MISO, CS, IRQ) is checked against the forbidden list before ANY touch SPI op, in the probe
//    itself and at all three bootProbe / autodetect scopes (call sites pinned: removing one makes a test here fail);
//  - the exact raw bytes the bench CYD returned are detected as ILI9341 + XPT2046 + TOUCHSCREEN;
//  - both-pulls rule, no preset => zero SPI, display_mode NONE => zero polling.
#include <string.h>
#include <unity.h>

#include "../../lib/fry_ui/display_presets.h"
#include "../support/cyd_mock.h"

using namespace fry;
using namespace fry::disp;
using fry::disptest::CydBus;

void setUp(void) {}
void tearDown(void) { setForbiddenOverrideForTest(nullptr, 0); }

// ---- the bench bytes ---------------------------------------------------------------------------------------------------------
struct BenchBus : fry::disptest::MockBus {
  int xptChannelCalls = 0;
  bool spiReadId(int cs, int dc, uint8_t cmd, uint8_t* buf, size_t n, bool) override {
    calls++;
    spiReads++;
    usePin(cs);
    usePin(dc);
    static const uint8_t d3Up[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    static const uint8_t d3Dn[6] = {0, 0, 0, 0, 0, 0};
    static const uint8_t p04Up[6] = {0, 0, 0, 0xFF, 0xFF, 0xFF};
    static const uint8_t p04Dn[6] = {0, 0, 0, 0, 0, 0};
    static const uint8_t st[6] = {0x00, 0x61, 0x00, 0x00, 0x00, 0x00};
    const uint8_t* src = st;
    if (cmd == 0xD3) src = pull > 0 ? d3Up : d3Dn;
    else if (cmd == 0x04) src = pull > 0 ? p04Up : p04Dn;
    for (size_t i = 0; i < n; i++) buf[i] = i < 6 ? src[i] : 0;
    return true;
  }
  int xpt2046Channels(int cs, uint16_t out[6]) override {
    calls++;
    xptChannelCalls++;
    usePin(cs);
    static const uint16_t v[6] = {0x32C, 0x32C, 0, 0, 0, 0xFFA};
    for (int i = 0; i < 6; i++) out[i] = v[i];
    return 1;
  }
};

void test_bench_cyd_raw_bytes_detect_ili9341_xpt2046_touchscreen() {
  BenchBus b;
  BoardPins p;
  TEST_ASSERT_TRUE(presetPins(PRESET_ESP32_CYD, p));
  Info i = probe(p, b, 400);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::ILI9341_240x320, (uint8_t)i.panel);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::XPT2046, (uint8_t)i.touch);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_TOUCHSCREEN, i.mode);
  TEST_ASSERT_EQUAL_HEX32(0x006100u, i.panelId);
  char line[200];
  formatProbeRaw(line, sizeof(line), i);
  TEST_ASSERT_EQUAL_STRING(
      "[ui] probe raw d3u=FFFFFFFFFFFF d3d=000000000000 d3bit=-1 04u=000000FFFFFF 04d=000000000000 04bit=-1 "
      "xpt=32C,32C,0,0,0,FFA xn=6 xv=1 st=00610000",
      line);
  // and through the preset boot probe
  BenchBus b2;
  Info best;
  BoardPins pins;
  bool have = false;
  TEST_ASSERT_EQUAL_UINT8(PRESET_ESP32_CYD, bootProbe(PRESET_ESP32_CYD, 0, PRESET_ESP32_OLED, nullptr, 0, b2, nullptr, 400, best, pins, have));
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_TOUCHSCREEN, best.mode);
}

// ---- both pulls ---------------------------------------------------------------------------------------------------------------
void test_status_fallback_needs_zero_first_byte_under_both_pulls() {
  // RDDID byte 0 follows the pull (0xFF up / 0x00 down): a floating line, not a clone driving zeros.
  struct FloatingId : BenchBus {
    bool spiReadId(int cs, int dc, uint8_t cmd, uint8_t* buf, size_t n, bool d) override {
      BenchBus::spiReadId(cs, dc, cmd, buf, n, d);
      if (cmd == 0x04 && pull > 0) memset(buf, 0xFF, n);
      return true;
    }
  } b;
  BoardPins p;
  presetPins(PRESET_ESP32_CYD, p);
  Info i = probe(p, b, 400);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::None, (uint8_t)i.panel);
  TEST_ASSERT_EQUAL_UINT8(FRY_DISP_NONE, i.mode);
  // And the other side: byte 0 is 0x00 under the pull-up but 0xFF under the pull-down (a line inverted against its pull).
  struct Inverted : BenchBus {
    bool spiReadId(int cs, int dc, uint8_t cmd, uint8_t* buf, size_t n, bool d) override {
      BenchBus::spiReadId(cs, dc, cmd, buf, n, d);
      if (cmd == 0x04) memset(buf, pull > 0 ? 0x00 : 0xFF, n);
      return true;
    }
  } c;
  Info j = probe(p, c, 400);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::None, (uint8_t)j.panel);
  // control: the bench bytes are accepted
  BenchBus ok;
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::ILI9341_240x320, (uint8_t)probe(p, ok, 400).panel);
}

void test_id_pattern_under_one_pull_only_is_rejected() {
  for (int pullSide = -1; pullSide <= 1; pullSide += 2) {
    CydBus b;
    b.panelKind = CydBus::ILI9341;
    b.d3OnlyUnderPull = pullSide;
    b.statusPresent = false;  // no RDDST fallback either: only the 0xD3 pattern could match
    BoardPins p;
    presetPins(PRESET_ESP32_CYD, p);
    Info i = probe(p, b, 400);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::None, (uint8_t)i.panel);
  }
  CydBus ok;  // control: the pattern under both pulls is accepted
  ok.panelKind = CydBus::ILI9341;
  BoardPins p;
  presetPins(PRESET_ESP32_CYD, p);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::ILI9341_240x320, (uint8_t)probe(p, ok, 400).panel);
}

// ---- probe-level touch pin check ---------------------------------------------------------------------------------------------
// CYD wiring on a chip whose forbidden list is the S3's (GPIO19-20, 26-37): TFT pins are fine, one touch pin at a time is not.
static BoardPins s3Cyd() {
  BoardPins p;
  presetPins(PRESET_ESP32_CYD, p);
  p.forbidden = kEsp32S3Forbidden;
  p.nForbidden = kEsp32S3ForbiddenCount;
  p.touchCs = 4;
  p.touchIrq = 5;
  p.touchSck = 18;
  p.touchMosi = 17;
  p.touchMiso = 16;
  return p;
}

void test_probe_drives_touch_bus_when_all_touch_pins_allowed_control() {
  CydBus b;
  b.panelKind = CydBus::ILI9341;
  b.xptBusPresent = true;
  Info i = probe(s3Cyd(), b, 400);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::XPT2046, (uint8_t)i.touch);
  TEST_ASSERT_TRUE(b.xptChannelCalls >= 1);
}

void test_probe_checks_each_touch_pin_before_any_touch_spi_op() {
  const char* names[5] = {"touchSck", "touchMosi", "touchMiso", "touchCs", "touchIrq"};
  for (int k = 0; k < 5; k++) {
    BoardPins p = s3Cyd();
    int* f[5] = {&p.touchSck, &p.touchMosi, &p.touchMiso, &p.touchCs, &p.touchIrq};
    *f[k] = 32;  // flash bus on S3
    CydBus b;
    b.panelKind = CydBus::ILI9341;
    b.xptBusPresent = true;
    Info i = probe(p, b, 400);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE((uint8_t)Panel::ILI9341_240x320, (uint8_t)i.panel, names[k]);  // TFT still fine
    TEST_ASSERT_EQUAL_UINT8_MESSAGE((uint8_t)Touch::None, (uint8_t)i.touch, names[k]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, b.xptChannelCalls + b.xptSamples, names[k]);
    TEST_ASSERT_FALSE_MESSAGE(b.pinWasUsed(32), names[k]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, i.raw.nXpt, names[k]);
  }
}

// ---- call sites: S3 forbidden list applied to the CYD preset's real wiring ----------------------------------------------------
struct Rec : BusHook {
  int selects = 0, releases = 0;
  BoardPins sel[4], rel[4];
  void select(uint8_t, const BoardPins& p) override {
    if (selects < 4) sel[selects] = p;
    selects++;
  }
  void release(const BoardPins& p) override {
    if (releases < 4) rel[releases] = p;
    releases++;
  }
};

static void assertTouchGated(const BoardPins& p) {
  TEST_ASSERT_EQUAL_INT(-1, p.touchCs);
  TEST_ASSERT_EQUAL_INT(-1, p.touchIrq);
  TEST_ASSERT_EQUAL_INT(-1, p.touchSck);
  TEST_ASSERT_EQUAL_INT(-1, p.touchMosi);
  TEST_ASSERT_EQUAL_INT(-1, p.touchMiso);
}

static void assertNoTouchTraffic(const CydBus& b) {
  TEST_ASSERT_EQUAL_INT(0, b.xptChannelCalls + b.xptSamples);
  for (size_t k = 0; k < kEsp32S3ForbiddenCount; k++) TEST_ASSERT_FALSE(b.pinWasUsed(kEsp32S3Forbidden[k]));
}

void test_preset_scope_gates_touch_bus_before_hook_and_probe() {
  setForbiddenOverrideForTest(kEsp32S3Forbidden, kEsp32S3ForbiddenCount);
  CydBus b;
  b.panelKind = CydBus::ILI9341;
  b.xptBusPresent = true;
  Rec h;
  Info best;
  BoardPins pins;
  bool have = false;
  bootProbe(PRESET_ESP32_CYD, 0, PRESET_ESP32_OLED, nullptr, 0, b, &h, 400, best, pins, have);
  TEST_ASSERT_EQUAL_INT(1, h.selects);
  assertTouchGated(h.sel[0]);  // the device bus is never told to claim the touch pins
  assertTouchGated(pins);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::ILI9341_240x320, (uint8_t)best.panel);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::None, (uint8_t)best.touch);
  assertNoTouchTraffic(b);
}

void test_candidates_scope_gates_touch_bus_before_hook_and_probe() {
  setForbiddenOverrideForTest(kEsp32S3Forbidden, kEsp32S3ForbiddenCount);
  CydBus b;
  b.panelKind = CydBus::ILI9341;
  b.xptBusPresent = true;
  Rec h;
  Info best;
  BoardPins pins;
  bool have = false;
  const uint8_t cands[1] = {PRESET_ESP32_CYD};
  const uint8_t r = bootProbe(0, 2 /*Screen*/, PRESET_ESP32_OLED, cands, 1, b, &h, 400, best, pins, have);
  TEST_ASSERT_EQUAL_UINT8(PRESET_ESP32_CYD, r);
  TEST_ASSERT_EQUAL_INT(1, h.selects);
  assertTouchGated(h.sel[0]);
  assertTouchGated(h.rel[0]);
  assertTouchGated(pins);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::None, (uint8_t)best.touch);
  assertNoTouchTraffic(b);
}

void test_autodetect_scope_never_drives_forbidden_touch_bus() {
  setForbiddenOverrideForTest(kEsp32S3Forbidden, kEsp32S3ForbiddenCount);
  CydBus b;
  b.panelKind = CydBus::ILI9341;
  b.xptBusPresent = true;
  Info best;
  const uint8_t cands[1] = {PRESET_ESP32_CYD};
  TEST_ASSERT_EQUAL_UINT8(PRESET_ESP32_CYD, autodetect(cands, 1, b, 400, best));
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Panel::ILI9341_240x320, (uint8_t)best.panel);
  TEST_ASSERT_EQUAL_UINT8((uint8_t)Touch::None, (uint8_t)best.touch);
  assertNoTouchTraffic(b);
}

void test_gate_touch_bus_checks_all_five_pins() {
  BoardPins ok = s3Cyd();
  TEST_ASSERT_EQUAL_INT(4, gateTouchBus(PRESET_ESP32_CYD, ok).touchCs);  // control: nothing forbidden, nothing gated
  for (int k = 0; k < 5; k++) {
    BoardPins p = ok;
    int* f[5] = {&p.touchSck, &p.touchMosi, &p.touchMiso, &p.touchCs, &p.touchIrq};
    *f[k] = 36;
    assertTouchGated(gateTouchBus(PRESET_ESP32_CYD, p));
  }
}

// ---- unchanged safety ----------------------------------------------------------------------------------------------------------
void test_no_preset_zero_spi_and_none_zero_polling() {
  CydBus b;
  b.panelKind = CydBus::ILI9341;
  b.xptBusPresent = true;
  Info best;
  BoardPins pins;
  bool have = false;
  const uint8_t cands[2] = {PRESET_ESP32_OLED, PRESET_ESP32_CYD};
  bootProbe(0, 0, PRESET_ESP32_OLED, cands, 2, b, nullptr, 400, best, pins, have);
  TEST_ASSERT_EQUAL_INT(0, b.spiReads + b.pullSets + b.xptChannelCalls + b.xptSamples);
  CydBus n;
  bootProbe(PRESET_ESP32_CYD, 1, PRESET_ESP32_OLED, cands, 2, n, nullptr, 400, best, pins, have);
  TEST_ASSERT_EQUAL_INT(0, n.calls);
  TEST_ASSERT_FALSE(shouldPoll(FRY_DISP_NONE));
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_bench_cyd_raw_bytes_detect_ili9341_xpt2046_touchscreen);
  RUN_TEST(test_status_fallback_needs_zero_first_byte_under_both_pulls);
  RUN_TEST(test_id_pattern_under_one_pull_only_is_rejected);
  RUN_TEST(test_probe_drives_touch_bus_when_all_touch_pins_allowed_control);
  RUN_TEST(test_probe_checks_each_touch_pin_before_any_touch_spi_op);
  RUN_TEST(test_preset_scope_gates_touch_bus_before_hook_and_probe);
  RUN_TEST(test_candidates_scope_gates_touch_bus_before_hook_and_probe);
  RUN_TEST(test_autodetect_scope_never_drives_forbidden_touch_bus);
  RUN_TEST(test_gate_touch_bus_checks_all_five_pins);
  RUN_TEST(test_no_preset_zero_spi_and_none_zero_polling);
  return UNITY_END();
}
