// Bounded boot probe + config resolve for the 3 display modes (NONE / SCREEN_ONLY / TOUCHSCREEN).
//
// Safety properties, each pinned by test/test_display_probe:
//  - A bus whose pin list touches a forbidden pin (ESP32-S3 GPIO19-20, 26-37 ...) is never driven.
//  - Time is bounded: every operation is charged its worst-case time against the caller's budget and
//    the probe stops starting new steps once it is spent. Bus recovery runs at most kMaxRecoveries times.
//  - A floating or stuck line never counts as a device: SPI ID reads are taken with MISO pulled up and
//    pulled down (a driven line returns the same bytes both times) and all-0x00 / all-0xFF is rejected;
//    I2C register values of 0x00 / 0xFF are rejected; a bus that ACKs the reserved address 0x7E is stuck.
#include <string.h>

#include "display_presets.h"

namespace fry {
namespace disp {

namespace {

const uint32_t kI2cTimeoutUs = 2000;
const uint32_t kI2cRecoverUs = 1000;
const uint32_t kSpiOpUs = 600;
const int kMaxRecoveries = 3;

struct Ctx {
  BusOps& bus;
  const BoardPins& pins;
  uint64_t spentUs;
  uint64_t limitUs;
  int recoveries;
  bool ok() const { return spentUs < limitUs; }
  void charge(uint32_t us) { spentUs += us; }
  void recover() {
    if (recoveries >= kMaxRecoveries) return;
    recoveries++;
    charge(kI2cRecoverUs);
    bus.i2cRecover();
  }
};

bool allPinsAllowed(const BoardPins& p, const int* pins, size_t n) {
  for (size_t i = 0; i < n; i++)
    if (pinForbidden(p, pins[i])) return false;
  return true;
}

bool ack(Ctx& c, uint8_t addr) {
  if (!c.ok()) return false;
  c.charge(kI2cTimeoutUs);
  return c.bus.i2cProbe(addr, kI2cTimeoutUs);
}

bool readReg(Ctx& c, uint8_t addr, uint16_t reg, bool reg16, uint8_t* buf, size_t n) {
  if (!c.ok()) return false;
  c.charge(kI2cTimeoutUs);
  return c.bus.i2cReadReg(addr, reg, reg16, buf, n, kI2cTimeoutUs);
}

bool plausible(uint8_t v) { return v != 0x00 && v != 0xFF; }

// Start an I2C session on (sda,scl): begin, one recovery pulse, and a stuck-bus check.
bool i2cOpen(Ctx& c, int sda, int scl) {
  if (sda < 0 || scl < 0 || !c.ok()) return false;
  const int pair[2] = {sda, scl};
  if (!allPinsAllowed(c.pins, pair, 2)) return false;
  if (!c.bus.i2cBegin(sda, scl, 100000)) return false;
  c.recover();
  if (ack(c, 0x7E)) {  // reserved address: nothing may answer. A bus held low "ACKs" everything.
    c.recover();
    return false;
  }
  return true;
}

Touch detectI2cTouch(Ctx& c, uint8_t* addr) {
  uint8_t b[4];
  if (ack(c, 0x15)) {  // CST816S / CST716: chip id at 0xA7
    bool got = readReg(c, 0x15, 0xA7, false, b, 1);
    if (!got) {
      c.recover();
      got = readReg(c, 0x15, 0xA7, false, b, 1);
    }
    if (got && plausible(b[0]) && b[0] >= 0xB4 && b[0] <= 0xB7) {
      *addr = 0x15;
      return Touch::CST816S;
    }
  }
  if (ack(c, 0x38)) {  // FT6236 / FT6336: vendor id 0x11 at 0xA8, chip id at 0xA3
    bool v = readReg(c, 0x38, 0xA8, false, b, 1);
    bool i = false;
    uint8_t cid = 0;
    if (v && plausible(b[0]) && b[0] == 0x11) {
      *addr = 0x38;
      return Touch::FT6236;
    }
    i = readReg(c, 0x38, 0xA3, false, b, 1);
    cid = b[0];
    if (!v && !i) {
      c.recover();
      i = readReg(c, 0x38, 0xA3, false, b, 1);
      cid = b[0];
    }
    if (i && plausible(cid) && (cid == 0x06 || cid == 0x36 || cid == 0x64)) {
      *addr = 0x38;
      return Touch::FT6236;
    }
  }
  const uint8_t gt[2] = {0x5D, 0x14};
  for (int k = 0; k < 2; k++) {
    if (!ack(c, gt[k])) continue;
    bool got = readReg(c, gt[k], 0x8140, true, b, 4);
    if (!got) {
      c.recover();
      got = readReg(c, gt[k], 0x8140, true, b, 4);
    }
    if (got && b[0] == '9' && b[1] == '1' && b[2] == '1') {  // product id "911"
      *addr = gt[k];
      return Touch::GT911;
    }
  }
  return Touch::None;
}

bool allSame(const uint8_t* b, size_t n, uint8_t v) {
  for (size_t i = 0; i < n; i++)
    if (b[i] != v) return false;
  return true;
}

// Anti-floating-MISO ID read: identical bytes under pull-up and pull-down, never all 0x00 / 0xFF.
bool readIdGuarded(Ctx& c, uint8_t cmd, uint8_t out[3]) {
  uint8_t up[3] = {0, 0, 0}, dn[3] = {0, 0, 0};
  bool ok1 = false, ok2 = false;
  if (c.ok()) {
    c.bus.setMisoPull(c.pins.spiMiso, +1);
    c.charge(kSpiOpUs);
    ok1 = c.bus.spiReadId(c.pins.tftCs, c.pins.tftDc, cmd, up, 3, true);
  }
  if (c.ok() || ok1) {
    c.bus.setMisoPull(c.pins.spiMiso, -1);
    c.charge(kSpiOpUs);
    ok2 = c.bus.spiReadId(c.pins.tftCs, c.pins.tftDc, cmd, dn, 3, true);
  }
  c.bus.setMisoPull(c.pins.spiMiso, 0);
  if (!ok1 || !ok2) return false;
  if (memcmp(up, dn, 3) != 0) return false;  // line followed the pull: floating
  if (allSame(up, 3, 0x00) || allSame(up, 3, 0xFF)) return false;
  memcpy(out, up, 3);
  return true;
}

bool xptPlausible(Ctx& c) {
  uint16_t x = 0, y = 0, z = 0;
  bool anyNonZero = false, anyNotFull = false;
  for (int k = 0; k < 3; k++) {
    if (!c.ok()) return false;
    c.charge(kSpiOpUs);
    if (!c.bus.xpt2046Sample(c.pins.touchCs, &x, &y, &z)) return false;
    if (x > 0xFFF || y > 0xFFF || z > 0xFFF) return false;  // not a 12-bit converter result
    if (x || y || z) anyNonZero = true;
    if (x != 0xFFF || y != 0xFFF || z != 0xFFF) anyNotFull = true;
  }
  return anyNonZero && anyNotFull;
}

Info blank() {
  Info i;
  memset(&i, 0, sizeof(i));
  i.mode = FRY_DISP_NONE;
  i.panel = Panel::None;
  i.touch = Touch::None;
  return i;
}

}  // namespace

Info probe(const BoardPins& pins, BusOps& bus, uint32_t budgetMs) {
  Ctx c = {bus, pins, 0, (uint64_t)budgetMs * 1000u, 0};
  Info r = blank();

  // 1. OLED on the display I2C bus.
  if (i2cOpen(c, pins.sda, pins.scl)) {
    if (ack(c, 0x3C)) {
      r.panel = Panel::SSD1306_128x64;
      r.i2cAddr = 0x3C;
    } else if (ack(c, 0x3D)) {
      r.panel = Panel::SSD1306_128x64;
      r.i2cAddr = 0x3D;
    }
    if (r.panel != Panel::None) {
      r.width = 128;
      r.height = 64;
      r.mono = true;
    }
  }

  // 2. SPI TFT: only when every pin of its bus is allowed.
  if (r.panel == Panel::None && pins.spiSck >= 0 && pins.spiMiso >= 0 && pins.tftCs >= 0 && pins.tftDc >= 0) {
    const int bp[7] = {pins.spiSck, pins.spiMosi, pins.spiMiso, pins.tftCs, pins.tftDc, pins.tftRst, pins.tftBl};
    if (allPinsAllowed(pins, bp, 7) && c.ok()) {
      uint8_t id[3];
      if (readIdGuarded(c, 0xD3, id) && id[1] == 0x93 && id[2] == 0x41) {
        r.panel = Panel::ILI9341_240x320;
        r.width = 240;
        r.height = 320;
        r.panelId = ((uint32_t)id[0] << 16) | ((uint32_t)id[1] << 8) | id[2];
      } else if (readIdGuarded(c, 0x04, id)) {
        r.panelId = ((uint32_t)id[0] << 16) | ((uint32_t)id[1] << 8) | id[2];
        if (id[0] == 0x85 && id[1] == 0x85 && id[2] == 0x52) {
          r.panel = Panel::ST7789_240x240;
          r.width = r.height = 240;
        } else if (id[0] == 0x7C && id[1] == 0x89 && id[2] == 0xF0) {
          r.panel = Panel::ST7735_128x160;
          r.width = 128;
          r.height = 160;
        } else if (id[0] == 0x00 && id[1] == 0x93 && id[2] == 0x41) {
          r.panel = Panel::ILI9341_240x320;
          r.width = 240;
          r.height = 320;
        }
      }
    }
  }

  // 3. Touch, only when a display answered (nothing is driven for a board with no screen).
  if (r.panel != Panel::None) {
    const bool sepI2c = pins.touchSda >= 0 && pins.touchScl >= 0;
    const int tsda = sepI2c ? pins.touchSda : pins.sda;
    const int tscl = sepI2c ? pins.touchScl : pins.scl;
    bool opened = false;
    if (sepI2c && i2cOpen(c, tsda, tscl)) opened = true;
    if (opened) {
      uint8_t a = 0;
      Touch t = detectI2cTouch(c, &a);
      if (t != Touch::None) {
        r.touch = t;
        r.touchAddr = a;
      }
    }
    if (r.touch == Touch::None && pins.touchCs >= 0 && pins.spiSck >= 0 && pins.spiMiso >= 0) {
      const int xp[4] = {pins.spiSck, pins.spiMosi, pins.spiMiso, pins.touchCs};
      if (allPinsAllowed(pins, xp, 4) && xptPlausible(c)) r.touch = Touch::XPT2046;
    }
    r.mode = r.touch != Touch::None ? FRY_DISP_TOUCHSCREEN : FRY_DISP_SCREEN_ONLY;
  } else {
    r.touch = Touch::None;
  }
  return r;
}

Info resolve(const Info& probed, uint8_t displayModeOverride, uint8_t preset) {
  Info r = probed;
  Info declared;
  const bool havePreset = presetInfo(preset, declared);
  const uint8_t ov = displayModeOverride;  // cfg::DisplayMode: 0 Auto, 1 None, 2 Screen, 3 Touch

  if (ov == 1) return blank();

  // A preset states what is wired. It fills in whatever the probe did not find when the owner forced a
  // mode, or when nothing at all was found.
  if (havePreset && (ov >= 2 || probed.mode == FRY_DISP_NONE)) {
    if (r.panel == Panel::None) {
      r.panel = declared.panel;
      r.width = declared.width;
      r.height = declared.height;
      r.mono = declared.mono;
      r.i2cAddr = declared.i2cAddr;
    }
    if (r.touch == Touch::None && ov != 2) {
      r.touch = declared.touch;
      r.touchAddr = declared.touchAddr;
    }
  }
  if (ov == 2) {
    r.touch = Touch::None;
    r.touchAddr = 0;
  }
  if (r.panel == Panel::None) return blank();
  r.mode = r.touch != Touch::None ? FRY_DISP_TOUCHSCREEN : FRY_DISP_SCREEN_ONLY;
  return r;
}

}  // namespace disp
}  // namespace fry
