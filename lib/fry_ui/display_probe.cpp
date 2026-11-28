// Bounded boot probe + config resolve for the 3 display modes (NONE / SCREEN_ONLY / TOUCHSCREEN).
//
// Safety properties, each pinned by test/test_display_probe:
//  - A bus whose pin list touches a forbidden pin (ESP32-S3 GPIO19-20, 26-37 ...) is never driven.
//  - Time is bounded: every operation is charged its worst-case time against the caller's budget and
//    the probe stops starting new steps once it is spent. Bus recovery runs at most kMaxRecoveries times.
//  - A floating or stuck line never counts as a device: SPI ID reads are taken with MISO pulled up and
//    pulled down (a driven line returns the same bytes both times) and all-0x00 / all-0xFF is rejected;
//    I2C register values of 0x00 / 0xFF are rejected; a bus that ACKs the reserved address 0x7E is stuck.
//  - ILI9341 RDID4 (0xD3) is 'dummy clock, [dummy byte], 0x00 0x93 0x41' and RDDID (0x04) is all zero on many modules, so the ID is
//    searched at any bit offset of a 6-byte read and must be found under BOTH MISO pulls (a floating line follows the pull and can
//    never contain the pattern under both). The XPT2046 (CYD GPIO39 has no internal pull) is judged by its temperature channel:
//    mid-range, two reads agreeing, not every channel identical.
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

const size_t kIdRead = 6;

// 24 bits of `raw` starting at bit `off` (MSB first).
uint32_t bits24(const uint8_t* raw, size_t n, int off) {
  uint32_t v = 0;
  for (int i = 0; i < 24; i++) {
    const int bit = off + i;
    const size_t by = (size_t)(bit >> 3);
    const uint8_t b = by < n ? (uint8_t)((raw[by] >> (7 - (bit & 7))) & 1) : 0;
    v = (v << 1) | b;
  }
  return v;
}

// Bit offset of the first occurrence of the 3-byte pattern (a,b,c) in raw[0..n), or -1. Offsets cover a dummy clock and a dummy byte.
int findId(const uint8_t* raw, size_t n, uint8_t a, uint8_t b, uint8_t c) {
  const uint32_t want = ((uint32_t)a << 16) | ((uint32_t)b << 8) | c;
  const int last = (int)(n * 8) - 24;
  for (int off = 0; off <= last; off++)
    if (bits24(raw, n, off) == want) return off;
  return -1;
}

// One ID command read twice, MISO pulled up then pulled down. Both raw reads are returned.
bool readIdPulled(Ctx& c, uint8_t cmd, uint8_t* up, uint8_t* dn) {
  memset(up, 0, kIdRead);
  memset(dn, 0, kIdRead);
  bool ok1 = false, ok2 = false;
  if (c.ok()) {
    c.bus.setMisoPull(c.pins.spiMiso, +1);
    c.charge(kSpiOpUs);
    ok1 = c.bus.spiReadId(c.pins.tftCs, c.pins.tftDc, cmd, up, kIdRead, true);
  }
  if (c.ok() || ok1) {
    c.bus.setMisoPull(c.pins.spiMiso, -1);
    c.charge(kSpiOpUs);
    ok2 = c.bus.spiReadId(c.pins.tftCs, c.pins.tftDc, cmd, dn, kIdRead, true);
  }
  c.bus.setMisoPull(c.pins.spiMiso, 0);
  return ok1 && ok2;
}

// The 3-byte ID (a,b,c) is present in both pulled reads. A line that only follows its pull never matches.
bool idPresent(const uint8_t* up, const uint8_t* dn, uint8_t a, uint8_t b, uint8_t c, int8_t* bitOut) {
  const int o1 = findId(up, kIdRead, a, b, c);
  const int o2 = findId(dn, kIdRead, a, b, c);
  if (o1 < 0 || o2 < 0) return false;
  *bitOut = (int8_t)o1;
  return true;
}

// Legacy anti-floating rule on the first three bytes (identical under both pulls, never all 0x00 / 0xFF).
bool stableFirst3(const uint8_t* up, const uint8_t* dn) {
  if (memcmp(up, dn, 3) != 0) return false;
  return !allSame(up, 3, 0x00) && !allSame(up, 3, 0xFF);
}

// LovyanGFX-style ILI9341 acceptance for clones that do not return 00 93 41: RDDID (0x04) byte 0 is 0x00 under BOTH pulls (a floating
// line follows the pull-up, so it cannot be 0x00 there) and RDDST (0x09) is a driven, non-zero, non-0xFF 4-byte status (identical under
// both pulls). A line stuck low reads 0x00 for RDDST and a line stuck high 0xFF, so neither passes.
bool ili9341StatusFallback(Ctx& c, ProbeRaw& rw) {
  if (rw.id04Up[0] != 0x00 || rw.id04Dn[0] != 0x00 || !c.ok()) return false;
  uint8_t up[kIdRead], dn[kIdRead];
  if (!readIdPulled(c, 0x09, up, dn)) return false;
  memcpy(rw.st, up, 4);
  rw.nSt = 4;
  if (memcmp(up, dn, 4) != 0) return false;
  return !allSame(up, 4, 0x00) && !allSame(up, 4, 0xFF);
}

// XPT2046 aux channels: the die temperature (TEMP0, ~590 mV at 25 C = mid-range) is read twice; a driven converter gives a
// non-saturated value that repeats, a floating MISO gives 0 / 4095 / noise. All six channels equal is a stuck or floating line.
bool xptChannelsPlausible(const uint16_t ch[6]) {
  for (int i = 0; i < 6; i++)
    if (ch[i] > 0xFFF) return false;
  const uint16_t t1 = ch[0], t2 = ch[1];
  if (t1 < 300 || t1 > 2400 || t2 < 300 || t2 > 2400) return false;
  const int d = (int)t1 - (int)t2;
  if (d > 48 || d < -48) return false;
  bool allEq = true;
  for (int i = 1; i < 6; i++)
    if (ch[i] != ch[0]) allEq = false;
  return !allEq;
}

bool xptLegacyPlausible(Ctx& c, ProbeRaw& raw) {
  uint16_t x = 0, y = 0, z = 0;
  bool anyNonZero = false, anyNotFull = false;
  for (int k = 0; k < 3; k++) {
    if (!c.ok()) return false;
    c.charge(kSpiOpUs);
    if (!c.bus.xpt2046Sample(c.pins.touchCs, &x, &y, &z)) return false;
    raw.nXpt = 3;
    raw.xpt[0] = x;
    raw.xpt[1] = y;
    raw.xpt[2] = z;
    if (x > 0xFFF || y > 0xFFF || z > 0xFFF) return false;  // not a 12-bit converter result
    if (x || y || z) anyNonZero = true;
    if (x != 0xFFF || y != 0xFFF || z != 0xFFF) anyNotFull = true;
  }
  return anyNonZero && anyNotFull;
}

bool xptPlausible(Ctx& c, ProbeRaw& raw) {
  if (!c.ok()) return false;
  uint16_t ch[6] = {0, 0, 0, 0, 0, 0};
  c.charge(kSpiOpUs);
  const int r = c.bus.xpt2046Channels(c.pins.touchCs, ch);
  if (r < 0) return xptLegacyPlausible(c, raw);  // bus has no channel read: x/y/z sample rule
  raw.nXpt = 6;
  for (int i = 0; i < 6; i++) raw.xpt[i] = ch[i];
  if (r == 0) return false;
  if (!xptChannelsPlausible(ch)) return false;
  // Two full reads must both be plausible and agree on the die temperature: noise on a floating MISO cannot do that.
  const uint16_t t = ch[0];
  if (!c.ok()) return false;
  c.charge(kSpiOpUs);
  if (c.bus.xpt2046Channels(c.pins.touchCs, ch) != 1) return false;
  for (int i = 0; i < 6; i++) raw.xpt[i] = ch[i];
  if (!xptChannelsPlausible(ch)) return false;
  const int d = (int)ch[0] - (int)t;
  return d <= 48 && d >= -48;
}

Info blank() {
  Info i;
  memset(&i, 0, sizeof(i));
  i.mode = FRY_DISP_NONE;
  i.panel = Panel::None;
  i.touch = Touch::None;
  i.raw.d3Bit = i.raw.id04Bit = -1;
  i.raw.xptVerdict = -1;
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
      ProbeRaw& rw = r.raw;
      uint8_t* up = rw.d3Up;
      uint8_t* dn = rw.d3Dn;
      bool matched = false;
      if (readIdPulled(c, 0xD3, up, dn)) {
        rw.nD3 = (uint8_t)kIdRead;
        if (idPresent(up, dn, 0x00, 0x93, 0x41, &rw.d3Bit)) {
          r.panel = Panel::ILI9341_240x320;
          r.width = 240;
          r.height = 320;
          r.panelId = 0x009341u;
          matched = true;
        }
      }
      if (!matched && c.ok() && readIdPulled(c, 0x04, rw.id04Up, rw.id04Dn)) {
        rw.n04 = (uint8_t)kIdRead;
        if (idPresent(rw.id04Up, rw.id04Dn, 0x85, 0x85, 0x52, &rw.id04Bit)) {
          r.panel = Panel::ST7789_240x240;
          r.width = r.height = 240;
          r.panelId = 0x858552u;
        } else if (idPresent(rw.id04Up, rw.id04Dn, 0x7C, 0x89, 0xF0, &rw.id04Bit)) {
          r.panel = Panel::ST7735_128x160;
          r.width = 128;
          r.height = 160;
          r.panelId = 0x7C89F0u;
        } else if (idPresent(rw.id04Up, rw.id04Dn, 0x00, 0x93, 0x41, &rw.id04Bit)) {
          r.panel = Panel::ILI9341_240x320;
          r.width = 240;
          r.height = 320;
          r.panelId = 0x009341u;
        } else if (ili9341StatusFallback(c, rw)) {
          // LovyanGFX's own CYD detector: RDDID first byte 0x00 and RDDST nonzero. Accepted only when driven (identical under both pulls).
          r.panel = Panel::ILI9341_240x320;
          r.width = 240;
          r.height = 320;
          r.panelId = ((uint32_t)rw.st[0] << 16) | ((uint32_t)rw.st[1] << 8) | rw.st[2];
        } else if (stableFirst3(rw.id04Up, rw.id04Dn)) {
          r.panelId = ((uint32_t)rw.id04Up[0] << 16) | ((uint32_t)rw.id04Up[1] << 8) | rw.id04Up[2];  // unknown, kept for the log
        }
      }
    }
  }

  // 3a. XPT2046 on SPI: read whenever the pin set declares it (touchCs >= 0 only in preset / explicit-mode scopes; the I2C-only default
  // scope clears it, so no-preset boards drive nothing). Done even when the TFT id read failed so the touch bus is diagnosable and the
  // controller is confirmed on its own; the mode still needs a panel.
  if (pins.touchCs >= 0 && pins.spiSck >= 0 && pins.spiMiso >= 0 && !(pins.touchSda >= 0 && pins.touchScl >= 0)) {
    const int xp[4] = {pins.spiSck, pins.spiMosi, pins.spiMiso, pins.touchCs};
    if (allPinsAllowed(pins, xp, 4)) {
      r.raw.xptVerdict = 0;
      if (xptPlausible(c, r.raw)) {
        r.touch = Touch::XPT2046;
        r.raw.xptVerdict = 1;
      }
    }
  }

  // 3b. I2C touch, only when a display answered (nothing is driven for a board with no screen).
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
    r.mode = r.touch != Touch::None ? FRY_DISP_TOUCHSCREEN : FRY_DISP_SCREEN_ONLY;
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
