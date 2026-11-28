// Bus model of the bench CYD (ESP32-2432S028R): what the real ILI9341 / ST7789 put on MISO after a read command, including
// the dummy clock / dummy byte, and an XPT2046 on its own bus whose MISO (GPIO39) has no pull.
#ifndef FRY_TEST_CYD_MOCK_H
#define FRY_TEST_CYD_MOCK_H

#include "display_mock.h"

namespace fry {
namespace disptest {

struct CydBus : MockBus {
  enum Panel { NONE, ILI9341, ST7789, STUCK_LOW, STUCK_HIGH };
  Panel panelKind = NONE;
  // ILI9341 RDDID (0x04) returns zeros on many modules; RDID4 (0xD3) = dummy byte, 0x00 0x93 0x41.
  bool d3HasDummyByte = true;
  bool st7789HasDummyByte = false;  // false: 85 85 52 straight after the dummy clock; true: one extra byte first
  // Clone knobs: 0xD3 pattern absent, only under one MISO pull, RDDST (0x09) absent / undriven.
  bool d3Works = true;
  int d3OnlyUnderPull = 0;     // +1: the 00 93 41 stream is only driven while MISO is pulled up, -1: only while pulled down
  bool statusPresent = true;   // RDDST returns a driven non-zero status (61 00 00 00)
  bool statusFollowsPull = false;
  bool dummyFollowsPull = true;     // the dummy byte is undefined: it tracks the MISO pull

  // XPT2046 on CLK25 MOSI32 MISO39 CS33. present=false -> MISO floats (no pull on GPIO39).
  bool xptBusPresent = false;
  uint16_t floatLevel = 0;  // what a floating GPIO39 reads (12-bit), when !xptBusPresent
  bool floatNoisy = false;  // floating line reads pseudo-random 12-bit values
  uint32_t lfsr = 0x1234567u;
  uint16_t noise() {
    lfsr = lfsr * 1664525u + 1013904223u;
    return (uint16_t)((lfsr >> 16) & 0xFFF);
  }
  int xptChannelCalls = 0;
  bool supportChannels = true;

  uint8_t dummyByte() const { return dummyFollowsPull ? (pull > 0 ? 0xFF : (pull < 0 ? 0x00 : 0x55)) : 0x3C; }

  bool spiReadId(int cs, int dc, uint8_t cmd, uint8_t* buf, size_t n, bool) {
    calls++;
    spiReads++;
    usePin(cs);
    usePin(dc);
    spentUs += 300;
    uint8_t s[12];
    size_t k = 0;
    const uint8_t fl = pull > 0 ? 0xFF : (pull < 0 ? 0x00 : 0x55);
    if (panelKind == NONE) {
      for (; k < 12; k++) s[k] = fl;  // nothing drives MISO
    } else if (panelKind == STUCK_LOW || panelKind == STUCK_HIGH) {
      for (; k < 12; k++) s[k] = panelKind == STUCK_LOW ? 0x00 : 0xFF;
    } else if (panelKind == ILI9341) {
      const bool d3Driven = d3Works && (d3OnlyUnderPull == 0 || (d3OnlyUnderPull > 0 && pull > 0) || (d3OnlyUnderPull < 0 && pull < 0));
      if (cmd == 0xD3 && d3Driven) {
        if (d3HasDummyByte) s[k++] = dummyByte();
        s[k++] = 0x00;
        s[k++] = 0x93;
        s[k++] = 0x41;
      } else if (cmd == 0x09 && statusPresent) {
        s[k++] = statusFollowsPull ? fl : 0x61;
        s[k++] = 0x00;
        s[k++] = 0x00;
        s[k++] = 0x00;
      }
      for (; k < 12; k++) s[k] = 0x00;  // 0xD3 (absent) / 0x04: a clone drives zeros
    } else {  // ST7789
      if (cmd == 0x04) {
        if (st7789HasDummyByte) s[k++] = dummyByte();
        s[k++] = 0x85;
        s[k++] = 0x85;
        s[k++] = 0x52;
      }
      for (; k < 12; k++) s[k] = 0x00;
    }
    for (size_t i = 0; i < n; i++) buf[i] = i < 12 ? s[i] : 0x00;
    return true;
  }

  bool xpt2046Sample(int cs, uint16_t* x, uint16_t* y, uint16_t* z) {
    calls++;
    xptSamples++;
    usePin(cs);
    spentUs += 300;
    if (xptBusPresent) {
      *x = 1900; *y = 2050; *z = 0;
    } else {
      *x = *y = *z = floatLevel;
    }
    return true;
  }

  int xpt2046Channels(int cs, uint16_t out[6]) {
    if (!supportChannels) return -1;
    calls++;
    xptChannelCalls++;
    usePin(cs);
    spentUs += 300;
    if (xptBusPresent) {
      static const uint16_t v[6] = {985, 986, 3100, 1500, 12, 4010};  // temp0 ~590 mV, vbat/4, aux, idle z1/z2
      for (int i = 0; i < 6; i++) out[i] = v[i];
    } else {
      for (int i = 0; i < 6; i++) out[i] = floatNoisy ? noise() : floatLevel;
    }
    return 1;
  }
};

}  // namespace disptest
}  // namespace fry

#endif  // FRY_TEST_CYD_MOCK_H
