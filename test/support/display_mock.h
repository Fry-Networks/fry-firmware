// Scripted bus for the display probe tests. Records every pin and call the probe makes.
#ifndef FRY_TEST_DISPLAY_MOCK_H
#define FRY_TEST_DISPLAY_MOCK_H

#include <string.h>

#include "../../include/fry_display_hal.h"

namespace fry {
namespace disptest {

struct MockBus : disp::BusOps {
  // --- scripted hardware
  bool oled3C = false, oled3D = false;
  struct Reg {
    uint8_t addr;
    uint16_t reg;
    uint8_t val[4];
    uint8_t n;
  };
  Reg regs[8];
  int nRegs = 0;
  bool ackOnlyNoRead = false;     // address ACKs but register reads fail (hung slave)
  bool everythingTimesOut = false;  // every op burns its full timeout and fails
  bool i2cAckAll = false;         // a stuck-low bus that "ACKs" everything
  // SPI TFT: id bytes per command; mode: 0 absent (floating MISO), 1 present, 2 stuck low, 3 stuck high
  int tftMode = 0;
  uint8_t id04[3] = {0, 0, 0};
  uint8_t idD3[3] = {0, 0, 0};
  bool xptPresent = false;
  uint16_t xptX = 1800, xptY = 2100, xptZ = 0;
  int xptFloatMode = 0;  // 0 normal, 1 all zero, 2 all 0xFFF

  // --- recording
  int pull = 0;
  int calls = 0, i2cBegins = 0, i2cProbes = 0, i2cReads = 0, recovers = 0, spiReads = 0, pullSets = 0, xptSamples = 0;
  uint64_t spentUs = 0;
  int pinsUsed[64];
  int nPins = 0;
  void usePin(int p) {
    if (p >= 0 && nPins < 64) pinsUsed[nPins++] = p;
  }
  bool pinWasUsed(int p) const {
    for (int i = 0; i < nPins; i++)
      if (pinsUsed[i] == p) return true;
    return false;
  }
  void addReg(uint8_t addr, uint16_t reg, uint8_t a, uint8_t b = 0, uint8_t c = 0, uint8_t d = 0, uint8_t n = 1) {
    Reg& r = regs[nRegs++];
    r.addr = addr;
    r.reg = reg;
    r.val[0] = a;
    r.val[1] = b;
    r.val[2] = c;
    r.val[3] = d;
    r.n = n;
  }

  bool i2cBegin(int sda, int scl, uint32_t) override {
    calls++;
    i2cBegins++;
    usePin(sda);
    usePin(scl);
    return true;
  }
  bool i2cProbe(uint8_t addr, uint32_t timeoutUs) override {
    calls++;
    i2cProbes++;
    if (everythingTimesOut) {
      spentUs += timeoutUs;
      return false;
    }
    spentUs += 100;
    if (i2cAckAll) return true;
    if (addr == 0x3C) return oled3C;
    if (addr == 0x3D) return oled3D;
    for (int i = 0; i < nRegs; i++)
      if (regs[i].addr == addr) return true;
    spentUs += timeoutUs / 4;  // a NACK costs a little
    return false;
  }
  bool i2cReadReg(uint8_t addr, uint16_t reg, bool, uint8_t* buf, size_t n, uint32_t timeoutUs) override {
    calls++;
    i2cReads++;
    if (everythingTimesOut || ackOnlyNoRead) {
      spentUs += timeoutUs;
      return false;
    }
    spentUs += 100;
    if (i2cAckAll) {
      memset(buf, 0xFF, n);
      return true;
    }
    for (int i = 0; i < nRegs; i++)
      if (regs[i].addr == addr && regs[i].reg == reg) {
        for (size_t k = 0; k < n; k++) buf[k] = k < regs[i].n ? regs[i].val[k] : 0;
        return true;
      }
    return false;  // register not implemented: NACK
  }
  void i2cRecover() override {
    calls++;
    recovers++;
    spentUs += 1000;
  }
  bool spiReadId(int cs, int dc, uint8_t cmd, uint8_t* buf, size_t n, bool) override {
    calls++;
    spiReads++;
    usePin(cs);
    usePin(dc);
    spentUs += 300;
    if (everythingTimesOut) {
      spentUs += 5000;
      return false;
    }
    const uint8_t* src = cmd == 0x04 ? id04 : idD3;
    for (size_t k = 0; k < n; k++) {
      uint8_t v = 0;
      if (tftMode == 1) v = src[k < 3 ? k : 2];
      else if (tftMode == 2) v = 0x00;
      else if (tftMode == 3) v = 0xFF;
      else v = pull > 0 ? 0xFF : (pull < 0 ? 0x00 : 0x55);  // floating: follows whatever pulls it
      buf[k] = v;
    }
    return true;
  }
  void setMisoPull(int miso, int p) override {
    calls++;
    pullSets++;
    usePin(miso);
    pull = p;
  }
  bool xpt2046Sample(int cs, uint16_t* x, uint16_t* y, uint16_t* z) override {
    calls++;
    xptSamples++;
    usePin(cs);
    spentUs += 300;
    if (!xptPresent && xptFloatMode == 0) return false;
    if (xptFloatMode == 1) {
      *x = *y = *z = 0;
    } else if (xptFloatMode == 2) {
      *x = *y = *z = 0xFFF;
    } else {
      *x = xptX;
      *y = xptY;
      *z = xptZ;
    }
    return true;
  }
};

}  // namespace disptest
}  // namespace fry

#endif  // FRY_TEST_DISPLAY_MOCK_H
