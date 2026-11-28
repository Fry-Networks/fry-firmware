// Display / touch HAL: probe, resolve and drawing interfaces. Declarations only; no Arduino include.
#ifndef FRY_DISPLAY_HAL_H
#define FRY_DISPLAY_HAL_H

#include <stddef.h>
#include <stdint.h>

namespace fry {
namespace disp {

enum Mode : uint8_t { FRY_DISP_NONE = 0, FRY_DISP_SCREEN_ONLY = 1, FRY_DISP_TOUCHSCREEN = 2 };

enum class Panel : uint8_t {
  None, SSD1306_128x64, SSD1306_128x32, SH1106_128x64, ST7735_128x160, ST7735_80x160, ST7789_240x240,
  ST7789_135x240, ILI9341_240x320
};

enum class Touch : uint8_t { None, XPT2046, CST816S, FT6236, GT911 };

// Raw bytes the probe saw, kept only so the boot log can show them ("[ui] probe raw ...").
struct ProbeRaw {
  uint8_t d3Up[6], d3Dn[6];    // RDID4 (0xD3) under MISO pull-up / pull-down; byte 0 is the first byte after the dummy clock
  uint8_t id04Up[6], id04Dn[6];  // RDDID (0x04), same layout
  uint8_t nD3, n04;            // bytes captured (0 = that read was not made)
  int8_t d3Bit, id04Bit;       // bit offset where the ID pattern matched (-1 = none)
  uint16_t xpt[6];             // XPT2046: temp0, temp0 again, vbat, aux, z1, z2 (12-bit)
  uint8_t nXpt;                // 0 = not read, 6 = channel read, 3 = legacy x/y/z sample
  int8_t xptVerdict;           // -1 not judged, 0 rejected, 1 accepted
  uint8_t st[4];               // RDDST (0x09) first 4 bytes, read only for the LovyanGFX-style ILI9341 fallback
  uint8_t nSt;                 // 0 = not read, 4 = read
};

struct Info {
  Mode mode;
  Panel panel;
  Touch touch;
  uint16_t width, height;
  bool mono;
  uint8_t i2cAddr;
  uint8_t touchAddr;
  uint32_t panelId;
  ProbeRaw raw;
};

struct BusOps {  // injectable; native tests mock it
  virtual bool i2cBegin(int sda, int scl, uint32_t hz) = 0;
  virtual bool i2cProbe(uint8_t addr, uint32_t timeoutUs) = 0;  // ACK?
  virtual bool i2cReadReg(uint8_t addr, uint16_t reg, bool reg16, uint8_t* buf, size_t n, uint32_t timeoutUs) = 0;
  virtual void i2cRecover() = 0;  // 9-clock bus recovery
  virtual bool spiReadId(int cs, int dc, uint8_t cmd, uint8_t* buf, size_t n, bool dummyBit) = 0;
  virtual void setMisoPull(int miso, int pull /* -1 down, 0 none, +1 up */) = 0;
  virtual bool xpt2046Sample(int cs, uint16_t* x, uint16_t* y, uint16_t* z) = 0;
  // XPT2046 on a bus whose MISO has no pull (CYD GPIO39): out = temp0, temp0 again, vbat, aux, z1, z2 (12-bit each).
  // Returns -1 = not supported (the probe falls back to xpt2046Sample), 0 = read failed, 1 = ok.
  virtual int xpt2046Channels(int cs, uint16_t out[6]) { (void)cs; (void)out; return -1; }
  virtual ~BusOps() {}
};

struct BoardPins {
  int sda, scl, spiSck, spiMosi, spiMiso, tftCs, tftDc, tftRst, tftBl, touchCs, touchIrq, touchSda, touchScl, touchRst;
  // Separate XPT2046 bus (CYD: CLK25 MOSI32 MISO39); -1 = the touch controller shares the TFT SPI bus or is absent.
  int touchSck = -1, touchMosi = -1, touchMiso = -1;
  const int* forbidden;  // probe must never drive a forbidden pin
  size_t nForbidden;
};

// Bounded; anti-floating-MISO: an ID read must differ between pull-up and pull-down and not be all 0x00/0xFF.
Info probe(const BoardPins& pins, BusOps& bus, uint32_t budgetMs);
// Config override (Auto/None/Screen/Touch + preset).
Info resolve(const Info& probed, uint8_t displayModeOverride, uint8_t preset);

struct Canvas {  // drawing target; device impl = U8g2 / LovyanGFX; native = in-memory framebuffer
  virtual uint16_t width() const = 0;
  virtual uint16_t height() const = 0;
  virtual bool mono() const = 0;
  virtual void clear(uint16_t c) = 0;
  virtual void fillRect(int16_t x, int16_t y, int16_t w, int16_t h, uint16_t c) = 0;
  virtual void drawPixel(int16_t x, int16_t y, uint16_t c) = 0;
  virtual void drawText(int16_t x, int16_t y, const char* s, uint8_t size, uint16_t fg, uint16_t bg) = 0;
  virtual void drawBitmap1(int16_t x, int16_t y, const uint8_t* bits, int16_t w, int16_t h, uint16_t fg) = 0;  // PROGMEM-safe reader inside
  virtual void flush() = 0;
  virtual ~Canvas() {}
};

}  // namespace disp
}  // namespace fry

#endif  // FRY_DISPLAY_HAL_H
