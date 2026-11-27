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

struct Info {
  Mode mode;
  Panel panel;
  Touch touch;
  uint16_t width, height;
  bool mono;
  uint8_t i2cAddr;
  uint8_t touchAddr;
  uint32_t panelId;
};

struct BusOps {  // injectable; native tests mock it
  virtual bool i2cBegin(int sda, int scl, uint32_t hz) = 0;
  virtual bool i2cProbe(uint8_t addr, uint32_t timeoutUs) = 0;  // ACK?
  virtual bool i2cReadReg(uint8_t addr, uint16_t reg, bool reg16, uint8_t* buf, size_t n, uint32_t timeoutUs) = 0;
  virtual void i2cRecover() = 0;  // 9-clock bus recovery
  virtual bool spiReadId(int cs, int dc, uint8_t cmd, uint8_t* buf, size_t n, bool dummyBit) = 0;
  virtual void setMisoPull(int miso, int pull /* -1 down, 0 none, +1 up */) = 0;
  virtual bool xpt2046Sample(int cs, uint16_t* x, uint16_t* y, uint16_t* z) = 0;
  virtual ~BusOps() {}
};

struct BoardPins {
  int sda, scl, spiSck, spiMosi, spiMiso, tftCs, tftDc, tftRst, tftBl, touchCs, touchIrq, touchSda, touchScl, touchRst;
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
