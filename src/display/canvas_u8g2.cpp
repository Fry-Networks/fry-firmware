#include "display_dev.h"

#if defined(FRY_HAS_DISPLAY) && defined(FRY_HAS_U8G2)

#include FRY_INC_SYS(U8g2lib.h)
#if !defined(FRY_SOFT_I2C)
#include FRY_INC_SYS(Wire.h)
#endif

namespace fry_dispdev {

namespace {

class U8g2Canvas : public fry::disp::Canvas {
 public:
  explicit U8g2Canvas(U8G2* u, uint16_t w, uint16_t h) : u_(u), w_(w), h_(h) {}
  uint16_t width() const override { return w_; }
  uint16_t height() const override { return h_; }
  bool mono() const override { return true; }
  void clear(uint16_t) override { u_->clearBuffer(); }
  void fillRect(int16_t x, int16_t y, int16_t w, int16_t h, uint16_t c) override {
    if (w <= 0 || h <= 0) return;
    u_->setDrawColor(c ? 1 : 0);
    u_->drawBox(x, y, (u8g2_uint_t)w, (u8g2_uint_t)h);
  }
  void drawPixel(int16_t x, int16_t y, uint16_t c) override {
    u_->setDrawColor(c ? 1 : 0);
    u_->drawPixel(x, y);
  }
  void drawText(int16_t x, int16_t y, const char* s, uint8_t size, uint16_t fg, uint16_t bg) override {
    (void)bg;  // transparent: the animator clears the area first
    u_->setFont(size >= 2 ? u8g2_font_9x15_tr : u8g2_font_5x7_tr);
    u_->setFontPosTop();
    u_->setDrawColor(fg ? 1 : 0);
    u_->drawStr(x, y, s);
  }
  void drawBitmap1(int16_t x, int16_t y, const uint8_t* bits, int16_t w, int16_t h, uint16_t fg) override {
    u_->setDrawColor(fg ? 1 : 0);
    u_->drawBitmap(x, y, (u8g2_uint_t)((w + 7) / 8), (u8g2_uint_t)h, bits);
  }
  void flush() override { u_->sendBuffer(); }

 private:
  U8G2* u_;
  uint16_t w_, h_;
};

U8G2* s_u8 = nullptr;
U8g2Canvas* s_canvas = nullptr;

}  // namespace

bool u8g2Init(const fry::disp::Info& info, const fry::disp::BoardPins& pins) {
  if (s_canvas) return true;
  using fry::disp::Panel;
#if defined(FRY_SOFT_I2C)
  const uint8_t scl = (uint8_t)pins.scl, sda = (uint8_t)pins.sda;
  switch (info.panel) {
    case Panel::SH1106_128x64: s_u8 = new U8G2_SH1106_128X64_NONAME_F_SW_I2C(U8G2_R0, scl, sda, U8X8_PIN_NONE); break;
    case Panel::SSD1306_128x32: s_u8 = new U8G2_SSD1306_128X32_UNIVISION_F_SW_I2C(U8G2_R0, scl, sda, U8X8_PIN_NONE); break;
    case Panel::SSD1306_128x64: s_u8 = new U8G2_SSD1306_128X64_NONAME_F_SW_I2C(U8G2_R0, scl, sda, U8X8_PIN_NONE); break;
    default: return false;
  }
#else
  switch (info.panel) {
    case Panel::SH1106_128x64:
      s_u8 = new U8G2_SH1106_128X64_NONAME_F_HW_I2C(U8G2_R0, U8X8_PIN_NONE);
      break;
    case Panel::SSD1306_128x32:
      s_u8 = new U8G2_SSD1306_128X32_UNIVISION_F_HW_I2C(U8G2_R0, U8X8_PIN_NONE);
      break;
    case Panel::SSD1306_128x64:
      s_u8 = new U8G2_SSD1306_128X64_NONAME_F_HW_I2C(U8G2_R0, U8X8_PIN_NONE);
      break;
    default:
      return false;
  }
#endif
  if (!s_u8) return false;
  if (info.i2cAddr == 0x3D) s_u8->setI2CAddress(0x3D << 1);
#if defined(FRY_SOFT_I2C)
  // pins were given to the constructor
#elif defined(ARDUINO_ARCH_ESP32)
  Wire.end();
  Wire.setPins(pins.sda, pins.scl);  // U8g2's own Wire.begin() then keeps these pins
#elif defined(ARDUINO_ARCH_RP2040)
  Wire.setSDA(pins.sda);
  Wire.setSCL(pins.scl);
#else
  (void)pins;
#endif
  if (!s_u8->begin()) return false;
  s_u8->setBusClock(400000);
  s_u8->setContrast(255);
  s_canvas = new U8g2Canvas(s_u8, info.width ? info.width : 128, info.height ? info.height : 64);
  return s_canvas != nullptr;
}

fry::disp::Canvas* u8g2Canvas() { return s_canvas; }

}  // namespace fry_dispdev

#endif
