#include "display_dev.h"

#if defined(FRY_HAS_DISPLAY) && defined(FRY_HAS_LGFX)

#include FRY_INC_SYS(LovyanGFX.hpp)
#include FRY_INC_LIB(touch_cal.h)

namespace fry_dispdev {

namespace {

#if defined(CONFIG_IDF_TARGET_ESP32S3)
const spi_host_device_t kTftHost = SPI2_HOST;
const spi_host_device_t kTouchHost = SPI3_HOST;
#else
const spi_host_device_t kTftHost = SPI2_HOST;  // HSPI: CYD display pins 14/13/12
const spi_host_device_t kTouchHost = SPI3_HOST;  // VSPI: CYD touch pins 25/32/39
#endif

// One LovyanGFX device whose panel and touch driver are chosen at runtime from the probe result.
class Dev : public lgfx::LGFX_Device {
 public:
  lgfx::Panel_ILI9341 ili;
  lgfx::Panel_ST7789 st89;
  lgfx::Panel_ST7735S st35;
  lgfx::Bus_SPI bus;
  lgfx::Light_PWM light;
  lgfx::Touch_XPT2046 xpt;
  lgfx::Touch_FT5x06 ft;
  lgfx::Touch_CST816S cst;
  lgfx::Touch_GT911 gt;

  bool setup(const fry::disp::Info& info, const fry::disp::BoardPins& p, const DevPins& dev) {
    using fry::disp::Panel;
    using fry::disp::Touch;
    {
      auto cfg = bus.config();
      cfg.spi_host = kTftHost;
      cfg.spi_mode = 0;
      cfg.freq_write = 40000000;
      cfg.freq_read = 16000000;
      cfg.spi_3wire = false;
      cfg.use_lock = true;
      cfg.dma_channel = SPI_DMA_CH_AUTO;
      cfg.pin_sclk = p.spiSck;
      cfg.pin_mosi = p.spiMosi;
      cfg.pin_miso = p.spiMiso;
      cfg.pin_dc = p.tftDc;
      bus.config(cfg);
    }
    lgfx::Panel_Device* panel = nullptr;
    switch (info.panel) {
      case Panel::ILI9341_240x320: panel = &ili; break;
      case Panel::ST7789_240x240:
      case Panel::ST7789_135x240: panel = &st89; break;
      case Panel::ST7735_128x160:
      case Panel::ST7735_80x160: panel = &st35; break;
      default: return false;
    }
    panel->setBus(&bus);
    {
      auto cfg = panel->config();
      cfg.pin_cs = p.tftCs;
      cfg.pin_rst = p.tftRst;
      cfg.pin_busy = -1;
      cfg.panel_width = info.width;
      cfg.panel_height = info.height;
      cfg.memory_width = info.width;
      cfg.memory_height = info.height;
      cfg.offset_x = 0;
      cfg.offset_y = 0;
      cfg.offset_rotation = 0;
      cfg.readable = true;
      cfg.invert = info.panel == Panel::ST7789_240x240 || info.panel == Panel::ST7789_135x240;
      cfg.rgb_order = false;
      cfg.dlen_16bit = false;
      cfg.bus_shared = false;
      panel->config(cfg);
    }
    if (p.tftBl >= 0) {
      auto cfg = light.config();
      cfg.pin_bl = p.tftBl;
      cfg.invert = false;
      cfg.freq = 12000;
      cfg.pwm_channel = 7;
      light.config(cfg);
      panel->setLight(&light);
    }
    if (info.touch == Touch::XPT2046) {
      auto cfg = xpt.config();
      cfg.x_min = 300;
      cfg.x_max = 3900;
      cfg.y_min = 200;
      cfg.y_max = 3700;
      cfg.pin_int = p.touchIrq;
      cfg.bus_shared = false;
      cfg.offset_rotation = 6;
      cfg.spi_host = kTouchHost;
      cfg.freq = 1000000;
      cfg.pin_sclk = dev.xptClk >= 0 ? dev.xptClk : p.spiSck;
      cfg.pin_mosi = dev.xptMosi >= 0 ? dev.xptMosi : p.spiMosi;
      cfg.pin_miso = dev.xptMiso >= 0 ? dev.xptMiso : p.spiMiso;
      cfg.pin_cs = p.touchCs;
      xpt.config(cfg);
      panel->setTouch(&xpt);
    } else if (info.touch != Touch::None) {
      const int sda = p.touchSda >= 0 ? p.touchSda : p.sda;
      const int scl = p.touchScl >= 0 ? p.touchScl : p.scl;
      lgfx::ITouch* t = nullptr;
      if (info.touch == Touch::FT6236) {
        auto cfg = ft.config();
        cfg.i2c_addr = info.touchAddr ? info.touchAddr : 0x38;
        cfg.i2c_port = 1;
        cfg.pin_sda = sda;
        cfg.pin_scl = scl;
        cfg.pin_int = p.touchIrq;
        cfg.freq = 400000;
        cfg.x_min = 0;
        cfg.x_max = info.width - 1;
        cfg.y_min = 0;
        cfg.y_max = info.height - 1;
        cfg.bus_shared = false;
        ft.config(cfg);
        t = &ft;
      } else if (info.touch == Touch::CST816S) {
        auto cfg = cst.config();
        cfg.i2c_addr = info.touchAddr ? info.touchAddr : 0x15;
        cfg.i2c_port = 1;
        cfg.pin_sda = sda;
        cfg.pin_scl = scl;
        cfg.pin_int = p.touchIrq;
        cfg.pin_rst = p.touchRst;
        cfg.freq = 400000;
        cfg.x_min = 0;
        cfg.x_max = info.width - 1;
        cfg.y_min = 0;
        cfg.y_max = info.height - 1;
        cfg.bus_shared = false;
        cst.config(cfg);
        t = &cst;
      } else {
        auto cfg = gt.config();
        cfg.i2c_addr = info.touchAddr ? info.touchAddr : 0x5D;
        cfg.i2c_port = 1;
        cfg.pin_sda = sda;
        cfg.pin_scl = scl;
        cfg.pin_int = p.touchIrq;
        cfg.pin_rst = p.touchRst;
        cfg.freq = 400000;
        cfg.x_min = 0;
        cfg.x_max = info.width - 1;
        cfg.y_min = 0;
        cfg.y_max = info.height - 1;
        cfg.bus_shared = false;
        gt.config(cfg);
        t = &gt;
      }
      panel->setTouch(t);
    }
    setPanel(panel);
    return true;
  }
};

class LgfxCanvas : public fry::disp::Canvas {
 public:
  explicit LgfxCanvas(Dev& d) : d_(d) {}
  uint16_t width() const override { return d_.width(); }
  uint16_t height() const override { return d_.height(); }
  bool mono() const override { return false; }
  void clear(uint16_t c) override { d_.fillScreen(col(c)); }
  void fillRect(int16_t x, int16_t y, int16_t w, int16_t h, uint16_t c) override { d_.fillRect(x, y, w, h, col(c)); }
  void drawPixel(int16_t x, int16_t y, uint16_t c) override { d_.drawPixel(x, y, col(c)); }
  void drawText(int16_t x, int16_t y, const char* s, uint8_t size, uint16_t fg, uint16_t bg) override {
    d_.setFont(&fonts::Font0);  // 6x8 cell, the metric the layout assumes
    d_.setTextSize(size);
    d_.setTextColor(col(fg), col(bg));
    d_.setCursor(x, y);
    d_.print(s);
  }
  void drawBitmap1(int16_t x, int16_t y, const uint8_t* bits, int16_t w, int16_t h, uint16_t fg) override {
    d_.drawBitmap(x, y, bits, w, h, col(fg));
  }
  void flush() override {}

 private:
  static lgfx::rgb565_t col(uint16_t c) {
    lgfx::rgb565_t v;
    v.raw = c;
    return v;
  }
  Dev& d_;
};

class LgfxTouch : public fry::ui::TouchHal {
 public:
  explicit LgfxTouch(Dev& d) : d_(d) {}
  bool read(fry::ui::TouchPoint& o) override {
    int32_t x = 0, y = 0;
    const bool down = d_.getTouch(&x, &y);
    o.pressed = down;
    if (down) {
      int16_t ix = (int16_t)x, iy = (int16_t)y;
      if (calOk_) fry::ui::calApply(A_, &ix, &iy, d_.width(), d_.height());
      o.x = ix;
      o.y = iy;
    }
    return true;
  }
  void setCal(const int16_t cal[8], int W, int H) { calOk_ = fry::ui::calFit(cal, W, H, A_); }

 private:
  Dev& d_;
  float A_[6] = {1, 0, 0, 0, 1, 0};
  bool calOk_ = false;
};

Dev* s_dev = nullptr;
LgfxCanvas* s_canvas = nullptr;
LgfxTouch* s_touch = nullptr;
bool s_hasTouch = false;

}  // namespace

bool lgfxInit(const fry::disp::Info& info, const fry::disp::BoardPins& pins, const DevPins& dev) {
  if (s_canvas) return true;
  s_dev = new Dev();
  if (!s_dev->setup(info, pins, dev)) return false;
  if (!s_dev->init()) return false;
  // Landscape on the tall panels; the UI layout follows width()/height().
  if (info.height > info.width) s_dev->setRotation(1);
  s_dev->setBrightness(255);
  s_dev->fillScreen(0);
  s_canvas = new LgfxCanvas(*s_dev);
  s_hasTouch = info.touch != fry::disp::Touch::None;
  if (s_hasTouch) s_touch = new LgfxTouch(*s_dev);
  return true;
}

fry::disp::Canvas* lgfxCanvas() { return s_canvas; }
fry::ui::TouchHal* lgfxTouch() { return s_hasTouch ? s_touch : nullptr; }
void lgfxSetBrightness(uint8_t pct) {
  if (s_dev) s_dev->setBrightness((uint8_t)((uint32_t)pct * 255 / 100));
}
void lgfxSetRotation(uint8_t rot) {
  if (s_dev) s_dev->setRotation(rot);
}
void lgfxApplyCal(const int16_t cal[8]) {
  if (s_touch && s_dev) s_touch->setCal(cal, s_dev->width(), s_dev->height());
}

}  // namespace fry_dispdev

#endif
