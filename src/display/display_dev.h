// Device side of the display stack (Arduino). Only compiled into display-enabled envs
// (-DFRY_HAS_DISPLAY=1, platformio.ui.ini); every .cpp under src/display and src/ui is empty otherwise.
#pragma once

#if defined(FRY_HAS_DISPLAY)

#include <Arduino.h>

#include "../../include/fry_touch_ui.h"
#include "../ui/fry_inc.h"
#include FRY_INC_LIB(display_presets.h)

namespace fry_dispdev {

// Bus access for the boot probe: hardware I2C (Wire), bit-banged SPI ID reads (so the pull-up /
// pull-down MISO test and the 1-bit read dummy are exact) and an XPT2046 sample. All pins arrive
// through BoardPins/DevPins that the pure probe has already checked against the forbidden list.
struct DevPins {
  int xptClk, xptMosi, xptMiso;  // XPT2046 own bus (CYD); -1 = shares the TFT bus pins
};

class Bus : public fry::disp::BusOps {
 public:
  void setSpi(int sck, int mosi, int miso) { sck_ = sck; mosi_ = mosi; miso_ = miso; }
  void setXpt(const DevPins& d) { xpt_ = d; }
  bool i2cBegin(int sda, int scl, uint32_t hz) override;
  bool i2cProbe(uint8_t addr, uint32_t timeoutUs) override;
  bool i2cReadReg(uint8_t addr, uint16_t reg, bool reg16, uint8_t* buf, size_t n, uint32_t timeoutUs) override;
  void i2cRecover() override;
  bool spiReadId(int cs, int dc, uint8_t cmd, uint8_t* buf, size_t n, bool dummyBit) override;
  void setMisoPull(int miso, int pull) override;
  bool xpt2046Sample(int cs, uint16_t* x, uint16_t* y, uint16_t* z) override;
  // Return every probed pin to a high-impedance input so the real driver can claim it.
  void release(const fry::disp::BoardPins& p);

 private:
  int sda_ = -1, scl_ = -1, sck_ = -1, mosi_ = -1, miso_ = -1;
  uint32_t hz_ = 100000;
  DevPins xpt_ = {-1, -1, -1};
};

// Per-preset wiring that BoardPins has no field for.
DevPins devPinsFor(uint8_t preset);

// Back ends, each compiled only when its library is in the env (FRY_HAS_U8G2 / FRY_HAS_LGFX).
bool u8g2Init(const fry::disp::Info& info, const fry::disp::BoardPins& pins);
fry::disp::Canvas* u8g2Canvas();
bool lgfxInit(const fry::disp::Info& info, const fry::disp::BoardPins& pins, const DevPins& dev);
fry::disp::Canvas* lgfxCanvas();
fry::ui::TouchHal* lgfxTouch();
void lgfxSetBrightness(uint8_t pct);
void lgfxSetRotation(uint8_t rot);
void lgfxApplyCal(const int16_t cal[8]);

// Display driver (U8g2 for mono OLED, LovyanGFX for colour TFT + touch).
bool driverInit(const fry::disp::Info& info, const fry::disp::BoardPins& pins, uint8_t preset);
fry::disp::Canvas* driverCanvas();
fry::ui::TouchHal* driverTouch();  // null when the resolved mode has no touch
const char* driverName();
void driverSetBrightness(uint8_t pct);
void driverSetRotation(uint8_t rot);
void driverApplyCal(const int16_t cal[8]);

}  // namespace fry_dispdev

#endif  // FRY_HAS_DISPLAY
