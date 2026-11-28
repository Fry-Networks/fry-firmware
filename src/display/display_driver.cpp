#include "display_dev.h"

#if defined(FRY_HAS_DISPLAY)

namespace fry_dispdev {

#if !defined(FRY_HAS_U8G2)
bool u8g2Init(const fry::disp::Info&, const fry::disp::BoardPins&) { return false; }
fry::disp::Canvas* u8g2Canvas() { return nullptr; }
#endif
#if !defined(FRY_HAS_LGFX)
bool lgfxInit(const fry::disp::Info&, const fry::disp::BoardPins&, const DevPins&) { return false; }
fry::disp::Canvas* lgfxCanvas() { return nullptr; }
fry::ui::TouchHal* lgfxTouch() { return nullptr; }
void lgfxSetBrightness(uint8_t) {}
void lgfxSetRotation(uint8_t) {}
void lgfxApplyCal(const int16_t[8]) {}
#endif

namespace {
fry::disp::Canvas* s_canvas = nullptr;
fry::ui::TouchHal* s_touch = nullptr;
const char* s_name = "-";
}  // namespace

bool driverInit(const fry::disp::Info& info, const fry::disp::BoardPins& pins, uint8_t preset) {
  if (info.mode == fry::disp::FRY_DISP_NONE) return false;
  if (info.mono) {
    if (!u8g2Init(info, pins)) return false;
    s_canvas = u8g2Canvas();
    s_touch = nullptr;
    s_name = "U8g2";
  } else {
    if (!lgfxInit(info, pins, devPinsFor(preset))) return false;
    s_canvas = lgfxCanvas();
    s_touch = info.mode == fry::disp::FRY_DISP_TOUCHSCREEN ? lgfxTouch() : nullptr;
    s_name = "LovyanGFX";
  }
  return s_canvas != nullptr;
}

fry::disp::Canvas* driverCanvas() { return s_canvas; }
fry::ui::TouchHal* driverTouch() { return s_touch; }
const char* driverName() { return s_name; }
void driverSetBrightness(uint8_t pct) { lgfxSetBrightness(pct); }
void driverSetRotation(uint8_t rot) { lgfxSetRotation(rot); }
void driverApplyCal(const int16_t cal[8]) { lgfxApplyCal(cal); }

}  // namespace fry_dispdev

#endif  // FRY_HAS_DISPLAY
