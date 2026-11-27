// Board presets, forbidden-pin tables and the pure helpers around include/fry_display_hal.h's
// probe()/resolve(). No Arduino include: host-testable and shared by every display-enabled env.
#ifndef FRY_UI_DISPLAY_PRESETS_H
#define FRY_UI_DISPLAY_PRESETS_H

#include <stddef.h>
#include <stdint.h>

#include "../../include/fry_display_hal.h"

namespace fry {
namespace disp {

enum Preset : uint8_t {
  PRESET_NONE = 0,
  PRESET_ESP32_OLED = 1,        // SSD1306 128x64 on I2C 21/22
  PRESET_ESP32S3_TFT = 2,       // ST7789 240x240 on SPI (no touch)
  PRESET_RPIPICOW_OLED = 3,     // SSD1306 on I2C0 GP4/GP5
  PRESET_ESP32_CYD = 4,         // ESP32-2432S028R: ILI9341 240x320 + XPT2046
  PRESET_ESP32S3_CAPTOUCH = 5,  // ST7789 + I2C capacitive touch (CST816S / FT6236 / GT911)
  PRESET_ESP8266_OLED = 6,      // SSD1306 on D2/D1
  PRESET_ESP32S3_OLED = 7,      // SSD1306 on I2C GPIO8/9
  PRESET_COUNT
};

// ESP32-S3: GPIO19/20 are the native USB D-/D+ and GPIO26-37 are the in-package flash / PSRAM bus
// (octal PSRAM on 33-37). Driving any of them can hang the chip or kill USB-CDC, so the probe never
// touches a bus that uses one.
extern const int kEsp32S3Forbidden[];
extern const size_t kEsp32S3ForbiddenCount;  // 14
// Classic ESP32 (GPIO6-11 flash bus, 1/3 console UART), ESP8266 (6-11 flash), RP2040 (CYW43 radio).
extern const int kEsp32Forbidden[];
extern const size_t kEsp32ForbiddenCount;
extern const int kEsp8266Forbidden[];
extern const size_t kEsp8266ForbiddenCount;
extern const int kRp2040Forbidden[];
extern const size_t kRp2040ForbiddenCount;

// True if `pin` (>= 0) is in the board's forbidden list. -1 (unused) is never forbidden.
bool pinForbidden(const BoardPins& p, int pin);
// True if no pin this board configuration would drive is forbidden.
bool pinsAllowed(const BoardPins& p);

bool presetPins(uint8_t preset, BoardPins& out);  // false for 0 / unknown
bool presetInfo(uint8_t preset, Info& out);       // the hardware the preset declares
const char* presetName(uint8_t preset);
const char* modeName(Mode m);
const char* panelName(Panel p);
const char* touchName(Touch t);

// Zero polling in NONE mode: nothing in the main loop may touch a bus or the UI.
bool shouldPoll(Mode m);
bool wantsTouchPolling(Mode m);
uint32_t loopIntervalMs(Mode m);  // minimum ms between UI loop calls; 0 for NONE

// "[ui] mode=TOUCHSCREEN panel=ILI9341_240x320 touch=XPT2046 drv=LovyanGFX sck=14 mosi=13 miso=12 cs=15 ..."
// Returns the length written (always NUL terminated, truncated to cap).
size_t formatBootLine(char* out, size_t cap, const Info& i, const char* driver, const BoardPins& p);

// Try the candidate presets in order, each with the remaining budget; the first whose probe finds
// something wins and the rest are never touched. Returns the chosen preset (0 = nothing found).
uint8_t autodetect(const uint8_t* presets, size_t n, BusOps& bus, uint32_t totalBudgetMs, Info& best);

}  // namespace disp
}  // namespace fry

#endif  // FRY_UI_DISPLAY_PRESETS_H
