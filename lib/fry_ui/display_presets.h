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
// A preset whose XPT2046 sits on its OWN bus (CYD: CLK25 MOSI32 MISO39, GPIO39/36 input-only with no internal pull) instead of the
// TFT bus. false = the touch controller shares the TFT SPI pins (or the preset has none).
bool presetTouchBus(uint8_t preset, int* clk, int* mosi, int* miso);
// `p` with touchCs cleared (so the touch controller is never driven) when a separate touch bus uses a forbidden pin.
BoardPins gateTouchBus(uint8_t preset, const BoardPins& p);
// Test seam only (never called by firmware): presetPins() uses this forbidden list instead of the preset's own (nullptr = off), so
// native tests can run a preset's real wiring against another chip's forbidden pins.
void setForbiddenOverrideForTest(const int* list, size_t n);
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

// "[ui] probe raw d3u=.. d3d=.. d3bit=N 04u=.. 04d=.. 04bit=N xpt=t,t,vb,ax,z1,z2 xv=N" (raw bytes in hex; '-' = not read).
size_t formatProbeRaw(char* out, size_t cap, const Info& i);

// Try the candidate presets in order, each with the remaining budget; the first whose probe finds
// something wins and the rest are never touched. Returns the chosen preset (0 = nothing found).
uint8_t autodetect(const uint8_t* presets, size_t n, BusOps& bus, uint32_t totalBudgetMs, Info& best);

// ---- boot probe scope (fleet-safety policy) -------------------------------------------------------------------------------
// A miner with unknown wiring must never have SPI / TFT / XPT2046 pins driven. The scope is decided from the config store
// (explicit board preset, explicit display_mode) and nothing else:
//   Off        display_mode=none: nothing is touched.
//   I2cDefault no preset and display_mode=Auto: ONLY the bounded I2C address/register probe on the board's default I2C pins.
//   Preset     a board preset is set (config store or compiled in): that preset's pins, SPI / touch included.
//   Candidates no preset but display_mode=screen/touch was set explicitly: the per-chip candidate presets.
enum class ProbeScope : uint8_t { Off, I2cDefault, Preset, Candidates };
ProbeScope probeScope(uint8_t preset, uint8_t displayMode /* cfg::DisplayMode: 0 Auto, 1 None, 2 Screen, 3 Touch */);

// `full` with every SPI / TFT / touch pin cleared: only sda / scl (and the forbidden list) remain.
BoardPins i2cOnlyPins(const BoardPins& full);

// Lets the device bus follow the probe (select the SPI / XPT pins before a preset is probed, release them after).
struct BusHook {
  virtual void select(uint8_t preset, const BoardPins& p) = 0;
  virtual void release(const BoardPins& p) = 0;
  virtual ~BusHook() {}
};

// Runs exactly the probe the scope allows. `defaultI2cPreset` names the chip's default I2C pin preset; `cands` are the
// Candidates-scope presets. Returns the preset that answered (or the explicit preset; 0 when none), fills `best` and `pinsOut`.
uint8_t bootProbe(uint8_t preset, uint8_t displayMode, uint8_t defaultI2cPreset, const uint8_t* cands, size_t nCands,
                  BusOps& bus, BusHook* hook, uint32_t totalBudgetMs, Info& best, BoardPins& pinsOut, bool& havePins);

}  // namespace disp
}  // namespace fry

#endif  // FRY_UI_DISPLAY_PRESETS_H
