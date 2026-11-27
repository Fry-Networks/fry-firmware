#include "display_presets.h"

#include <stdio.h>
#include <string.h>

namespace fry {
namespace disp {

const int kEsp32S3Forbidden[] = {19, 20, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37};
const size_t kEsp32S3ForbiddenCount = sizeof(kEsp32S3Forbidden) / sizeof(kEsp32S3Forbidden[0]);
const int kEsp32Forbidden[] = {1, 3, 6, 7, 8, 9, 10, 11};
const size_t kEsp32ForbiddenCount = sizeof(kEsp32Forbidden) / sizeof(kEsp32Forbidden[0]);
const int kEsp8266Forbidden[] = {6, 7, 8, 9, 10, 11};
const size_t kEsp8266ForbiddenCount = sizeof(kEsp8266Forbidden) / sizeof(kEsp8266Forbidden[0]);
const int kRp2040Forbidden[] = {23, 24, 25, 29};
const size_t kRp2040ForbiddenCount = sizeof(kRp2040Forbidden) / sizeof(kRp2040Forbidden[0]);

bool pinForbidden(const BoardPins& p, int pin) {
  if (pin < 0 || !p.forbidden) return false;
  for (size_t i = 0; i < p.nForbidden; i++)
    if (p.forbidden[i] == pin) return true;
  return false;
}

bool pinsAllowed(const BoardPins& p) {
  const int all[] = {p.sda,   p.scl,      p.spiSck,  p.spiMosi,  p.spiMiso,  p.tftCs,    p.tftDc,
                     p.tftRst, p.tftBl,   p.touchCs, p.touchIrq, p.touchSda, p.touchScl, p.touchRst};
  for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++)
    if (pinForbidden(p, all[i])) return false;
  return true;
}

namespace {

BoardPins blank() {
  BoardPins p;
  p.sda = p.scl = p.spiSck = p.spiMosi = p.spiMiso = p.tftCs = p.tftDc = p.tftRst = p.tftBl = -1;
  p.touchCs = p.touchIrq = p.touchSda = p.touchScl = p.touchRst = -1;
  p.forbidden = nullptr;
  p.nForbidden = 0;
  return p;
}

Info blankInfo() {
  Info i;
  memset(&i, 0, sizeof(i));
  i.mode = FRY_DISP_NONE;
  i.panel = Panel::None;
  i.touch = Touch::None;
  return i;
}

}  // namespace

bool presetPins(uint8_t preset, BoardPins& out) {
  BoardPins p = blank();
  switch (preset) {
    case PRESET_ESP32_OLED:
      p.sda = 21;
      p.scl = 22;
      p.forbidden = kEsp32Forbidden;
      p.nForbidden = kEsp32ForbiddenCount;
      break;
    case PRESET_ESP32S3_TFT:
    case PRESET_ESP32S3_CAPTOUCH:
      p.spiSck = 12;
      p.spiMosi = 11;
      p.spiMiso = 13;
      p.tftCs = 10;
      p.tftDc = 9;
      p.tftRst = 8;
      p.tftBl = 14;
      if (preset == PRESET_ESP32S3_CAPTOUCH) {
        p.touchSda = 4;
        p.touchScl = 5;
        p.touchRst = 6;
        p.touchIrq = 7;
      }
      p.forbidden = kEsp32S3Forbidden;
      p.nForbidden = kEsp32S3ForbiddenCount;
      break;
    case PRESET_RPIPICOW_OLED:
      p.sda = 4;
      p.scl = 5;
      p.forbidden = kRp2040Forbidden;
      p.nForbidden = kRp2040ForbiddenCount;
      break;
    case PRESET_ESP32_CYD:  // ESP32-2432S028R
      p.spiSck = 14;
      p.spiMosi = 13;
      p.spiMiso = 12;
      p.tftCs = 15;
      p.tftDc = 2;
      p.tftBl = 21;
      p.touchCs = 33;
      p.touchIrq = 36;
      p.forbidden = kEsp32Forbidden;
      p.nForbidden = kEsp32ForbiddenCount;
      break;
    case PRESET_ESP32S3_OLED:
      p.sda = 8;
      p.scl = 9;
      p.forbidden = kEsp32S3Forbidden;
      p.nForbidden = kEsp32S3ForbiddenCount;
      break;
    case PRESET_ESP8266_OLED:
      p.sda = 4;
      p.scl = 5;
      p.forbidden = kEsp8266Forbidden;
      p.nForbidden = kEsp8266ForbiddenCount;
      break;
    default:
      return false;
  }
  out = p;
  return true;
}

bool presetInfo(uint8_t preset, Info& out) {
  Info i = blankInfo();
  switch (preset) {
    case PRESET_ESP32_OLED:
    case PRESET_RPIPICOW_OLED:
    case PRESET_ESP8266_OLED:
    case PRESET_ESP32S3_OLED:
      i.mode = FRY_DISP_SCREEN_ONLY;
      i.panel = Panel::SSD1306_128x64;
      i.width = 128;
      i.height = 64;
      i.mono = true;
      i.i2cAddr = 0x3C;
      break;
    case PRESET_ESP32S3_TFT:
      i.mode = FRY_DISP_SCREEN_ONLY;
      i.panel = Panel::ST7789_240x240;
      i.width = i.height = 240;
      break;
    case PRESET_ESP32S3_CAPTOUCH:
      i.mode = FRY_DISP_TOUCHSCREEN;
      i.panel = Panel::ST7789_240x240;
      i.touch = Touch::CST816S;
      i.touchAddr = 0x15;
      i.width = i.height = 240;
      break;
    case PRESET_ESP32_CYD:
      i.mode = FRY_DISP_TOUCHSCREEN;
      i.panel = Panel::ILI9341_240x320;
      i.touch = Touch::XPT2046;
      i.width = 240;
      i.height = 320;
      break;
    default:
      return false;
  }
  out = i;
  return true;
}

const char* presetName(uint8_t p) {
  switch (p) {
    case PRESET_ESP32_OLED: return "esp32-oled";
    case PRESET_ESP32S3_TFT: return "esp32s3-tft";
    case PRESET_RPIPICOW_OLED: return "rpipicow-oled";
    case PRESET_ESP32_CYD: return "esp32-cyd";
    case PRESET_ESP32S3_CAPTOUCH: return "esp32s3-cap-touch";
    case PRESET_ESP8266_OLED: return "esp8266-oled";
    case PRESET_ESP32S3_OLED: return "esp32s3-oled";
    default: return "none";
  }
}

const char* modeName(Mode m) {
  switch (m) {
    case FRY_DISP_SCREEN_ONLY: return "SCREEN_ONLY";
    case FRY_DISP_TOUCHSCREEN: return "TOUCHSCREEN";
    default: return "NONE";
  }
}

const char* panelName(Panel p) {
  switch (p) {
    case Panel::SSD1306_128x64: return "SSD1306_128x64";
    case Panel::SSD1306_128x32: return "SSD1306_128x32";
    case Panel::SH1106_128x64: return "SH1106_128x64";
    case Panel::ST7735_128x160: return "ST7735_128x160";
    case Panel::ST7735_80x160: return "ST7735_80x160";
    case Panel::ST7789_240x240: return "ST7789_240x240";
    case Panel::ST7789_135x240: return "ST7789_135x240";
    case Panel::ILI9341_240x320: return "ILI9341_240x320";
    default: return "none";
  }
}

const char* touchName(Touch t) {
  switch (t) {
    case Touch::XPT2046: return "XPT2046";
    case Touch::CST816S: return "CST816S";
    case Touch::FT6236: return "FT6236";
    case Touch::GT911: return "GT911";
    default: return "none";
  }
}

bool shouldPoll(Mode m) { return m != FRY_DISP_NONE; }
bool wantsTouchPolling(Mode m) { return m == FRY_DISP_TOUCHSCREEN; }
uint32_t loopIntervalMs(Mode m) {
  switch (m) {
    case FRY_DISP_TOUCHSCREEN: return 20;  // touch latency
    case FRY_DISP_SCREEN_ONLY: return 33;  // ~30 fps cap, animator rate-limits further
    default: return 0;
  }
}

static const char* pn(char* buf, size_t cap, int v) {
  if (v < 0) snprintf(buf, cap, "-");
  else snprintf(buf, cap, "%d", v);
  return buf;
}

size_t formatBootLine(char* out, size_t cap, const Info& i, const char* driver, const BoardPins& p) {
  if (!out || cap == 0) return 0;
  char b[14][6];
  int n = snprintf(out, cap,
                   "[ui] mode=%s panel=%s touch=%s drv=%s sda=%s scl=%s sck=%s mosi=%s miso=%s cs=%s dc=%s rst=%s bl=%s "
                   "tcs=%s tirq=%s tsda=%s tscl=%s",
                   modeName(i.mode), panelName(i.panel), touchName(i.touch), driver ? driver : "-", pn(b[0], 6, p.sda),
                   pn(b[1], 6, p.scl), pn(b[2], 6, p.spiSck), pn(b[3], 6, p.spiMosi), pn(b[4], 6, p.spiMiso),
                   pn(b[5], 6, p.tftCs), pn(b[6], 6, p.tftDc), pn(b[7], 6, p.tftRst), pn(b[8], 6, p.tftBl),
                   pn(b[9], 6, p.touchCs), pn(b[10], 6, p.touchIrq), pn(b[11], 6, p.touchSda), pn(b[12], 6, p.touchScl));
  if (n < 0) {
    out[0] = 0;
    return 0;
  }
  if ((size_t)n >= cap) {
    out[cap - 1] = 0;
    return cap - 1;
  }
  return (size_t)n;
}

uint8_t autodetect(const uint8_t* presets, size_t n, BusOps& bus, uint32_t totalBudgetMs, Info& best) {
  best = blankInfo();
  const uint32_t each = n ? totalBudgetMs / (uint32_t)n : 0;
  for (size_t k = 0; k < n; k++) {
    BoardPins p;
    if (!presetPins(presets[k], p)) continue;
    Info i = probe(p, bus, each);
    if (i.mode != FRY_DISP_NONE) {
      best = i;
      return presets[k];
    }
  }
  return 0;
}

}  // namespace disp
}  // namespace fry
