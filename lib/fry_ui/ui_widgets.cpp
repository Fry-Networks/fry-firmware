#include "ui_widgets.h"

#include <string.h>

namespace fry {
namespace ui {

Pal palette(bool mono) {
  Pal p;
  if (mono) {
    p.bg = 0;
    p.fg = p.accent = p.ok = p.err = p.warn = p.dim = 1;
    p.btn = 0;
  } else {
    p.bg = 0x0000;
    p.fg = 0xFFFF;
    p.accent = 0x07FF;
    p.ok = 0x07E0;
    p.err = 0xF800;
    p.warn = 0xFD20;
    p.dim = 0x7BEF;
    p.btn = 0x2965;
  }
  return p;
}

int16_t textWidth(const char* s, uint8_t sz) { return (int16_t)(strlen(s) * 6 * sz); }

void drawOutline(disp::Canvas& c, int16_t x, int16_t y, int16_t w, int16_t h, uint16_t col) {
  if (w < 2 || h < 2) return;
  c.fillRect(x, y, w, 1, col);
  c.fillRect(x, (int16_t)(y + h - 1), w, 1, col);
  c.fillRect(x, y, 1, h, col);
  c.fillRect((int16_t)(x + w - 1), y, 1, h, col);
}

void drawProgress(disp::Canvas& c, const Rect& r, uint8_t pct, const Pal& p) {
  if (pct > 100) pct = 100;
  drawOutline(c, r.x, r.y, r.w, r.h, p.fg);
  const int16_t inner = (int16_t)(r.w - 4);
  const int16_t fill = (int16_t)((int32_t)inner * pct / 100);
  if (fill > 0) c.fillRect((int16_t)(r.x + 2), (int16_t)(r.y + 2), fill, (int16_t)(r.h - 4), p.accent);
}

void drawCentered(disp::Canvas& c, const Rect& r, const char* s, uint8_t sz, uint16_t fg, uint16_t bg) {
  const int16_t tw = textWidth(s, sz);
  const int16_t th = (int16_t)(8 * sz);
  c.drawText((int16_t)(r.x + (r.w - tw) / 2), (int16_t)(r.y + (r.h - th) / 2), s, sz, fg, bg);
}

void drawButton(disp::Canvas& c, const Rect& r, const char* label, const Pal& p, bool emphasised, bool enabled) {
  const uint16_t fill = emphasised ? p.accent : p.btn;
  const uint16_t txt = emphasised ? p.bg : (enabled ? p.fg : p.dim);
  c.fillRect(r.x, r.y, r.w, r.h, fill);
  drawOutline(c, r.x, r.y, r.w, r.h, enabled ? p.fg : p.dim);
  const uint8_t sz = (r.h >= 28 && textWidth(label, 2) <= r.w - 4) ? 2 : 1;
  drawCentered(c, r, label, sz, txt, fill);
}

}  // namespace ui
}  // namespace fry
