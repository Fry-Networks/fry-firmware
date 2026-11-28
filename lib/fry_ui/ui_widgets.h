// Small drawing helpers shared by ScreenAnimator and TouchUI. Fixed storage, no heap.
#ifndef FRY_UI_WIDGETS_H
#define FRY_UI_WIDGETS_H

#include <stdint.h>

#include "../../include/fry_display_hal.h"
#include "touch_layout.h"

namespace fry {
namespace ui {

struct Pal {
  uint16_t bg, fg, accent, ok, err, warn, dim, btn;
};
Pal palette(bool mono);

void drawOutline(disp::Canvas& c, int16_t x, int16_t y, int16_t w, int16_t h, uint16_t col);
void drawProgress(disp::Canvas& c, const Rect& r, uint8_t pct, const Pal& p);
void drawButton(disp::Canvas& c, const Rect& r, const char* label, const Pal& p, bool emphasised = false,
                bool enabled = true);
// Text of size `sz` horizontally centred in `r`.
void drawCentered(disp::Canvas& c, const Rect& r, const char* s, uint8_t sz, uint16_t fg, uint16_t bg);
int16_t textWidth(const char* s, uint8_t sz);

}  // namespace ui
}  // namespace fry

#endif  // FRY_UI_WIDGETS_H
