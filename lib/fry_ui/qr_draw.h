// "Setup with App" QR: payload builder, matrix generator (ricmoo/QRCode 0.0.1) and canvas renderer.
#ifndef FRY_UI_QR_DRAW_H
#define FRY_UI_QR_DRAW_H

#include <stddef.h>
#include <stdint.h>

#include "../../include/fry_touch_ui.h"

namespace fry {
namespace ui {

// WIFI:T:nopass;S:<apSsid>;;  (the standard Wi-Fi QR phones understand) when the board runs a setup AP,
// otherwise FRY:<boardName> so the app can pick the board over BLE. Returns the length, 0 (and "") if it
// does not fit `cap`.
size_t appQrPayload(const MinerStatus& s, char* out, size_t cap);

// Encodes `text` into `out` as a packed row-major bit matrix (1 = dark). Returns modules per side, or 0
// if the text does not fit a version <= 10 code or `cap` is too small.
int qrEncode(const char* text, uint8_t* out, size_t cap);
bool qrGet(const uint8_t* m, int n, int x, int y);

// Draws the matrix with a 4-module quiet zone, scaled to fit `area`, black on white.
void drawQr(disp::Canvas& c, const uint8_t* m, int n, int16_t x, int16_t y, int16_t w, int16_t h);

}  // namespace ui
}  // namespace fry

#endif  // FRY_UI_QR_DRAW_H
