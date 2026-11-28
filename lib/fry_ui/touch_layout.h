// Touch screen geometry shared by the renderer, the hit tester and the simulator tests. Pure inline
// functions of the canvas size, so what is drawn and what is tappable cannot drift apart.
#ifndef FRY_UI_TOUCH_LAYOUT_H
#define FRY_UI_TOUCH_LAYOUT_H

#include <stdint.h>
#include <string.h>

namespace fry {
namespace ui {

struct Rect {
  int16_t x, y, w, h;
  bool contains(int16_t px, int16_t py) const { return px >= x && py >= y && px < x + w && py < y + h; }
  int16_t cx() const { return x + w / 2; }
  int16_t cy() const { return y + h / 2; }
};

// Grid cell `i` (row-major) of a cols x rows grid under the title bar.
inline Rect gridBtn(int i, int cols, int rows, int W, int H) {
  const int top = H / 8 + 4, areaH = H - top - 6, cw = (W - 12) / cols, ch = areaH / rows;
  const int col = i % cols, row = i / cols;
  Rect r = {(int16_t)(6 + col * cw), (int16_t)(top + row * ch), (int16_t)(cw - 6), (int16_t)(ch - 6)};
  return r;
}

inline Rect bottomLeftBtn(int W, int H) {
  (void)W;
  Rect r = {6, (int16_t)(H - 34), 84, 28};
  return r;
}
inline Rect bottomRightBtn(int W, int H) {
  Rect r = {(int16_t)(W - 90), (int16_t)(H - 34), 84, 28};
  return r;
}

// Screen button indices.
enum { kFirstContinue = 2 };                              // gridBtn(2,1,3)
enum { kChoiceScreen = 0, kChoiceApp = 1 };               // gridBtn(i,1,3)
enum { kWifiRows = 5, kWifiBack = 5 };                    // gridBtn(i,1,6)
enum { kSetCheckOta = 0, kSetBrightDn, kSetBrightUp, kSetRotate, kSetCalibrate, kSetReset, kSetBack };  // gridBtn(i,2,4)
enum { kResetConfirm = 0, kResetCancel = 1 };             // gridBtn(i,1,3)

inline Rect dashSettingsBtn(int W, int H) { return bottomRightBtn(W, H); }
inline Rect backBtn(int W, int H) { return bottomLeftBtn(W, H); }

// --- keyboard -------------------------------------------------------------------------------------
enum { kLayerLower = 0, kLayerUpper = 1, kLayerSym = 2 };
enum { kFnShift = 0, kFnLayer, kFnSpace, kFnShow, kFnBack, kFnCancel, kFnOk, kFnCount };

inline const char* kbRow(int layer, int row) {
  static const char* const t[3][4] = {
      {"1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"},
      {"1234567890", "QWERTYUIOP", "ASDFGHJKL", "ZXCVBNM"},
      {"1234567890", "!@#$%^&*()", "-_=+[]{};:", "'\",.<>/?\\|"},
  };
  return t[layer][row];
}
inline Rect kbField(int W, int H) {
  (void)H;
  Rect r = {6, 4, (int16_t)(W - 12), 28};
  return r;
}
inline Rect kbKey(int row, int col, int n, int W, int H) {
  (void)H;
  const int kw = W / 10, off = (W - n * kw) / 2;
  Rect r = {(int16_t)(off + col * kw), (int16_t)(36 + row * 38), (int16_t)(kw - 2), 36};
  return r;
}
inline Rect kbFn(int i, int W, int H) {
  (void)H;
  const int fw = W / kFnCount;
  Rect r = {(int16_t)(i * fw), (int16_t)(36 + 4 * 38), (int16_t)(fw - 2), 36};
  return r;
}

// --- calibration ----------------------------------------------------------------------------------
inline void calTarget(int step, int W, int H, int16_t* x, int16_t* y) {
  const int m = 20;
  *x = (step == 0 || step == 3) ? m : W - m;
  *y = (step == 0 || step == 1) ? m : H - m;
}

}  // namespace ui
}  // namespace fry

#endif  // FRY_UI_TOUCH_LAYOUT_H
