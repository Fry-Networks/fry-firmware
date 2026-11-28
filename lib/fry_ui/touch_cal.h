// Touch calibration: the Calibrate screen stores the four points the panel reported for four known
// targets (touch_layout.h calTarget); the device TouchHal fits an affine correction from them.
// An all-zero set means "no correction".
#ifndef FRY_UI_TOUCH_CAL_H
#define FRY_UI_TOUCH_CAL_H

#include <stdint.h>

#include "touch_layout.h"

namespace fry {
namespace ui {

// A = {a,b,c,d,e,f}: x' = a*x + b*y + c, y' = d*x + e*y + f. False for an all-zero or degenerate set.
bool calFit(const int16_t cal[8], int W, int H, float A[6]);
void calApply(const float A[6], int16_t* x, int16_t* y, int W, int H);

}  // namespace ui
}  // namespace fry

#endif  // FRY_UI_TOUCH_CAL_H
