#include "touch_cal.h"

namespace fry {
namespace ui {

namespace {

// Solve the 3x3 normal equations for one output axis by Cramer's rule.
bool solve(const double X[4], const double Y[4], const double T[4], double out[3]) {
  double sxx = 0, sxy = 0, sx = 0, syy = 0, sy = 0, n = 4, sxt = 0, syt = 0, st = 0;
  for (int i = 0; i < 4; i++) {
    sxx += X[i] * X[i];
    sxy += X[i] * Y[i];
    sx += X[i];
    syy += Y[i] * Y[i];
    sy += Y[i];
    sxt += X[i] * T[i];
    syt += Y[i] * T[i];
    st += T[i];
  }
  const double M[3][3] = {{sxx, sxy, sx}, {sxy, syy, sy}, {sx, sy, n}};
  const double R[3] = {sxt, syt, st};
  auto det = [](const double a[3][3]) {
    return a[0][0] * (a[1][1] * a[2][2] - a[1][2] * a[2][1]) - a[0][1] * (a[1][0] * a[2][2] - a[1][2] * a[2][0]) +
           a[0][2] * (a[1][0] * a[2][1] - a[1][1] * a[2][0]);
  };
  const double d = det(M);
  if (d < 1.0 && d > -1.0) return false;
  for (int col = 0; col < 3; col++) {
    double Mc[3][3];
    for (int r = 0; r < 3; r++)
      for (int k = 0; k < 3; k++) Mc[r][k] = (k == col) ? R[r] : M[r][k];
    out[col] = det(Mc) / d;
  }
  return true;
}

}  // namespace

bool calFit(const int16_t cal[8], int W, int H, float A[6]) {
  bool any = false;
  for (int i = 0; i < 8; i++) any = any || cal[i] != 0;
  if (!any) return false;
  double X[4], Y[4], TX[4], TY[4];
  for (int i = 0; i < 4; i++) {
    int16_t tx, ty;
    calTarget(i, W, H, &tx, &ty);
    X[i] = cal[i * 2];
    Y[i] = cal[i * 2 + 1];
    TX[i] = tx;
    TY[i] = ty;
  }
  double a[3], b[3];
  if (!solve(X, Y, TX, a) || !solve(X, Y, TY, b)) return false;
  A[0] = (float)a[0];
  A[1] = (float)a[1];
  A[2] = (float)a[2];
  A[3] = (float)b[0];
  A[4] = (float)b[1];
  A[5] = (float)b[2];
  return true;
}

void calApply(const float A[6], int16_t* x, int16_t* y, int W, int H) {
  const float fx = A[0] * *x + A[1] * *y + A[2];
  const float fy = A[3] * *x + A[4] * *y + A[5];
  int ix = (int)(fx + (fx < 0 ? -0.5f : 0.5f)), iy = (int)(fy + (fy < 0 ? -0.5f : 0.5f));
  if (ix < 0) ix = 0;
  if (iy < 0) iy = 0;
  if (ix > W - 1) ix = W - 1;
  if (iy > H - 1) iy = H - 1;
  *x = (int16_t)ix;
  *y = (int16_t)iy;
}

}  // namespace ui
}  // namespace fry
