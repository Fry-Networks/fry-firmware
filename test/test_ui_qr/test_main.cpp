// QR payload for "Setup with App" and the matrix generator (ricmoo/QRCode), plus touch calibration math.
#include <unity.h>

#include "../../include/fry_touch_ui.h"
#include "../../lib/fry_ui/qr_draw.h"
#include "../../lib/fry_ui/touch_cal.h"

using namespace fry;
using namespace fry::ui;

void setUp(void) {}
void tearDown(void) {}

static bool finder(const uint8_t* m, int n, int ox, int oy) {
  // 7x7 finder: dark ring, light ring, dark 3x3 core
  for (int y = 0; y < 7; y++)
    for (int x = 0; x < 7; x++) {
      const bool ring = x == 0 || y == 0 || x == 6 || y == 6;
      const bool core = x >= 2 && x <= 4 && y >= 2 && y <= 4;
      if (qrGet(m, n, ox + x, oy + y) != (ring || core)) return false;
    }
  return true;
}

void test_payload_ap_uses_standard_wifi_qr() {
  MinerStatus s;
  memset(&s, 0, sizeof(s));
  strcpy(s.apSsid, "FRY-Setup-A1B2");
  strcpy(s.boardName, "FRY-ESP32-A1B2C3");
  char out[96];
  size_t n = appQrPayload(s, out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("WIFI:T:nopass;S:FRY-Setup-A1B2;;", out);
  TEST_ASSERT_EQUAL_UINT32(strlen(out), n);
}

void test_payload_escapes_specials_and_truncation_safe() {
  MinerStatus s;
  memset(&s, 0, sizeof(s));
  strcpy(s.apSsid, "a;b:c\\d");
  char out[96];
  appQrPayload(s, out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("WIFI:T:nopass;S:a\\;b\\:c\\\\d;;", out);
  char tiny[10];
  size_t n = appQrPayload(s, tiny, sizeof(tiny));
  TEST_ASSERT_EQUAL_UINT32(0, n);  // does not fit -> nothing, never a half payload
  TEST_ASSERT_EQUAL_STRING("", tiny);
}

void test_payload_without_ap_uses_board_name() {
  MinerStatus s;
  memset(&s, 0, sizeof(s));
  strcpy(s.boardName, "FRY-ESP32-A1B2C3");
  char out[96];
  appQrPayload(s, out, sizeof(out));
  TEST_ASSERT_EQUAL_STRING("FRY:FRY-ESP32-A1B2C3", out);
}

void test_matrix_has_finder_patterns_and_is_deterministic() {
  uint8_t a[512], b[512], c[512];
  int na = qrEncode("WIFI:T:nopass;S:FRY-Setup-A1B2;;", a, sizeof(a));
  int nb = qrEncode("WIFI:T:nopass;S:FRY-Setup-A1B2;;", b, sizeof(b));
  int nc = qrEncode("FRY:FRY-ESP32-A1B2C3", c, sizeof(c));
  TEST_ASSERT_TRUE(na >= 21);
  TEST_ASSERT_EQUAL_INT(1, na % 4);
  TEST_ASSERT_EQUAL_INT(na, nb);
  TEST_ASSERT_EQUAL_MEMORY(a, b, ((size_t)na * na + 7) / 8);
  TEST_ASSERT_TRUE(finder(a, na, 0, 0));
  TEST_ASSERT_TRUE(finder(a, na, na - 7, 0));
  TEST_ASSERT_TRUE(finder(a, na, 0, na - 7));
  TEST_ASSERT_TRUE(nc >= 21);
  TEST_ASSERT_TRUE(finder(c, nc, 0, 0));
  TEST_ASSERT_TRUE(na != nc || memcmp(a, c, ((size_t)na * na + 7) / 8) != 0);
}

void test_matrix_rejects_too_long_and_small_buffer() {
  uint8_t m[512];
  char longText[400];
  memset(longText, 'x', sizeof(longText) - 1);
  longText[sizeof(longText) - 1] = 0;
  TEST_ASSERT_EQUAL_INT(0, qrEncode(longText, m, sizeof(m)));
  uint8_t tiny[4];
  TEST_ASSERT_EQUAL_INT(0, qrEncode("FRY:abc", tiny, sizeof(tiny)));
}

// ---- touch calibration -----------------------------------------------------------------------------------
void test_affine_identity_when_taps_hit_targets() {
  int16_t cal[8];
  for (int i = 0; i < 4; i++) calTarget(i, 320, 240, &cal[i * 2], &cal[i * 2 + 1]);
  float A[6];
  TEST_ASSERT_TRUE(calFit(cal, 320, 240, A));
  int16_t x = 100, y = 120;
  calApply(A, &x, &y, 320, 240);
  TEST_ASSERT_INT16_WITHIN(1, 100, x);
  TEST_ASSERT_INT16_WITHIN(1, 120, y);
}

void test_affine_corrects_offset_and_scale() {
  // panel reads x as 0.9*x+10, y as 1.1*y-5; calibration must undo that
  int16_t cal[8];
  for (int i = 0; i < 4; i++) {
    int16_t tx, ty;
    calTarget(i, 320, 240, &tx, &ty);
    cal[i * 2] = (int16_t)(0.9f * tx + 10);
    cal[i * 2 + 1] = (int16_t)(1.1f * ty - 5);
  }
  float A[6];
  TEST_ASSERT_TRUE(calFit(cal, 320, 240, A));
  int16_t x = (int16_t)(0.9f * 160 + 10), y = (int16_t)(1.1f * 100 - 5);
  calApply(A, &x, &y, 320, 240);
  TEST_ASSERT_INT16_WITHIN(2, 160, x);
  TEST_ASSERT_INT16_WITHIN(2, 100, y);
}

void test_affine_rejects_degenerate_and_zero_cal() {
  float A[6];
  int16_t zero[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  TEST_ASSERT_FALSE(calFit(zero, 320, 240, A));
  int16_t same[8] = {50, 50, 50, 50, 50, 50, 50, 50};
  TEST_ASSERT_FALSE(calFit(same, 320, 240, A));
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_payload_ap_uses_standard_wifi_qr);
  RUN_TEST(test_payload_escapes_specials_and_truncation_safe);
  RUN_TEST(test_payload_without_ap_uses_board_name);
  RUN_TEST(test_matrix_has_finder_patterns_and_is_deterministic);
  RUN_TEST(test_matrix_rejects_too_long_and_small_buffer);
  RUN_TEST(test_affine_identity_when_taps_hit_targets);
  RUN_TEST(test_affine_corrects_offset_and_scale);
  RUN_TEST(test_affine_rejects_degenerate_and_zero_cal);
  return UNITY_END();
}
