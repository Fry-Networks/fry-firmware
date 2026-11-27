#include "qr_draw.h"

#include <string.h>

#include <qrcode.h>

namespace fry {
namespace ui {

size_t appQrPayload(const MinerStatus& s, char* out, size_t cap) {
  if (!out || cap == 0) return 0;
  out[0] = 0;
  size_t n = 0;
  auto put = [&](char ch) -> bool {
    if (n + 1 >= cap) return false;
    out[n++] = ch;
    return true;
  };
  bool ok = true;
  if (s.apSsid[0]) {
    const char* pre = "WIFI:T:nopass;S:";
    for (const char* p = pre; *p && ok; p++) ok = put(*p);
    for (const char* p = s.apSsid; *p && ok; p++) {
      if (*p == '\\' || *p == ';' || *p == ',' || *p == ':' || *p == '"') ok = put('\\');
      if (ok) ok = put(*p);
    }
    if (ok) ok = put(';');
    if (ok) ok = put(';');
  } else {
    const char* pre = "FRY:";
    for (const char* p = pre; *p && ok; p++) ok = put(*p);
    for (const char* p = s.boardName; *p && ok; p++) ok = put(*p);
  }
  if (!ok) {
    out[0] = 0;
    return 0;
  }
  out[n] = 0;
  return n;
}

bool qrGet(const uint8_t* m, int n, int x, int y) {
  if (x < 0 || y < 0 || x >= n || y >= n) return false;
  const int idx = y * n + x;
  return (m[idx / 8] >> (7 - idx % 8)) & 1;
}

int qrEncode(const char* text, uint8_t* out, size_t cap) {
  // Byte-mode capacity at ECC_LOW per version. The library trusts its caller about length, so a text
  // that cannot fit a version is never handed to it (it would overrun the work buffer).
  static const uint16_t kCap[11] = {0, 17, 32, 53, 78, 106, 134, 154, 192, 230, 271};
  const size_t len = strlen(text);
  uint8_t work[512];
  for (uint8_t v = 1; v <= 10; v++) {
    if (len > kCap[v]) continue;
    if (qrcode_getBufferSize(v) > sizeof(work)) break;
    QRCode qr;
    if (qrcode_initText(&qr, work, v, ECC_LOW, text) != 0) continue;
    const int n = qr.size;
    const size_t bytes = ((size_t)n * n + 7) / 8;
    if (bytes > cap) return 0;
    memset(out, 0, bytes);
    for (int y = 0; y < n; y++)
      for (int x = 0; x < n; x++)
        if (qrcode_getModule(&qr, (uint8_t)x, (uint8_t)y)) {
          const int idx = y * n + x;
          out[idx / 8] |= (uint8_t)(0x80 >> (idx % 8));
        }
    return n;
  }
  return 0;
}

void drawQr(disp::Canvas& c, const uint8_t* m, int n, int16_t x, int16_t y, int16_t w, int16_t h) {
  const int total = n + 8;
  int scale = (w < h ? w : h) / total;
  if (scale < 1) scale = 1;
  const int px = total * scale;
  const int16_t ox = (int16_t)(x + (w - px) / 2), oy = (int16_t)(y + (h - px) / 2);
  const uint16_t white = c.mono() ? 1 : 0xFFFF, black = 0;
  c.fillRect(ox, oy, (int16_t)px, (int16_t)px, white);
  for (int my = 0; my < n; my++)
    for (int mx = 0; mx < n; mx++)
      if (qrGet(m, n, mx, my))
        c.fillRect((int16_t)(ox + (mx + 4) * scale), (int16_t)(oy + (my + 4) * scale), (int16_t)scale, (int16_t)scale, black);
}

}  // namespace ui
}  // namespace fry
