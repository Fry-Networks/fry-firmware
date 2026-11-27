// In-memory Canvas (host tests and the simulator). Fixed storage after construction: drawing never
// allocates, so the animator's "no heap after begin" property can be measured against it.
#ifndef FRY_UI_MEM_CANVAS_H
#define FRY_UI_MEM_CANVAS_H

#include <stdint.h>
#include <string.h>

#include "../../include/fry_display_hal.h"

namespace fry {
namespace disp {

class MemCanvas : public Canvas {
 public:
  MemCanvas(uint16_t w, uint16_t h, bool mono) : w_(w), h_(h), mono_(mono), px_(new uint16_t[(size_t)w * h]) {
    clear(0);
    ops_ = 0;
    flushes_ = 0;
  }
  ~MemCanvas() { delete[] px_; }

  uint16_t width() const override { return w_; }
  uint16_t height() const override { return h_; }
  bool mono() const override { return mono_; }
  void clear(uint16_t c) override {
    ops_++;
    for (size_t i = 0; i < (size_t)w_ * h_; i++) px_[i] = c;
    textLen_ = 0;
    text_[0] = 0;
  }
  void fillRect(int16_t x, int16_t y, int16_t w, int16_t h, uint16_t c) override {
    ops_++;
    for (int yy = y; yy < y + h; yy++)
      for (int xx = x; xx < x + w; xx++) put(xx, yy, c);
  }
  void drawPixel(int16_t x, int16_t y, uint16_t c) override {
    ops_++;
    put(x, y, c);
  }
  void drawText(int16_t x, int16_t y, const char* s, uint8_t size, uint16_t fg, uint16_t bg) override {
    ops_++;
    if (size == 0) size = 1;
    const int cw = 6 * size, chh = 8 * size;
    int cx = x;
    for (const char* p = s; *p; p++, cx += cw) {
      // Glyph stand-in: a deterministic 5x7 pattern keyed on the character, so different text
      // yields different pixels (frame hashes) without carrying a font table into the host build.
      for (int gy = 0; gy < 7; gy++)
        for (int gx = 0; gx < 5; gx++) {
          const bool on = (((uint32_t)(uint8_t)*p * 2654435761u) >> ((gy * 5 + gx) % 31)) & 1u;
          for (int sy = 0; sy < size; sy++)
            for (int sx = 0; sx < size; sx++) put(cx + gx * size + sx, y + gy * size + sy, on ? fg : bg);
        }
      (void)chh;
    }
    append(s);
    append("\n");
  }
  void drawBitmap1(int16_t x, int16_t y, const uint8_t* bits, int16_t w, int16_t h, uint16_t fg) override {
    ops_++;
    const int stride = (w + 7) / 8;
    for (int yy = 0; yy < h; yy++)
      for (int xx = 0; xx < w; xx++)
        if (bits[yy * stride + xx / 8] & (0x80 >> (xx % 8))) put(x + xx, y + yy, fg);
  }
  void flush() override { flushes_++; }

  uint16_t at(int x, int y) const { return (x < 0 || y < 0 || x >= w_ || y >= h_) ? 0 : px_[(size_t)y * w_ + x]; }
  uint32_t hash() const {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < (size_t)w_ * h_; i++) h = (h ^ px_[i]) * 16777619u;
    return h;
  }
  uint32_t ops() const { return ops_; }
  uint32_t flushes() const { return flushes_; }
  void resetOps() { ops_ = 0; }
  // Text drawn since the last clear(), one string per line.
  const char* text() const { return text_; }
  bool hasText(const char* needle) const { return strstr(text_, needle) != nullptr; }
  size_t countNonZero() const {
    size_t n = 0;
    for (size_t i = 0; i < (size_t)w_ * h_; i++) n += px_[i] != 0;
    return n;
  }

 private:
  void put(int x, int y, uint16_t c) {
    if (x >= 0 && y >= 0 && x < w_ && y < h_) px_[(size_t)y * w_ + x] = c;
  }
  void append(const char* s) {
    while (*s && textLen_ + 1 < sizeof(text_)) text_[textLen_++] = *s++;
    text_[textLen_] = 0;
  }
  uint16_t w_, h_;
  bool mono_;
  uint16_t* px_;
  uint32_t ops_ = 0, flushes_ = 0;
  char text_[2048];
  size_t textLen_ = 0;
};

}  // namespace disp
}  // namespace fry

#endif  // FRY_UI_MEM_CANVAS_H
