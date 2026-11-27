// ScreenAnimator: one distinct looping animation per MinerState. tick() is non-blocking, rate-capped
// and allocation-free; every frame is a bounded number of Canvas calls on stack buffers.
#include <stdio.h>
#include <string.h>

#include "../../include/fry_touch_ui.h"
#include "ui_widgets.h"

namespace fry {
namespace ui {

namespace {

const char* stateTitle(MinerState s) {
  switch (s) {
    case MinerState::Boot: return "FRY";
    case MinerState::SetupAP: return "SETUP";
    case MinerState::WifiConnecting: return "WIFI";
    case MinerState::Mining: return "MINING";
    case MinerState::HeartbeatOk: return "ONLINE";
    case MinerState::OtaUpdating: return "UPDATE";
    default: return "ERROR";
  }
}

void fmtUptime(char* out, size_t cap, uint32_t s) {
  snprintf(out, cap, "up %uh%02um", (unsigned)(s / 3600), (unsigned)((s / 60) % 60));
}

// Triangle wave 0..n..0 over 2n steps.
int tri(uint32_t f, int n) {
  const int k = (int)(f % (uint32_t)(2 * n));
  return k <= n ? k : 2 * n - k;
}

}  // namespace

void ScreenAnimator::drawInto(disp::Canvas& c, const MinerStatus& s, uint32_t frame, int16_t x, int16_t y, int16_t w,
                              int16_t h, bool full) {
  const Pal p = palette(c.mono());
  const uint8_t sz = (w >= 200 && h >= 100) ? 2 : 1;
  const int16_t lh = (int16_t)(8 * sz + 2);
  char buf[48];

  c.fillRect(x, y, w, h, p.bg);

  int16_t top = y;  // animation area below the text header
  int16_t bot = (int16_t)(y + h - 5);
  if (full) {
    c.drawText((int16_t)(x + 2), (int16_t)(y + 1), stateTitle(s.state), sz, p.fg, p.bg);
    top = (int16_t)(y + lh + 2);
  }
  const int16_t aw = w, ah = (int16_t)(bot - top);
  const int16_t cx = (int16_t)(x + aw / 2), cy = (int16_t)(top + ah / 2);

  switch (s.state) {
    case MinerState::Boot: {  // progress sweep
      const uint8_t pct = (uint8_t)((frame * 4) % 100);
      Rect r = {(int16_t)(x + 4), (int16_t)(cy - 4), (int16_t)(aw - 8), 9};
      drawProgress(c, r, pct, p);
      if (full) {
        snprintf(buf, sizeof(buf), "v%s", s.fwVersion);
        c.drawText((int16_t)(x + 2), (int16_t)(bot - 8 * sz), buf, sz, p.dim, p.bg);
      }
      break;
    }
    case MinerState::SetupAP: {  // radiating squares
      const int step = ah / 8 > 2 ? ah / 8 : 2;
      for (int k = 0; k < 3; k++) {
        const int r = (int)((frame + k * 3) % 9) * step / 2 + 2;
        if (r * 2 < aw && r * 2 < ah) drawOutline(c, (int16_t)(cx - r), (int16_t)(cy - r), (int16_t)(2 * r), (int16_t)(2 * r), p.accent);
      }
      if (full) {
        c.drawText((int16_t)(x + 2), (int16_t)(bot - 2 * lh), s.apSsid, sz, p.fg, p.bg);
        c.drawText((int16_t)(x + 2), (int16_t)(bot - lh), s.apIp, sz, p.dim, p.bg);
      }
      break;
    }
    case MinerState::WifiConnecting: {  // three dots chase
      const int active = (int)(frame % 4);
      for (int k = 0; k < 3; k++) {
        const int16_t dx = (int16_t)(cx + (k - 1) * (aw / 5));
        const int16_t d = (active == k) ? 8 : 4;
        c.fillRect((int16_t)(dx - d / 2), (int16_t)(cy - d / 2), d, d, active == k ? p.accent : p.dim);
      }
      if (full) c.drawText((int16_t)(x + 2), (int16_t)(bot - lh), s.ssid, sz, p.fg, p.bg);
      break;
    }
    case MinerState::Mining: {  // hash-rate style bars
      const int n = 8;
      const int bw = (aw - 8) / n;
      for (int k = 0; k < n; k++) {
        const int hh = 2 + ((int)((frame * 3 + (uint32_t)k * 5) % 13)) * (ah - 4) / 13;
        c.fillRect((int16_t)(x + 4 + k * bw), (int16_t)(top + ah - hh), (int16_t)(bw - 2), (int16_t)hh, p.ok);
      }
      if (full) {
        c.drawText((int16_t)(x + 2), (int16_t)(bot - 2 * lh), s.ssid, sz, p.fg, p.bg);
        snprintf(buf, sizeof(buf), "%s %ddBm", s.ip, (int)s.rssi);
        c.drawText((int16_t)(x + 2), (int16_t)(bot - lh), buf, sz, p.dim, p.bg);
      }
      break;
    }
    case MinerState::HeartbeatOk: {  // pulsing heart-block
      const int r = 3 + tri(frame, 5) * (ah / 2 - 3) / 5;
      c.fillRect((int16_t)(cx - r), (int16_t)(cy - r), (int16_t)(2 * r), (int16_t)(2 * r), p.ok);
      if (full) {
        fmtUptime(buf, sizeof(buf), s.uptimeS);
        c.drawText((int16_t)(x + 2), (int16_t)(bot - lh), buf, sz, p.dim, p.bg);
      }
      break;
    }
    case MinerState::OtaUpdating: {  // progress + orbiting dot
      Rect r = {(int16_t)(x + 4), (int16_t)(cy - 4), (int16_t)(aw - 8), 9};
      drawProgress(c, r, s.otaPct, p);
      const int k = (int)(frame % 8);
      const int16_t ox = (int16_t)(cx + ((k < 3) ? k - 1 : (k < 5 ? 1 : (7 - k) - 1)) * 6);
      c.fillRect(ox, (int16_t)(cy + 8), 3, 3, p.warn);
      snprintf(buf, sizeof(buf), "%u%%", (unsigned)(s.otaPct > 100 ? 100 : s.otaPct));
      if (full) {
        c.drawText((int16_t)(x + 2), (int16_t)(bot - 2 * lh), buf, sz, p.fg, p.bg);
        c.drawText((int16_t)(x + 2), (int16_t)(bot - lh), s.otaStage, sz, p.dim, p.bg);
      }
      break;
    }
    default: {  // Error: blinking block with a bar
      const bool on = (frame % 2) == 0;
      const int bwid = ah / 2 + 4;
      c.fillRect((int16_t)(cx - bwid), (int16_t)(cy - ah / 4), (int16_t)(2 * bwid), (int16_t)(ah / 2), on ? p.err : (c.mono() ? p.bg : p.dim));
      c.fillRect((int16_t)(cx - 2), (int16_t)(cy - ah / 4 + 3), 4, (int16_t)(ah / 4), p.bg);
      if (full) {
        snprintf(buf, sizeof(buf), "E%u", (unsigned)s.errCode);
        c.drawText((int16_t)(x + 2), (int16_t)(bot - lh), buf, sz, p.fg, p.bg);
      }
      break;
    }
  }

  // Activity sweep: guarantees consecutive frames of every state differ.
  const int16_t span = (int16_t)(aw - 6);
  c.fillRect((int16_t)(x + 2 + (int16_t)((frame * 3) % (uint32_t)span)), (int16_t)(y + h - 3), 3, 2, p.accent);
}

void ScreenAnimator::begin(disp::Canvas& c, uint16_t fpsCap) {
  c_ = &c;
  intervalMs_ = fpsCap ? 1000u / fpsCap : 100u;
  if (intervalMs_ == 0) intervalMs_ = 1;
  lastDrawMs_ = 0;
  frames_ = 0;
  frameNo_ = 0;
  lastState_ = MinerState::Boot;
  drawnOnce_ = false;
}

bool ScreenAnimator::tick(uint32_t nowMs, const MinerStatus& s) {
  if (!c_) return false;
  const bool changed = !drawnOnce_ || s.state != lastState_;
  if (!changed && (uint32_t)(nowMs - lastDrawMs_) < intervalMs_) return false;
  frameNo_ = changed ? 0 : frameNo_ + 1;
  drawInto(*c_, s, frameNo_, 0, 0, (int16_t)c_->width(), (int16_t)c_->height(), true);
  c_->flush();
  lastDrawMs_ = nowMs;
  lastState_ = s.state;
  drawnOnce_ = true;
  frames_++;
  return true;
}

uint32_t ScreenAnimator::framesDrawn() const { return frames_; }
uint32_t ScreenAnimator::frameNo() const { return frameNo_; }

}  // namespace ui
}  // namespace fry
