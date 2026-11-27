// TouchUI: the on-device setup + dashboard UI for touch screens. Pure C++ over the Canvas / TouchHal /
// Store / StatusSource / Actions interfaces, so the whole flow runs unchanged in the native simulator.
// Fixed storage only: nothing is allocated after begin().
#include <stdio.h>
#include <string.h>

#include "../../include/fry_touch_ui.h"
#include "qr_draw.h"
#include "touch_layout.h"
#include "ui_widgets.h"

namespace fry {
namespace ui {

namespace {

const uint32_t kPollMs = 1000;        // Store + status poll
const uint32_t kScanPollMs = 250;     // WiFi scan result poll
const uint32_t kScanTimeoutMs = 12000;
const uint32_t kArmMs = 5000;         // factory-reset second tap must land inside this window
const uint32_t kConnectTimeoutMs = 45000;
const uint32_t kFrameMs = 100;        // animation frame period on animated screens

void copyStr(char* dst, size_t cap, const char* src) {
  strncpy(dst, src, cap - 1);
  dst[cap - 1] = 0;
}

bool animated(uint8_t s) { return s == S_Connecting || s == S_Ota; }

const char* stateName(MinerState s) {
  switch (s) {
    case MinerState::Boot: return "booting";
    case MinerState::SetupAP: return "setup";
    case MinerState::WifiConnecting: return "connecting";
    case MinerState::Mining: return "mining";
    case MinerState::HeartbeatOk: return "online";
    case MinerState::OtaUpdating: return "updating";
    default: return "error";
  }
}

}  // namespace

void TouchUI::begin(disp::Canvas& c, TouchHal& t, cfg::Store& st, StatusSource& src, Actions& a) {
  c_ = &c;
  t_ = &t;
  st_ = &st;
  src_ = &src;
  a_ = &a;
  memset(&snap_, 0, sizeof(snap_));
  memset(&status_, 0, sizeof(status_));
  memset(ssids_, 0, sizeof(ssids_));
  memset(rssis_, 0, sizeof(rssis_));
  memset(secs_, 0, sizeof(secs_));
  memset(selSsid_, 0, sizeof(selSsid_));
  memset(text_, 0, sizeof(text_));
  memset(pass_, 0, sizeof(pass_));
  memset(key_, 0, sizeof(key_));
  memset(cal_, 0, sizeof(cal_));
  textLen_ = 0;
  nSsid_ = 0;
  scanning_ = false;
  armed_ = false;
  started_ = false;
  prevPressed_ = false;
  bright_ = 100;
  rot_ = 0;
  st_->load(snap_);
  lastGen_ = snap_.generation;
  src_->read(status_);
  screen_ = (snap_.hasWifi && snap_.hasMinerKey) ? S_Dashboard : S_FirstBoot;
  dirty_ = true;
}

uint8_t TouchUI::screenId() const { return screen_; }

void TouchUI::go(uint8_t s, uint32_t now) {
  screen_ = s;
  screenSinceMs_ = now;
  dirty_ = true;
  armed_ = false;
  saveFailed_ = false;
  if (s == S_SetupChoice || s == S_Dashboard || s == S_FirstBoot || s == S_WifiList) {
    memset(pass_, 0, sizeof(pass_));
    memset(key_, 0, sizeof(key_));
    memset(text_, 0, sizeof(text_));
    textLen_ = 0;
  }
  switch (s) {
    case S_WifiList:
      nSsid_ = 0;
      scanning_ = a_->startWifiScan();
      lastScanMs_ = now - kScanPollMs;
      break;
    case S_Keyboard:
      memset(text_, 0, sizeof(text_));
      textLen_ = 0;
      layer_ = kLayerLower;
      show_ = false;
      break;
    case S_MinerKey:
      memset(text_, 0, sizeof(text_));
      memcpy(text_, "FEM-", 4);
      textLen_ = 4;
      layer_ = kLayerLower;
      show_ = true;
      break;
    case S_Calibrate:
      calStep_ = 0;
      memset(cal_, 0, sizeof(cal_));
      st_->saveTouchCal(cal_);  // drop the old correction so the four taps are measured raw
      break;
    case S_Connecting:
      connectFailed_ = false;
      break;
    default:
      break;
  }
}

void TouchUI::typeChar(char ch) {
  const uint8_t cap = (screen_ == S_MinerKey) ? 36 : 63;
  if (textLen_ >= cap) return;
  text_[textLen_++] = ch;
  text_[textLen_] = 0;
  dirty_ = true;
}

void TouchUI::finishSetup(uint32_t now) {
  if (key_[0] && !st_->saveMinerKey(key_)) {
    saveFailed_ = true;
    dirty_ = true;
    return;
  }
  if (!st_->saveWifi(selSsid_, pass_)) {
    saveFailed_ = true;
    dirty_ = true;
    return;
  }
  memset(pass_, 0, sizeof(pass_));
  memset(key_, 0, sizeof(key_));
  memset(text_, 0, sizeof(text_));
  textLen_ = 0;
  a_->requestConnect();
  go(S_Connecting, now);
}

void TouchUI::tapKeyboard(int16_t x, int16_t y, uint32_t now) {
  const int W = c_->width(), H = c_->height();
  for (int r = 0; r < 4; r++) {
    const char* row = kbRow(layer_, r);
    const int n = (int)strlen(row);
    for (int k = 0; k < n; k++) {
      if (kbKey(r, k, n, W, H).contains(x, y)) {
        typeChar(row[k]);
        return;
      }
    }
  }
  for (int f = 0; f < kFnCount; f++) {
    if (!kbFn(f, W, H).contains(x, y)) continue;
    switch (f) {
      case kFnShift:
        layer_ = (layer_ == kLayerUpper) ? kLayerLower : kLayerUpper;
        dirty_ = true;
        break;
      case kFnLayer:
        layer_ = (layer_ == kLayerSym) ? kLayerLower : kLayerSym;
        dirty_ = true;
        break;
      case kFnSpace:
        typeChar(' ');
        break;
      case kFnShow:
        show_ = !show_;
        dirty_ = true;
        break;
      case kFnBack:
        if (textLen_ > (screen_ == S_MinerKey ? 4 : 0)) {  // the FEM- prefix stays
          text_[--textLen_] = 0;
          dirty_ = true;
        }
        break;
      case kFnCancel:
        go(S_WifiList, now);
        break;
      case kFnOk:
        if (screen_ == S_Keyboard) {
          copyStr(pass_, sizeof(pass_), text_);
          if (snap_.hasMinerKey) finishSetup(now);
          else go(S_MinerKey, now);
        } else if (cfg::validMinerKey(text_)) {
          copyStr(key_, sizeof(key_), text_);
          finishSetup(now);
        } else {
          saveFailed_ = true;
          dirty_ = true;
        }
        break;
    }
    return;
  }
}

void TouchUI::onTap(int16_t x, int16_t y, uint32_t now) {
  const int W = c_->width(), H = c_->height();
  switch (screen_) {
    case S_FirstBoot:
      if (gridBtn(kFirstContinue, 1, 3, W, H).contains(x, y)) go(S_SetupChoice, now);
      break;
    case S_SetupChoice:
      if (gridBtn(kChoiceScreen, 1, 3, W, H).contains(x, y)) go(S_WifiList, now);
      else if (gridBtn(kChoiceApp, 1, 3, W, H).contains(x, y)) go(S_AppQr, now);
      break;
    case S_WifiList:
      if (gridBtn(kWifiBack, 1, 6, W, H).contains(x, y)) {
        go(S_SetupChoice, now);
        break;
      }
      if (nSsid_ == 0 && !scanning_ && gridBtn(0, 1, 6, W, H).contains(x, y)) {
        go(S_WifiList, now);  // rescan
        break;
      }
      for (int i = 0; i < kWifiRows && i < nSsid_; i++) {
        if (!gridBtn(i, 1, 6, W, H).contains(x, y)) continue;
        copyStr(selSsid_, sizeof(selSsid_), ssids_[i]);
        selSecured_ = secs_[i];
        pass_[0] = 0;
        if (selSecured_) go(S_Keyboard, now);
        else if (snap_.hasMinerKey) finishSetup(now);
        else go(S_MinerKey, now);
        break;
      }
      break;
    case S_Keyboard:
    case S_MinerKey:
      tapKeyboard(x, y, now);
      break;
    case S_Connecting:
    case S_AppQr:
      if (backBtn(W, H).contains(x, y)) go(S_SetupChoice, now);
      break;
    case S_Dashboard:
      if (dashSettingsBtn(W, H).contains(x, y)) go(S_Settings, now);
      break;
    case S_Settings:
      for (int i = 0; i <= kSetBack; i++) {
        if (!gridBtn(i, 2, 4, W, H).contains(x, y)) continue;
        switch (i) {
          case kSetCheckOta: a_->requestOtaCheck(); break;
          case kSetBrightDn:
            bright_ = bright_ > 30 ? (uint8_t)(bright_ - 20) : 10;
            a_->setBrightness(bright_);
            break;
          case kSetBrightUp:
            bright_ = bright_ < 80 ? (uint8_t)(bright_ + 20) : 100;
            a_->setBrightness(bright_);
            break;
          case kSetRotate:
            rot_ = (uint8_t)((rot_ + 1) % 4);
            a_->setRotation(rot_);
            dirty_ = true;
            break;
          case kSetCalibrate: go(S_Calibrate, now); break;
          case kSetReset: go(S_ConfirmReset, now); break;
          case kSetBack: go(S_Dashboard, now); break;
        }
        break;
      }
      break;
    case S_ConfirmReset:
      if (gridBtn(kResetCancel, 1, 3, W, H).contains(x, y)) {
        go(S_Settings, now);
      } else if (gridBtn(kResetConfirm, 1, 3, W, H).contains(x, y)) {
        if (armed_ && (uint32_t)(now - armedAtMs_) < kArmMs) {
          st_->factoryReset();
          a_->reboot();
          armed_ = false;
          dirty_ = true;
        } else {
          armed_ = true;
          armedAtMs_ = now;
          dirty_ = true;
        }
      }
      break;
    case S_Calibrate:
      cal_[calStep_ * 2] = x;
      cal_[calStep_ * 2 + 1] = y;
      calStep_++;
      dirty_ = true;
      if (calStep_ >= 4) {
        st_->saveTouchCal(cal_);
        go(S_Settings, now);
      }
      break;
    default:
      break;
  }
}

void TouchUI::poll(uint32_t now) {
  MinerStatus old = status_;
  cfg::Snapshot s;
  if (st_->load(s)) {
    if (s.generation != lastGen_) {
      lastGen_ = s.generation;
      dirty_ = true;  // re-render on any stored-config change
    }
    snap_ = s;
  }
  src_->read(status_);
  animFrame_++;
  const bool live = screen_ == S_Dashboard || screen_ == S_Connecting || screen_ == S_Ota || screen_ == S_AppQr;
  if (live && memcmp(&old, &status_, sizeof(MinerStatus)) != 0) dirty_ = true;

  // Configuration landed by another path (phone app over BLE / captive portal): no on-board setup needed.
  if ((screen_ == S_FirstBoot || screen_ == S_SetupChoice || screen_ == S_AppQr) && snap_.hasWifi &&
      snap_.hasMinerKey && snap_.provDone) {
    go(S_Dashboard, now);
    return;
  }
  if (screen_ == S_Dashboard && status_.state == MinerState::OtaUpdating) {
    go(S_Ota, now);
    return;
  }
  if (screen_ == S_Ota && status_.state != MinerState::OtaUpdating) {
    go(S_Dashboard, now);
    return;
  }
  if (screen_ == S_Connecting) {
    if (status_.state == MinerState::Mining || status_.state == MinerState::HeartbeatOk) {
      go(S_Dashboard, now);
    } else if (!connectFailed_ && (uint32_t)(now - screenSinceMs_) > kConnectTimeoutMs) {
      connectFailed_ = true;
      dirty_ = true;
    }
  }
}

void TouchUI::renderButtons(const char* const* labels, int n, int cols, int rows) {
  const Pal p = palette(c_->mono());
  for (int i = 0; i < n; i++) drawButton(*c_, gridBtn(i, cols, rows, c_->width(), c_->height()), labels[i], p, i == 0);
}

void TouchUI::renderKeyboard(const char* title) {
  const int W = c_->width(), H = c_->height();
  const Pal p = palette(c_->mono());
  const Rect f = kbField(W, H);
  c_->fillRect(f.x, f.y, f.w, f.h, p.btn);
  drawOutline(*c_, f.x, f.y, f.w, f.h, saveFailed_ ? p.err : p.accent);
  char shown[70];
  const bool plain = show_;
  if (textLen_ == 0) {
    c_->drawText((int16_t)(f.x + 4), (int16_t)(f.y + 10), title, 1, p.dim, p.btn);
  } else {
    int n = textLen_;
    // Keep the tail visible when the text is longer than the field.
    const int maxc = (f.w - 8) / 12;
    const char* src = text_;
    if (plain) {
      copyStr(shown, sizeof(shown), src);
    } else {
      for (int i = 0; i < n; i++) shown[i] = '*';
      shown[n] = 0;
    }
    const char* start = shown;
    if (n > maxc) start = shown + (n - maxc);
    c_->drawText((int16_t)(f.x + 4), (int16_t)(f.y + 6), start, 2, p.fg, p.btn);
  }
  for (int r = 0; r < 4; r++) {
    const char* row = kbRow(layer_, r);
    const int n = (int)strlen(row);
    for (int k = 0; k < n; k++) {
      const Rect kr = kbKey(r, k, n, W, H);
      c_->fillRect(kr.x, kr.y, kr.w, kr.h, p.btn);
      char one[2] = {row[k], 0};
      drawCentered(*c_, kr, one, 2, p.fg, p.btn);
    }
  }
  const char* labels[kFnCount] = {layer_ == kLayerUpper ? "abc" : "ABC", layer_ == kLayerSym ? "abc?" : "#+=", "Space",
                                  show_ ? "Hide" : "Show", "Del", "Esc", screen_ == S_MinerKey ? "Save" : "OK"};
  for (int f2 = 0; f2 < kFnCount; f2++) {
    const Rect kr = kbFn(f2, W, H);
    c_->fillRect(kr.x, kr.y, kr.w, kr.h, f2 == kFnOk ? p.accent : p.btn);
    drawCentered(*c_, kr, labels[f2], 1, f2 == kFnOk ? p.bg : p.fg, f2 == kFnOk ? p.accent : p.btn);
  }
}

void TouchUI::render() {
  const int W = c_->width(), H = c_->height();
  const Pal p = palette(c_->mono());
  char buf[72];
  c_->clear(p.bg);
  auto title = [&](const char* t) { c_->drawText(6, 4, t, 2, p.accent, p.bg); };

  switch (screen_) {
    case S_FirstBoot: {
      title("Welcome to FRY");
      c_->drawText(6, (int16_t)(H / 8 + 8), "Let's set up your miner.", 1, p.fg, p.bg);
      c_->drawText(6, (int16_t)(H / 8 + 22), "No WiFi or miner key stored yet.", 1, p.dim, p.bg);
      drawButton(*c_, gridBtn(kFirstContinue, 1, 3, W, H), "Continue", p, true);
      break;
    }
    case S_SetupChoice: {
      title("Setup");
      drawButton(*c_, gridBtn(kChoiceScreen, 1, 3, W, H), "Setup on Screen", p, true);
      drawButton(*c_, gridBtn(kChoiceApp, 1, 3, W, H), "Setup with App", p);
      break;
    }
    case S_WifiList: {
      title("Pick WiFi");
      if (scanning_) c_->drawText(6, (int16_t)(H / 8 + 12), "Scanning...", 1, p.dim, p.bg);
      for (int i = 0; i < kWifiRows && i < nSsid_; i++) {
        const Rect r = gridBtn(i, 1, 6, W, H);
        drawButton(*c_, r, ssids_[i], p);
        snprintf(buf, sizeof(buf), "%d", (int)rssis_[i]);
        c_->drawText((int16_t)(r.x + r.w - 30), (int16_t)(r.y + 3), buf, 1, p.dim, p.btn);
        if (secs_[i]) c_->drawText((int16_t)(r.x + 4), (int16_t)(r.y + 3), "*", 1, p.warn, p.btn);
      }
      if (nSsid_ == 0 && !scanning_) drawButton(*c_, gridBtn(0, 1, 6, W, H), "No networks - rescan", p);
      drawButton(*c_, gridBtn(kWifiBack, 1, 6, W, H), "Back", p);
      break;
    }
    case S_Keyboard:
      renderKeyboard("WiFi password");
      break;
    case S_MinerKey:
      renderKeyboard("Miner key");
      break;
    case S_Connecting: {
      MinerStatus ms = status_;
      ms.state = MinerState::WifiConnecting;
      if (selSsid_[0]) copyStr(ms.ssid, sizeof(ms.ssid), selSsid_);
      ScreenAnimator::drawInto(*c_, ms, animFrame_, 0, 0, (int16_t)W, (int16_t)(H - 40), true);
      if (connectFailed_) c_->drawText(6, (int16_t)(H - 52), "Connect failed - Cancel and retry", 1, p.err, p.bg);
      drawButton(*c_, backBtn(W, H), "Cancel", p);
      break;
    }
    case S_Dashboard: {
      title("FRY Miner");
      const char* ssid = status_.ssid[0] ? status_.ssid : snap_.ssid;
      int16_t y = (int16_t)(H / 8 + 8);
      snprintf(buf, sizeof(buf), "%s", ssid);
      c_->drawText(6, y, buf, 2, p.fg, p.bg);
      y += 22;
      c_->drawText(6, y, status_.ip[0] ? status_.ip : "no ip", 1, p.dim, p.bg);
      y += 12;
      snprintf(buf, sizeof(buf), "%s  %d dBm", stateName(status_.state), (int)status_.rssi);
      c_->drawText(6, y, buf, 1, p.fg, p.bg);
      y += 12;
      snprintf(buf, sizeof(buf), "fw %s  key ...%s", status_.fwVersion, snap_.hasMinerKey ? snap_.minerKeyLast4 : "none");
      c_->drawText(6, y, buf, 1, p.dim, p.bg);
      y += 12;
      snprintf(buf, sizeof(buf), "up %uh%02um", (unsigned)(status_.uptimeS / 3600), (unsigned)((status_.uptimeS / 60) % 60));
      c_->drawText(6, y, buf, 1, p.dim, p.bg);
      ScreenAnimator::drawInto(*c_, status_, animFrame_, (int16_t)(W - 100), (int16_t)(H / 8 + 6), 92, 90, false);
      drawButton(*c_, dashSettingsBtn(W, H), "Settings", p);
      break;
    }
    case S_Settings: {
      title("Settings");
      const char* labels[7] = {"Check update", "Dimmer", "Brighter", "Rotate", "Calibrate", "Factory reset", "Back"};
      for (int i = 0; i < 7; i++) drawButton(*c_, gridBtn(i, 2, 4, W, H), labels[i], p, i == kSetBack);
      snprintf(buf, sizeof(buf), "%u%%", (unsigned)bright_);
      c_->drawText((int16_t)(W - 50), 8, buf, 1, p.dim, p.bg);
      break;
    }
    case S_Ota: {
      ScreenAnimator::drawInto(*c_, status_, animFrame_, 0, 0, (int16_t)W, (int16_t)H, true);
      break;
    }
    case S_ConfirmReset: {
      title("Factory reset");
      c_->drawText(6, (int16_t)(H / 8 + 8), "Erases WiFi and wallet.", 1, p.fg, p.bg);
      c_->drawText(6, (int16_t)(H / 8 + 20), "Miner key is kept.", 1, p.dim, p.bg);
      drawButton(*c_, gridBtn(kResetConfirm, 1, 3, W, H), armed_ ? "Tap again to confirm" : "Reset", p, armed_);
      drawButton(*c_, gridBtn(kResetCancel, 1, 3, W, H), "Cancel", p);
      break;
    }
    case S_Calibrate: {
      int16_t tx = 0, ty = 0;
      if (calStep_ < 4) calTarget(calStep_, W, H, &tx, &ty);
      c_->fillRect((int16_t)(tx - 10), ty, 21, 1, p.accent);
      c_->fillRect(tx, (int16_t)(ty - 10), 1, 21, p.accent);
      drawOutline(*c_, (int16_t)(tx - 6), (int16_t)(ty - 6), 13, 13, p.fg);
      snprintf(buf, sizeof(buf), "Tap the cross (%d/4)", (int)calStep_ + 1);
      c_->drawText((int16_t)(W / 2 - 60), (int16_t)(H / 2), buf, 1, p.fg, p.bg);
      break;
    }
    case S_AppQr: {
      title("Setup with App");
      char payload[96];
      uint8_t m[512];
      const int top = H / 8 + 4;
      const int qs = H - top - 40;
      if (appQrPayload(status_, payload, sizeof(payload))) {
        const int n = qrEncode(payload, m, sizeof(m));
        if (n > 0) drawQr(*c_, m, n, 6, (int16_t)top, (int16_t)qs, (int16_t)qs);
      }
      const int16_t tx = (int16_t)(qs + 14);
      int16_t y = (int16_t)(top + 4);
      if (status_.apSsid[0]) {
        c_->drawText(tx, y, "Join WiFi:", 1, p.dim, p.bg);
        y += 12;
        c_->drawText(tx, y, status_.apSsid, 1, p.fg, p.bg);
        y += 16;
        c_->drawText(tx, y, "Then open:", 1, p.dim, p.bg);
        y += 12;
        c_->drawText(tx, y, status_.apIp, 1, p.fg, p.bg);
        y += 16;
      }
      c_->drawText(tx, y, "Board:", 1, p.dim, p.bg);
      y += 12;
      c_->drawText(tx, y, status_.boardName, 1, p.fg, p.bg);
      y += 16;
      c_->drawText(tx, y, "Scan with the", 1, p.dim, p.bg);
      y += 10;
      c_->drawText(tx, y, "FRY app", 1, p.dim, p.bg);
      drawButton(*c_, backBtn(W, H), "Back", p);
      break;
    }
    default:
      break;
  }
  c_->flush();
}

bool TouchUI::tick(uint32_t now) {
  if (!c_) return false;
  nowMs_ = now;
  if (!started_) {
    started_ = true;
    lastPollMs_ = now;
    lastFrameMs_ = now;
    screenSinceMs_ = now;
    dirty_ = true;
  }

  TouchPoint p = {0, 0, false};
  if (t_->read(p)) {
    if (p.pressed) {
      last_ = p;
      prevPressed_ = true;
    } else if (prevPressed_) {
      prevPressed_ = false;
      onTap(last_.x, last_.y, now);
    }
  }

  if (screen_ == S_WifiList && scanning_) {
    if ((uint32_t)(now - lastScanMs_) >= kScanPollMs) {
      lastScanMs_ = now;
      char tmp[6][33];
      int8_t r[6];
      bool sec[6];
      const int n = a_->scanResults(tmp, r, sec, 6);
      if (n >= 0) {
        nSsid_ = n > 6 ? 6 : n;
        for (int i = 0; i < nSsid_; i++) {
          copyStr(ssids_[i], sizeof(ssids_[i]), tmp[i]);
          rssis_[i] = r[i];
          secs_[i] = sec[i];
        }
        scanning_ = false;
        dirty_ = true;
      } else if ((uint32_t)(now - screenSinceMs_) > kScanTimeoutMs) {
        scanning_ = false;
        nSsid_ = 0;
        dirty_ = true;
      }
    }
  }

  if (armed_ && (uint32_t)(now - armedAtMs_) >= kArmMs) {
    armed_ = false;
    dirty_ = true;
  }

  if ((uint32_t)(now - lastPollMs_) >= kPollMs) {
    lastPollMs_ = now;
    poll(now);
  }

  if (animated(screen_) && (uint32_t)(now - lastFrameMs_) >= kFrameMs) {
    lastFrameMs_ = now;
    animFrame_++;
    dirty_ = true;
  }

  if (!dirty_) return false;
  dirty_ = false;
  render();
  return true;
}

}  // namespace ui
}  // namespace fry
