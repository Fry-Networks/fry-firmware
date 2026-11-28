// Host-side fakes for the UI native tests: in-memory config store, scripted touch panel, recording
// actions, scripted miner status, and a Rig that owns them and steps virtual time.
#ifndef FRY_TEST_UI_FAKES_H
#define FRY_TEST_UI_FAKES_H

#include <stdio.h>
#include <string.h>

#include "../../include/fry_touch_ui.h"
#include "../../lib/fry_ui/mem_canvas.h"
#include "../../lib/fry_ui/touch_layout.h"

namespace fry {
namespace uitest {

using ui::Actions;
using ui::MinerState;
using ui::MinerStatus;
using ui::StatusSource;
using ui::TouchHal;
using ui::TouchPoint;
using ui::TouchUI;

struct FakeStore : cfg::Store {
  char ssid[33] = "";
  char pass[65] = "";
  char key[37] = "";
  char wallet[65] = "";
  bool provDone = false;
  cfg::DisplayMode mode = cfg::DisplayMode::Auto;
  uint8_t preset = 0;
  int16_t cal[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  int calSaves = 0, resets = 0, wifiSaves = 0, keySaves = 0, loads = 0;
  bool failKeySave = false;

  bool load(cfg::Snapshot& o) override {
    loads++;
    memset(&o, 0, sizeof(o));
    strncpy(o.ssid, ssid, 32);
    o.hasWifi = ssid[0] != 0;
    o.hasPass = pass[0] != 0;
    o.hasMinerKey = key[0] != 0;
    if (key[0]) memcpy(o.minerKeyLast4, key + strlen(key) - 4, 4);
    strncpy(o.wallet, wallet, 64);
    o.provDone = provDone;
    o.displayMode = mode;
    o.boardPreset = preset;
    o.generation = cfg::snapshotGeneration(o);
    return true;
  }
  bool saveWifi(const char* s, const char* p) override {
    wifiSaves++;
    strncpy(ssid, s, 32);
    strncpy(pass, p, 64);
    provDone = true;
    return true;
  }
  bool saveMinerKey(const char* k) override {
    if (failKeySave || !cfg::validMinerKey(k)) return false;
    keySaves++;
    strncpy(key, k, 36);
    return true;
  }
  bool saveWallet(const char* w) override {
    strncpy(wallet, w, 64);
    return true;
  }
  bool saveDisplayMode(cfg::DisplayMode m, uint8_t p) override {
    mode = m;
    preset = p;
    return true;
  }
  bool saveTouchCal(const int16_t c[8]) override {
    calSaves++;
    memcpy(cal, c, sizeof(cal));
    return true;
  }
  bool loadTouchCal(int16_t c[8]) override {
    memcpy(c, cal, sizeof(cal));
    return true;
  }
  bool factoryReset() override {
    resets++;
    ssid[0] = pass[0] = wallet[0] = 0;
    provDone = false;  // identity (miner key) is preserved, like fry_config::factoryReset
    return true;
  }
  // What the phone app / captive write does: lands in the store without any on-board UI.
  void externalWrite(const char* s, const char* p, const char* k) {
    strncpy(ssid, s, 32);
    strncpy(pass, p, 64);
    strncpy(key, k, 36);
    provDone = true;
  }
};

struct FakeTouch : TouchHal {
  TouchPoint q[64];
  int head = 0, tail = 0;
  TouchPoint cur = {0, 0, false};
  void push(int16_t x, int16_t y, bool p) {
    q[tail++ % 64] = TouchPoint{x, y, p};
  }
  void tap(int16_t x, int16_t y) {
    push(x, y, true);
    push(x, y, false);
  }
  bool read(TouchPoint& o) override {
    if (head != tail) cur = q[head++ % 64];
    o = cur;
    return true;
  }
};

struct FakeActions : Actions {
  int scans = 0, connects = 0, otaChecks = 0, reboots = 0;
  uint8_t brightness = 100, rotation = 0;
  int scanPendingPolls = 2;  // scanResults reports -1 (in progress) this many times
  int nAp = 0;
  char ap[8][33];
  int8_t apRssi[8];
  bool apSec[8];
  int polls = 0;
  void addAp(const char* s, int8_t r, bool sec) {
    strncpy(ap[nAp], s, 32);
    ap[nAp][32] = 0;
    apRssi[nAp] = r;
    apSec[nAp] = sec;
    nAp++;
  }
  bool startWifiScan() override {
    scans++;
    polls = 0;
    return true;
  }
  int scanResults(char ssids[][33], int8_t* rssi, bool* secured, int max) override {
    if (polls++ < scanPendingPolls) return -1;
    int n = nAp < max ? nAp : max;
    for (int i = 0; i < n; i++) {
      strncpy(ssids[i], ap[i], 33);
      rssi[i] = apRssi[i];
      secured[i] = apSec[i];
    }
    return n;
  }
  void requestConnect() override { connects++; }
  void requestOtaCheck() override { otaChecks++; }
  void reboot() override { reboots++; }
  void setBrightness(uint8_t p) override { brightness = p; }
  void setRotation(uint8_t r) override { rotation = r; }
};

struct FakeStatus : StatusSource {
  MinerStatus s;
  FakeStatus() {
    memset(&s, 0, sizeof(s));
    s.state = MinerState::SetupAP;
    strcpy(s.apSsid, "FRY-Setup-A1B2");
    strcpy(s.apIp, "192.168.4.1");
    strcpy(s.boardName, "FRY-ESP32-A1B2C3");
    strcpy(s.fwVersion, "0.4.31");
    s.rssi = -55;
  }
  void read(MinerStatus& o) override { o = s; }
};

inline bool hasLine(const disp::MemCanvas& c, const char* line) {
  const char* t = c.text();
  const size_t n = strlen(line);
  while (*t) {
    const char* e = strchr(t, '\n');
    const size_t len = e ? (size_t)(e - t) : strlen(t);
    if (len == n && strncmp(t, line, n) == 0) return true;
    if (!e) break;
    t = e + 1;
  }
  return false;
}

struct Rig {
  disp::MemCanvas canvas;
  FakeTouch touch;
  FakeStore store;
  FakeStatus status;
  FakeActions act;
  TouchUI ui;
  uint32_t now = 1000;
  int W, H;
  explicit Rig(uint16_t w = 320, uint16_t h = 240) : canvas(w, h, false), W(w), H(h) {}
  void begin() { ui.begin(canvas, touch, store, status, act); }
  void step(int ticks = 1, uint32_t dtMs = 20) {
    for (int i = 0; i < ticks; i++) {
      now += dtMs;
      ui.tick(now);
    }
  }
  void tapXY(int16_t x, int16_t y) {
    touch.tap(x, y);
    step(3);
  }
  void tapRect(const ui::Rect& r) { tapXY(r.cx(), r.cy()); }
  void waitMs(uint32_t ms) { step((int)(ms / 20) + 1); }
  // Type a string on the on-screen keyboard, switching layers as needed.
  bool typeString(const char* s) {
    for (const char* p = s; *p; p++) {
      if (!typeChar(*p)) return false;
    }
    return true;
  }
  bool typeChar(char ch) {
    for (int attempt = 0; attempt < 3; attempt++) {
      for (int layer = 0; layer < 3; layer++) {
        for (int row = 0; row < 4; row++) {
          const char* r = ui::kbRow(layer, row);
          const char* f = strchr(r, ch);
          if (!f) continue;
          if (!layerActive(layer, row, r[0])) continue;
          tapRect(ui::kbKey(row, (int)(f - r), (int)strlen(r), W, H));
          return true;
        }
      }
      // wanted layer not showing: switch toward it
      if (strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZ", ch)) {
        tapRect(ui::kbFn(ui::kFnShift, W, H));
      } else if (strchr("abcdefghijklmnopqrstuvwxyz", ch)) {
        if (hasLine(canvas, "!")) tapRect(ui::kbFn(ui::kFnLayer, W, H));
        else tapRect(ui::kbFn(ui::kFnShift, W, H));
      } else {
        tapRect(ui::kbFn(ui::kFnLayer, W, H));
      }
    }
    return false;
  }
  // Is the keyboard currently showing this layer? Probe by the row's first-key label.
  bool layerActive(int layer, int row, char first) {
    (void)layer;
    char one[2] = {first, 0};
    if (row == 0) return true;  // digits are on every layer
    return hasLine(canvas, one);
  }
};

}  // namespace uitest
}  // namespace fry

#endif  // FRY_TEST_UI_FAKES_H
