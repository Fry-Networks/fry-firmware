// Screen / touch UI interfaces and the two firmware hooks (weak no-ops in src/core/ui_hooks.cpp).
// Declarations only; no Arduino include (host-compilable). The class members beyond the SPEC'd
// public API (private state) are added by the UI implementation track.
#ifndef FRY_TOUCH_UI_H
#define FRY_TOUCH_UI_H

#include <stdint.h>

#include "fry_config_store.h"
#include "fry_display_hal.h"

extern "C" void fry_ui_setup(void);
extern "C" void fry_ui_loop(void);

namespace fry {
namespace ui {

enum class MinerState : uint8_t { Boot, SetupAP, WifiConnecting, Mining, HeartbeatOk, OtaUpdating, Error };

struct MinerStatus {
  MinerState state;
  char ssid[33];
  char ip[16];
  int8_t rssi;
  uint32_t uptimeS;
  bool lastHeartbeatOk;
  uint8_t otaPct;
  char otaStage[12];
  uint16_t errCode;
  char apSsid[33];
  char apIp[16];
  char boardName[24];
  char fwVersion[12];
  char minerKeyLast4[5];
};

struct StatusSource {  // device impl reads status_snapshot
  virtual void read(MinerStatus& out) = 0;
  virtual ~StatusSource() {}
};

struct TouchPoint {
  int16_t x, y;
  bool pressed;
};

struct TouchHal {  // raw->screen mapping inside, uses cal
  virtual bool read(TouchPoint& out) = 0;
  virtual ~TouchHal() {}
};

struct Actions {  // side effects the UI requests; device impl calls existing code, tests record
  virtual bool startWifiScan() = 0;
  virtual int scanResults(char ssids[][33], int8_t* rssi, bool* secured, int max) = 0;
  virtual void requestConnect() = 0;   // after saveWifi: same path as provisioning readyToConnect/restartToApply
  virtual void requestOtaCheck() = 0;  // fry_trigger_ota_now
  virtual void reboot() = 0;
  virtual void setBrightness(uint8_t pct) = 0;
  virtual void setRotation(uint8_t r) = 0;
  virtual ~Actions() {}
};

class ScreenAnimator {  // non-touch screens; non-blocking
 public:
  void begin(disp::Canvas& c, uint16_t fpsCap);
  bool tick(uint32_t nowMs, const MinerStatus& s);  // true if a frame was drawn
  uint32_t framesDrawn() const;
  // Draw one frame of `state` at animation step `frame` inside the given box (widget used by TouchUI too).
  static void drawInto(disp::Canvas& c, const MinerStatus& s, uint32_t frame, int16_t x, int16_t y, int16_t w,
                       int16_t h, bool full);
  uint32_t frameNo() const;

 private:  // state added by the implementation track (no heap after begin())
  disp::Canvas* c_ = nullptr;
  uint32_t intervalMs_ = 100;
  uint32_t lastDrawMs_ = 0;
  uint32_t frames_ = 0;
  uint32_t frameNo_ = 0;
  MinerState lastState_ = MinerState::Boot;
  bool drawnOnce_ = false;
};

enum Screen : uint8_t {
  S_FirstBoot = 0, S_SetupChoice, S_WifiList, S_Keyboard, S_Connecting, S_MinerKey, S_Dashboard, S_Settings, S_Ota,
  S_ConfirmReset, S_Calibrate, S_AppQr
};

class TouchUI {  // touch screens; superset: uses ScreenAnimator widgets
 public:
  void begin(disp::Canvas& c, TouchHal& t, cfg::Store& st, StatusSource& src, Actions& a);
  bool tick(uint32_t nowMs);  // non-blocking; returns true if redrawn
  uint8_t screenId() const;   // tests: FirstBoot, SetupChoice, WifiList, Keyboard, Connecting, MinerKey, Dashboard, Settings, Ota, ConfirmReset, Calibrate, AppQr

 private:  // state added by the implementation track (all fixed-size, no heap after begin())
  void go(uint8_t s, uint32_t now);
  void onTap(int16_t x, int16_t y, uint32_t now);
  void tapKeyboard(int16_t x, int16_t y, uint32_t now);
  void typeChar(char ch);
  void finishSetup(uint32_t now);
  void poll(uint32_t now);
  void render();
  void renderKeyboard(const char* title);
  void renderButtons(const char* const* labels, int n, int cols, int rows);

  disp::Canvas* c_ = nullptr;
  TouchHal* t_ = nullptr;
  cfg::Store* st_ = nullptr;
  StatusSource* src_ = nullptr;
  Actions* a_ = nullptr;
  uint8_t screen_ = S_FirstBoot;
  uint8_t returnScreen_ = S_Dashboard;
  bool dirty_ = true;
  bool started_ = false;
  bool prevPressed_ = false;
  TouchPoint last_ = {0, 0, false};
  uint32_t lastPollMs_ = 0, lastFrameMs_ = 0, screenSinceMs_ = 0, lastScanMs_ = 0, armedAtMs_ = 0, nowMs_ = 0;
  uint32_t lastGen_ = 0;
  uint32_t animFrame_ = 0;
  cfg::Snapshot snap_;
  MinerStatus status_;
  char ssids_[6][33];
  int8_t rssis_[6];
  bool secs_[6];
  int nSsid_ = 0;
  bool scanning_ = false;
  char selSsid_[33];
  bool selSecured_ = false;
  char text_[66];
  uint8_t textLen_ = 0;
  uint8_t layer_ = 0;  // 0 lower 1 upper 2 symbols
  bool show_ = false;
  char pass_[65];
  char key_[37];
  bool armed_ = false;
  uint8_t calStep_ = 0;
  int16_t cal_[8];
  bool connectFailed_ = false;
  bool saveFailed_ = false;
  uint8_t bright_ = 100, rot_ = 0;
};

}  // namespace ui
}  // namespace fry

#endif  // FRY_TOUCH_UI_H
