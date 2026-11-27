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
  // + private state, no heap after begin() (added by the implementation)
};

class TouchUI {  // touch screens; superset: uses ScreenAnimator widgets
 public:
  void begin(disp::Canvas& c, TouchHal& t, cfg::Store& st, StatusSource& src, Actions& a);
  bool tick(uint32_t nowMs);  // non-blocking; returns true if redrawn
  uint8_t screenId() const;   // tests: FirstBoot, SetupChoice, WifiList, Keyboard, Connecting, MinerKey, Dashboard, Settings, Ota, ConfirmReset, Calibrate, AppQr
};

}  // namespace ui
}  // namespace fry

#endif  // FRY_TOUCH_UI_H
