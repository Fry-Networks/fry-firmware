// Strong fry_ui_setup()/fry_ui_loop(): boot-time display probe + resolve, then either the touch UI,
// the screen animation, or nothing. Compiled to an empty unit unless -DFRY_HAS_DISPLAY=1.
//
// NONE mode (nothing found, or display_mode=none) leaves s_mode at FRY_DISP_NONE: fry_ui_loop() is a
// single compare and return - no bus access, no timers, nothing that can hang or touch the WDT.
#include "../../include/fry_touch_ui.h"

#if defined(FRY_HAS_DISPLAY)

#include <Arduino.h>
#include <string.h>

#if !defined(FRY_UI_BARE)
#if defined(ARDUINO_ARCH_ESP8266)
#include <ESP8266WiFi.h>
#include <Updater.h>
#elif defined(FRY_BOARDS_PORT)
#include <WiFi.h>
#if defined(FRY_BOARD_PICO)
#include <Updater.h>
#else
#include <Update.h>
#endif
#include "../../include/fry_board_hal.h"
#else
#include <Update.h>
#include <WiFi.h>
#endif

#include "../core/flash_print.h"
#include "../core/fry_config.h"
#include "../core/kv_store.h"
#include "../core/miner_key.h"
#include "../core/ota_client.h"
#include "../core/provisioning_transport.h"
#include "../core/trigger_hooks.h"
#include "../core/wifi_station.h"
#else
// FRY_UI_BARE: display bring-up image for boards whose firmware core is not ported (rpipicow-oled until
// the boards track lands its HAL). Same probe / resolve / animator, status is a looping demo.
#define FRY_PRINTF(fmt, ...) Serial.printf(fmt, ##__VA_ARGS__)
#define FRY_PRINTLN(text) Serial.println(text)
#endif
#include "../display/display_dev.h"

#if defined(ARDUINO_ARCH_ESP8266)
#define WIFI_AUTH_OPEN_VALUE ENC_TYPE_NONE
#elif defined(FRY_BOARDS_PORT)
#define WIFI_AUTH_OPEN_VALUE 0
#else
#define WIFI_AUTH_OPEN_VALUE WIFI_AUTH_OPEN
#endif
// fry::cfg::deviceStore() has exactly ONE owner per env: this file on the ESP envs, src/hal/config_store_boards.cpp on the board
// ports (FRY_BOARDS_PORT; it guards its definition with FRY_UI_PROVIDES_DEVICE_STORE, which an env sets when it wants this
// file's store instead). The bring-up image (FRY_UI_BARE) has no Store at all.
#if !defined(FRY_UI_BARE) && (!defined(FRY_BOARDS_PORT) || defined(FRY_UI_PROVIDES_DEVICE_STORE))
#define FRY_UI_OWNS_DEVICE_STORE 1
#endif
#if defined(FRY_BOARDS_PORT)
#define FRY_UI_RESTART() fry::board::restart()
#else
#define FRY_UI_RESTART() ESP.restart()
#endif
#ifndef FRY_FIRMWARE_VERSION
#define FRY_FIRMWARE_VERSION "0"
#endif
#ifndef FRY_UI_PRESET
#define FRY_UI_PRESET 0  // compile-time default board preset; 0 = autodetect
#endif

namespace {

using namespace fry;

// ---- persisted display settings (namespace "fry_ui": NEW keys only) -----------------------------
struct UiPrefs {
  cfg::DisplayMode mode = cfg::DisplayMode::Auto;
  uint8_t preset = 0;
};

#if defined(FRY_UI_BARE)
UiPrefs loadPrefs() { return UiPrefs(); }

class DevStatus : public ui::StatusSource {
 public:
  void read(ui::MinerStatus& o) override {
    memset(&o, 0, sizeof(o));
    const uint32_t s = millis() / 1000;
    o.state = (ui::MinerState)((s / 4) % 7);
    o.uptimeS = s;
    strcpy(o.ssid, "demo-net");
    strcpy(o.ip, "10.0.0.2");
    strcpy(o.apSsid, "FRY-Setup-demo");
    strcpy(o.apIp, "192.168.4.1");
    strcpy(o.boardName, "FRY-RP2040-demo");
    strcpy(o.fwVersion, FRY_FIRMWARE_VERSION);
    strcpy(o.otaStage, "flash");
    o.otaPct = (uint8_t)((s * 7) % 100);
    o.rssi = -58;
    o.errCode = 3;
  }
};
DevStatus s_status;
#else
UiPrefs loadPrefs() {
  UiPrefs p;
  KvStore kv;
  kv.begin("fry_ui", true);
  const uint8_t m = kv.getUChar("dispMode", 0);
  p.mode = m <= 3 ? (cfg::DisplayMode)m : cfg::DisplayMode::Auto;
  p.preset = kv.getUChar("dispPreset", 0);
  kv.end();
  return p;
}

#if defined(FRY_UI_OWNS_DEVICE_STORE)
class DevStore : public cfg::Store {
 public:
  bool load(cfg::Snapshot& o) override {
    memset(&o, 0, sizeof(o));
    char pass[65] = {0};
    const bool has = fry_config::getWifi(o.ssid, sizeof(o.ssid), pass, sizeof(pass));
    o.hasWifi = has && o.ssid[0];
    o.hasPass = pass[0] != 0;
    memset(pass, 0, sizeof(pass));
    char key[40] = {0};
    o.hasMinerKey = fry_config::getMinerKey(key, sizeof(key)) && key[0];
    const size_t kl = strlen(key);
    if (o.hasMinerKey && kl >= 4) memcpy(o.minerKeyLast4, key + kl - 4, 4);
    memset(key, 0, sizeof(key));
    String w = fry_config::getWallet();
    strncpy(o.wallet, w.c_str(), sizeof(o.wallet) - 1);
    o.provDone = fry_config::hasProvDone();
    const UiPrefs p = loadPrefs();
    o.displayMode = p.mode;
    o.boardPreset = p.preset;
    o.generation = cfg::snapshotGeneration(o);
    return true;
  }
  bool saveWifi(const char* ssid, const char* pass) override {
    // Same two writes as provisioning commitWifiOnlyCredentials; the board restarts to apply them.
    fry_config::setWifi(ssid, pass ? pass : "");
    fry_config::setProvDone();
    return fry_config::hasWifi();
  }
  bool saveMinerKey(const char* key) override {
    if (!cfg::validMinerKey(key)) return false;
    bool changed = false;
    // Typed on the device itself: physical access, the same trust as the USB (Improv 0xF0) write.
    const KeyWriteVerdict v = fry_identity::setOwnerKey(key, KeyTransport::Usb, &changed);
    return v == KeyWriteVerdict::Accept;
  }
  bool saveWallet(const char* wallet) override {
    fry_config::setWallet(wallet);
    return true;
  }
  bool saveDisplayMode(cfg::DisplayMode m, uint8_t preset) override {
    KvStore kv;
    if (!kv.begin("fry_ui", false)) return false;
    kv.putUChar("dispMode", (uint8_t)m);
    kv.putUChar("dispPreset", preset);
    kv.end();
    return true;
  }
  bool saveTouchCal(const int16_t cal[8]) override {
    KvStore kv;
    if (!kv.begin("fry_ui", false)) return false;
    const bool ok = kv.putBytes("tcal", cal, 16) == 16;
    kv.end();
    fry_dispdev::driverApplyCal(cal);
    return ok;
  }
  bool loadTouchCal(int16_t cal[8]) override {
    KvStore kv;
    kv.begin("fry_ui", true);
    const bool ok = kv.getBytesLength("tcal") == 16 && kv.getBytes("tcal", cal, 16) == 16;
    kv.end();
    if (!ok) memset(cal, 0, 16);
    return ok;
  }
  bool factoryReset() override {
    fry_config::factoryReset();
    return true;
  }
};

#endif  // FRY_UI_OWNS_DEVICE_STORE

class DevStatus : public ui::StatusSource {
 public:
  void read(ui::MinerStatus& o) override {
    memset(&o, 0, sizeof(o));
    const uint32_t up = millis() / 1000;
    o.uptimeS = up;
    const bool up_ = fry_wifi::isConnected();
    if (up_) {
      strncpy(o.ssid, WiFi.SSID().c_str(), sizeof(o.ssid) - 1);
      strncpy(o.ip, fry_wifi::localIp().c_str(), sizeof(o.ip) - 1);
      o.rssi = fry_wifi::rssi();
    } else {
      char pass[8];
      fry_config::getWifi(o.ssid, sizeof(o.ssid), pass, sizeof(pass));  // truncated read: pass is never shown
      memset(pass, 0, sizeof(pass));
    }
    const int32_t hb = fry_ota::heartbeatAgeS();
    o.lastHeartbeatOk = hb >= 0;
    char key[40] = {0};
    if (fry_config::getMinerKey(key, sizeof(key)) && strlen(key) >= 4) memcpy(o.minerKeyLast4, key + strlen(key) - 4, 4);
    memset(key, 0, sizeof(key));
    fry_identity::getDeviceName(o.boardName, sizeof(o.boardName));
    strncpy(o.fwVersion, FRY_FIRMWARE_VERSION, sizeof(o.fwVersion) - 1);
#if defined(ARDUINO_ARCH_ESP8266)
    if (WiFi.getMode() & WIFI_AP) {
      strncpy(o.apSsid, WiFi.softAPSSID().c_str(), sizeof(o.apSsid) - 1);
      strncpy(o.apIp, WiFi.softAPIP().toString().c_str(), sizeof(o.apIp) - 1);
    }
#endif
    if (Update.isRunning()) {
      o.state = ui::MinerState::OtaUpdating;
      const uint32_t sz = Update.size();
      o.otaPct = sz ? (uint8_t)((uint64_t)Update.progress() * 100 / sz) : 0;
      strncpy(o.otaStage, "flash", sizeof(o.otaStage) - 1);
    } else if (fry_provisioning::state() == ProvState::Error) {
      o.state = ui::MinerState::Error;
      o.errCode = (uint16_t)fry_provisioning::lastError();
    } else if (up_) {
      o.state = (hb >= 0 && hb <= 3) ? ui::MinerState::HeartbeatOk : ui::MinerState::Mining;
    } else if (up < 3) {
      o.state = ui::MinerState::Boot;
    } else if (fry_config::hasWifi()) {
      o.state = ui::MinerState::WifiConnecting;
    } else {
      o.state = ui::MinerState::SetupAP;
    }
  }
};

class DevActions : public ui::Actions {
 public:
#if defined(FRY_BOARDS_PORT)
  // Board ports (Pico W / BK7231N) are screen-only: no touch setup UI, so no on-device Wi-Fi scan. Provisioning is the SoftAP portal / Improv.
  bool startWifiScan() override { return false; }
  int scanResults(char[][33], int8_t*, bool*, int) override { return 0; }
#else
  bool startWifiScan() override {
    if (WiFi.getMode() == WIFI_OFF) WiFi.mode(WIFI_STA);
    WiFi.scanDelete();
    const int r = WiFi.scanNetworks(true /* async */, false);
    return r == WIFI_SCAN_RUNNING || r >= 0;
  }
  int scanResults(char ssids[][33], int8_t* rssi, bool* secured, int max) override {
    const int n = WiFi.scanComplete();
    if (n == WIFI_SCAN_RUNNING) return -1;
    if (n < 0) return 0;  // failed: an empty list the user can rescan from
    int out = 0;
    for (int i = 0; i < n && out < max; i++) {
      String s = WiFi.SSID(i);
      if (s.length() == 0 || s.length() > 32) continue;
      bool dup = false;
      for (int k = 0; k < out; k++) dup = dup || strcmp(ssids[k], s.c_str()) == 0;
      if (dup) continue;
      strncpy(ssids[out], s.c_str(), 32);
      ssids[out][32] = 0;
      rssi[out] = (int8_t)WiFi.RSSI(i);
      secured[out] = WiFi.encryptionType(i) != WIFI_AUTH_OPEN_VALUE;
      out++;
    }
    WiFi.scanDelete();
    return out;
  }
#endif  // FRY_BOARDS_PORT
  void requestConnect() override { scheduleRestart(2000); }
  void requestOtaCheck() override { fry_trigger_ota_now(); }
  void reboot() override { scheduleRestart(1500); }
  void setBrightness(uint8_t pct) override { fry_dispdev::driverSetBrightness(pct); }
  void setRotation(uint8_t r) override { fry_dispdev::driverSetRotation(r); }

  void serviceRestart() {
    if (restartAt_ && (int32_t)(millis() - restartAt_) >= 0) {
      FRY_PRINTLN("[ui] planned restart to apply new settings");
      fry_ota::notePlannedRestart();  // not a failure: a pending image must not take a strike
      Serial.flush();
      FRY_UI_RESTART();
    }
  }

 private:
  void scheduleRestart(uint32_t inMs) {
    restartAt_ = millis() + inMs;
    if (restartAt_ == 0) restartAt_ = 1;
  }
  uint32_t restartAt_ = 0;
};

#if defined(FRY_UI_OWNS_DEVICE_STORE)
DevStore s_store;
#endif
DevStatus s_status;
DevActions s_actions;
#endif  // !FRY_UI_BARE
ui::TouchUI* s_touchUi = nullptr;
ui::ScreenAnimator* s_anim = nullptr;
disp::Mode s_mode = disp::FRY_DISP_NONE;
uint32_t s_lastTickMs = 0;
uint32_t s_lastStatusMs = 0;
ui::MinerStatus s_cached;

void logLine(const char* line) { FRY_PRINTF("%s\n", line); }

}  // namespace

#if defined(FRY_UI_OWNS_DEVICE_STORE)
namespace fry {
namespace cfg {
Store& deviceStore() { return s_store; }
}  // namespace cfg
}  // namespace fry
#endif

extern "C" void fry_ui_setup(void) {
  const UiPrefs prefs = loadPrefs();
  if (prefs.mode == cfg::DisplayMode::None) {
    FRY_PRINTLN("[ui] mode=NONE (display_mode=none) - no probe, no polling");
    return;
  }

  fry_dispdev::Bus bus;
  disp::Info probed;
  memset(&probed, 0, sizeof(probed));
  uint8_t preset = prefs.preset ? prefs.preset : (uint8_t)FRY_UI_PRESET;
#if !defined(FRY_UI_BARE)
  if (!prefs.preset && FRY_UI_PRESET) {
    // A preset image (esp32-cyd-touch ...) remembers its board in the config store, so an OTA to the unified default image
    // (which has no compiled-in preset) keeps probing this board's pins and the UI survives the update.
    KvStore kv;
    if (kv.begin("fry_ui", false)) {
      kv.putUChar("dispPreset", (uint8_t)FRY_UI_PRESET);
      kv.end();
    }
  }
#endif
  disp::BoardPins pins;
  bool havePins = false;

  const uint32_t t0 = millis();
  // Fleet safety (lib/fry_ui bootProbe + probeScope): with no board preset and display_mode=Auto only the bounded I2C probe on
  // the chip's default I2C pins runs. SPI / TFT / XPT2046 pins are driven only for a preset (config store or compiled in) or an
  // explicit display_mode=screen/touch.
#if defined(CONFIG_IDF_TARGET_ESP32S3)
  static const uint8_t kCands[] = {disp::PRESET_ESP32S3_CAPTOUCH, disp::PRESET_ESP32S3_TFT, disp::PRESET_ESP32S3_OLED};
  const uint8_t defaultI2c = disp::PRESET_ESP32S3_OLED;
#elif defined(ARDUINO_ARCH_ESP32)
  static const uint8_t kCands[] = {disp::PRESET_ESP32_OLED, disp::PRESET_ESP32_CYD};
  const uint8_t defaultI2c = disp::PRESET_ESP32_OLED;
#else
  static const uint8_t kCands[] = {disp::PRESET_ESP8266_OLED};
  const uint8_t defaultI2c = disp::PRESET_ESP8266_OLED;
#endif
  struct Hook : disp::BusHook {
    fry_dispdev::Bus* b;
    void select(uint8_t pr, const disp::BoardPins& p) override {
      b->setSpi(p.spiSck, p.spiMosi, p.spiMiso);
      b->setXpt(fry_dispdev::devPinsFor(pr));
    }
    void release(const disp::BoardPins& p) override { b->release(p); }
  } hook;
  hook.b = &bus;
  const uint8_t chosen = disp::bootProbe(preset, (uint8_t)prefs.mode, defaultI2c, kCands, sizeof(kCands) / sizeof(kCands[0]), bus,
                                         &hook, 400, probed, pins, havePins);
  if (chosen) preset = chosen;

  char line[200];
  FRY_PRINTF("[ui] probe preset=%s panel=%s id=0x%06X touch=%s taddr=0x%02X ms=%u\n", disp::presetName(preset),
             disp::panelName(probed.panel), (unsigned)(probed.panelId & 0xFFFFFFu), disp::touchName(probed.touch),
             (unsigned)probed.touchAddr, (unsigned)(millis() - t0));

  const disp::Info res = disp::resolve(probed, (uint8_t)prefs.mode, preset);
  if (!havePins) {
    disp::BoardPins none;
    memset(&none, 0xFF, sizeof(none));  // every pin -1
    none.forbidden = nullptr;
    none.nForbidden = 0;
    pins = none;
  }
  if (res.mode == disp::FRY_DISP_NONE) {
    disp::formatBootLine(line, sizeof(line), res, "-", pins);
    logLine(line);
    FRY_PRINTLN("[ui] no display - UI off, zero polling");
    if (havePins) bus.release(pins);
    return;
  }

  bus.release(pins);
  if (!fry_dispdev::driverInit(res, pins, preset)) {
    FRY_PRINTLN("[ui] display driver init failed - UI off");
    return;
  }
  disp::formatBootLine(line, sizeof(line), res, fry_dispdev::driverName(), pins);
  logLine(line);

  disp::Canvas* canvas = fry_dispdev::driverCanvas();
  if (res.mode == disp::FRY_DISP_TOUCHSCREEN && fry_dispdev::driverTouch()) {
#if !defined(FRY_UI_BARE)
    int16_t cal[8];
    if (cfg::deviceStore().loadTouchCal(cal)) fry_dispdev::driverApplyCal(cal);
    s_touchUi = new ui::TouchUI();
    s_touchUi->begin(*canvas, *fry_dispdev::driverTouch(), cfg::deviceStore(), s_status, s_actions);
    s_mode = disp::FRY_DISP_TOUCHSCREEN;
    FRY_PRINTF("[ui] TouchUI init screen=%u controller=%s\n", (unsigned)s_touchUi->screenId(), disp::touchName(res.touch));
#endif
  } else {
    s_anim = new ui::ScreenAnimator();
    s_anim->begin(*canvas, 15);
    s_mode = disp::FRY_DISP_SCREEN_ONLY;
    FRY_PRINTLN("[ui] ScreenAnimator init");
  }
}

extern "C" void fry_ui_loop(void) {
  if (s_mode == disp::FRY_DISP_NONE) return;  // zero polling
#if !defined(FRY_UI_BARE)
  s_actions.serviceRestart();
#endif
  const uint32_t now = millis();
  if ((uint32_t)(now - s_lastTickMs) < disp::loopIntervalMs(s_mode)) return;
  s_lastTickMs = now;
  if (s_touchUi) {
    s_touchUi->tick(now);
  } else if (s_anim) {
    if (s_lastStatusMs == 0 || (uint32_t)(now - s_lastStatusMs) >= 500) {
      s_lastStatusMs = now ? now : 1;
      s_status.read(s_cached);
    }
    s_anim->tick(now, s_cached);
  }
}

#endif  // FRY_HAS_DISPLAY
