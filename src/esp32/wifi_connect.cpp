// ESP32/S3/C3 WiFi station connect. The stock arduino-esp32 WiFi stack is far more robust than
// ESP8266's, so this does not need the scan-then-match-by-BSSID / forced-PHY workarounds in
// src/esp8266/wifi_connect.cpp — just a disconnect-reason-aware wait loop and a reconnect watchdog.
#include "../core/wifi_station.h"
#include "bench_fault.h"
#include "wifi_reason.h"
#include "wifi_tx_fallback.h"

#include <WiFi.h>

#include <cstring>

namespace fry_wifi {

namespace {

void (*s_waitHook)() = nullptr;
volatile bool s_l2Associated = false;
volatile uint8_t s_lastDiscReason = 0;
bool s_everConnected = false;
volatile uint8_t s_lastChannel = 0;
volatile uint8_t s_lastAuthMode = 0;
#if defined(CONFIG_IDF_TARGET_ESP32C3)
// Set once a join only succeeded at reduced TX power: RAM only, this boot only, kept across reconnects.
bool s_lowTx = false;
// Set when the low-TX retry has been made, joined or not: it is never repeated this boot (RAM only).
bool s_lowTxTried = false;
// True while our own disconnect() settles, so its ASSOC_LEAVE (8) event cannot become the reported reason.
volatile bool s_ignoreLeave = false;
#endif

void onWifiEvent(WiFiEvent_t event, WiFiEventInfo_t info) {
  if (event == ARDUINO_EVENT_WIFI_STA_CONNECTED) {
    s_l2Associated = true;
    s_lastChannel = info.wifi_sta_connected.channel;
    s_lastAuthMode = static_cast<uint8_t>(info.wifi_sta_connected.authmode);
  } else if (event == ARDUINO_EVENT_WIFI_STA_DISCONNECTED) {
#if defined(CONFIG_IDF_TARGET_ESP32C3)
    if (s_ignoreLeave && info.wifi_sta_disconnected.reason == 8) return;
#endif
    s_lastDiscReason = info.wifi_sta_disconnected.reason;
  }
}

// One WiFi.begin + wait loop. True once the station is connected.
bool joinOnce(const char* ssid, const char* pass, uint32_t timeoutMs) {
  s_l2Associated = false;
  s_lastDiscReason = 0;
  WiFi.begin(ssid, (pass && strlen(pass)) ? pass : nullptr);
  unsigned long start = millis();
  while (millis() - start < timeoutMs) {
    if (WiFi.status() == WL_CONNECTED) return true;
    if (s_waitHook) s_waitHook();
    delay(250);
  }
  return false;
}

}  // namespace

void setWaitHook(void (*hook)()) { s_waitHook = hook; }

bool connect(const char* ssid, const char* pass, uint32_t timeoutMs, fry::ProvErr* errOut) {
  static bool eventRegistered = false;
  if (!eventRegistered) {
    WiFi.onEvent(onWifiEvent);
    eventRegistered = true;
  }

#if defined(FRY_TEST_FAULT) && FRY_TEST_FAULT == 4
  // Test channel only (tools/fry_prebuild.py defines FRY_TEST_FAULT for *_test envs and refuses everything
  // else): the first two joins after a boot fail as if the network were down, so the background retry of
  // the stored network (lib/fry_core/wifi_retry.h) can be watched on hardware.
  static int s_faultJoins = 0;
  if (s_faultJoins < 2) {
    s_faultJoins++;
    Serial.printf("[fault] FRY_TEST_FAULT=4 - join %d refused\n", s_faultJoins);
    delay(5000);
    if (errOut) *errOut = fry::ProvErr::BadSsid;
    return false;
  }
#endif
  WiFi.persistent(false);  // don't wear the flash — we persist credentials ourselves
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true);
  delay(100);
#if defined(CONFIG_IDF_TARGET_ESP32C3)
  if (s_lowTx) {  // this boot needed it once: keep it (setTxPower needs the radio started)
    WiFi.mode(WIFI_STA);
    WiFi.setTxPower(WIFI_POWER_8_5dBm);
  }
#endif
  bool joined = joinOnce(ssid, pass, timeoutMs);

#if defined(CONFIG_IDF_TARGET_ESP32C3)
  if (!joined && fry::shouldRetryLowTx(s_lastDiscReason, s_l2Associated, s_lowTxTried)) {
    // Associated but the handshake failed: retry once at reduced TX power (bounded, no loop).
    Serial.printf("wifi: join retry at reduced tx power reason=%u\n", (unsigned)s_lastDiscReason);
    s_lowTxTried = true;
    const wifi_power_t prevTx = WiFi.getTxPower();
    s_ignoreLeave = true;
    WiFi.disconnect(true);
    delay(300);
    s_ignoreLeave = false;
    WiFi.mode(WIFI_STA);
    WiFi.setTxPower(WIFI_POWER_8_5dBm);
    joined = joinOnce(ssid, pass, fry::lowTxRetryTimeoutMs(timeoutMs));
    if (joined) {
      s_lowTx = true;
      Serial.println("wifi: joined at reduced tx power (this boot only)");
    } else {
      WiFi.setTxPower(prevTx);
    }
  }
#endif

  if (joined) {
    s_everConnected = true;
    Serial.printf("wifi connected ip=%s rssi=%d tx=%d\n", WiFi.localIP().toString().c_str(), WiFi.RSSI(),
                  (int)WiFi.getTxPower());
    return true;
  }

  if (errOut) {
    if (s_l2Associated) {
      *errOut = fry::ProvErr::NoIp;  // associated but DHCP never completed
    } else {
      // 201 NO_AP_FOUND -> BadSsid; auth/assoc failures and an undiagnosed 0 -> WifiAuth.
      *errOut = fry::classifyWifiDisconnect(s_lastDiscReason);
    }
  }
  Serial.printf("wifi connect failed reason=%u associated=%d\n", s_lastDiscReason, (int)s_l2Associated);
  Serial.printf("wifi diag rssi=%d channel=%u auth=%u tx=%d\n", WiFi.RSSI(), (unsigned)s_lastChannel,
                (unsigned)s_lastAuthMode, (int)WiFi.getTxPower());
  return false;
}

bool isConnected() { return WiFi.status() == WL_CONNECTED; }
String localIp() { return WiFi.localIP().toString(); }
int8_t rssi() { return static_cast<int8_t>(WiFi.RSSI()); }

void maintain() {
  static unsigned long s_lastCheck = 0;
  static unsigned long s_lost = 0;
  unsigned long now = millis();
  if (now - s_lastCheck < 5000) return;
  s_lastCheck = now;

  if (WiFi.status() == WL_CONNECTED) {
    s_lost = 0;
    return;
  }
  if (!s_everConnected) return;  // never connected yet — the boot sequence owns the first attempt
  if (!s_lost) {
    s_lost = now;
    Serial.println("wifi: link DOWN - recovering");
  }
  if (now - s_lost > 20000) {
    WiFi.reconnect();
    s_lost = now;  // retry every ~20s, matching the sensmos-proven cadence
  }
}

}  // namespace fry_wifi
