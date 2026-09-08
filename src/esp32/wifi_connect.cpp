// ESP32/S3/C3 WiFi station connect. The stock arduino-esp32 WiFi stack is far more robust than
// ESP8266's, so this does not need the scan-then-match-by-BSSID / forced-PHY workarounds in
// src/esp8266/wifi_connect.cpp — just a disconnect-reason-aware wait loop and a reconnect watchdog.
#include "../core/wifi_station.h"

#include <WiFi.h>

#include <cstring>

namespace fry_wifi {

namespace {

volatile bool s_l2Associated = false;
volatile uint8_t s_lastDiscReason = 0;
bool s_everConnected = false;

void onWifiEvent(WiFiEvent_t event, WiFiEventInfo_t info) {
  if (event == ARDUINO_EVENT_WIFI_STA_CONNECTED) {
    s_l2Associated = true;
  } else if (event == ARDUINO_EVENT_WIFI_STA_DISCONNECTED) {
    s_lastDiscReason = info.wifi_sta_disconnected.reason;
  }
}

bool isAuthFailureReason(uint8_t reason) {
  // WIFI_REASON_* from esp_wifi_types.h: 2 AUTH_EXPIRE, 15 4WAY_HANDSHAKE_TIMEOUT,
  // 201 NO_AP_FOUND, 202 AUTH_FAIL, 203 ASSOC_FAIL.
  return reason == 2 || reason == 15 || reason == 201 || reason == 202 || reason == 203;
}

}  // namespace

bool connect(const char* ssid, const char* pass, uint32_t timeoutMs, fry::ProvErr* errOut) {
  s_l2Associated = false;
  s_lastDiscReason = 0;
  static bool eventRegistered = false;
  if (!eventRegistered) {
    WiFi.onEvent(onWifiEvent);
    eventRegistered = true;
  }

  WiFi.persistent(false);  // don't wear the flash — we persist credentials ourselves
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true);
  delay(100);
  WiFi.begin(ssid, (pass && strlen(pass)) ? pass : nullptr);

  unsigned long start = millis();
  while (millis() - start < timeoutMs) {
    if (WiFi.status() == WL_CONNECTED) {
      s_everConnected = true;
      Serial.printf("wifi connected ip=%s rssi=%d\n", WiFi.localIP().toString().c_str(), WiFi.RSSI());
      return true;
    }
    delay(250);
  }

  if (errOut) {
    if (s_l2Associated) {
      *errOut = fry::ProvErr::NoIp;  // associated but DHCP never completed
    } else if (isAuthFailureReason(s_lastDiscReason)) {
      *errOut = fry::ProvErr::WifiAuth;
    } else {
      *errOut = fry::ProvErr::WifiAuth;  // undiagnosed failure — treat as an auth-class error
    }
  }
  Serial.printf("wifi connect failed reason=%u associated=%d\n", s_lastDiscReason, (int)s_l2Associated);
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
