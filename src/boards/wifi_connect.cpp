// Built only by the Pico / BK7231N envs (platformio.boards.ini defines FRY_BOARDS_PORT); the ESP envs compile all of src/.
#if defined(FRY_BOARDS_PORT)
// WiFi station for the Pico and BK7231N boards behind src/core/wifi_station.h. The Arduino WiFi API both cores provide
// (WiFi.begin / status / RSSI / localIP), driven the way src/esp32/wifi_connect.cpp drives it: a bounded blocking join that calls the
// wait hook every 250 ms, a failure classified into fry::ProvErr, and a reconnect watchdog.
#include "../core/wifi_station.h"

#include <WiFi.h>

#include "../core/fry_config.h"
#include "config.h"
#include "ip_str.h"
#include "../core/flash_print.h"

namespace fry_wifi {

namespace {

void (*s_waitHook)() = nullptr;
bool s_everConnected = false;
unsigned long s_lastReconnectMs = 0;
const unsigned long kReconnectEveryMs = 15000;

// What a failed join looked like. The cores report an unknown SSID (WL_NO_SSID_AVAIL), a refused association (WL_CONNECT_FAILED)
// and a timeout; a link without an address is NoIp.
fry::ProvErr classify(wl_status_t st) {
  if (st == WL_NO_SSID_AVAIL) return fry::ProvErr::BadSsid;
  if (st == WL_CONNECTED) return fry::ProvErr::NoIp;
  return fry::ProvErr::WifiAuth;
}

}  // namespace

void setWaitHook(void (*hook)()) { s_waitHook = hook; }

bool connect(const char* ssid, const char* pass, uint32_t timeoutMs, fry::ProvErr* errOut) {
  if (errOut) *errOut = fry::ProvErr::None;
  if (!ssid || !ssid[0]) {
    if (errOut) *errOut = fry::ProvErr::BadSsid;
    return false;
  }
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(50);
  if (pass && pass[0]) {
    WiFi.begin(ssid, pass);
  } else {
    WiFi.begin(ssid);
  }
  const unsigned long start = millis();
  unsigned long lastHook = start;
  wl_status_t st = WL_IDLE_STATUS;
  while (millis() - start < timeoutMs) {
    st = static_cast<wl_status_t>(WiFi.status());
    if (st == WL_CONNECTED && WiFi.localIP() != IPAddress(0, 0, 0, 0)) {
      s_everConnected = true;
      FRY_PRINTF("wifi: connected ip=%s rssi=%d\n", fry_boards::ipToString(WiFi.localIP()).c_str(), static_cast<int>(WiFi.RSSI()));
      return true;
    }
    if (st == WL_NO_SSID_AVAIL || st == WL_CONNECT_FAILED) break;  // the stack already gave its answer
    if (s_waitHook && millis() - lastHook >= 250) {
      lastHook = millis();
      s_waitHook();
    }
    delay(50);
  }
  st = static_cast<wl_status_t>(WiFi.status());
  if (errOut) *errOut = classify(st);
  FRY_PRINTF("wifi: join failed status=%d\n", static_cast<int>(st));
  WiFi.disconnect();
  return false;
}

// arduino-pico reports WL_CONNECTED for a running soft AP as well; a station link exists only outside AP-only mode.
bool isConnected() { return WiFi.getMode() != WIFI_AP && WiFi.status() == WL_CONNECTED; }

String localIp() { return fry_boards::ipToString(WiFi.localIP()); }

int8_t rssi() { return static_cast<int8_t>(WiFi.RSSI()); }

void maintain() {
  if (!s_everConnected || isConnected()) return;
  const unsigned long now = millis();
  if (now - s_lastReconnectMs < kReconnectEveryMs) return;
  s_lastReconnectMs = now;
  FRY_PRINTLN("wifi: link lost - reconnecting");
  char ssid[33] = {0};
  char pass[65] = {0};
  fry_config::getWifi(ssid, sizeof(ssid), pass, sizeof(pass));
  if (pass[0]) {
    WiFi.begin(ssid, pass);
  } else {
    WiFi.begin(ssid);
  }
  memset(pass, 0, sizeof(pass));
}

}  // namespace fry_wifi
#endif  // FRY_BOARDS_PORT
