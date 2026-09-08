// ESP8266 WiFi station connect. Ported patterns from the hardware-proven sensmos-firmware
// wifi_manager.cpp: softAP teardown before STA, forced 802.11g PHY, event-aware connect wait
// with a DHCP-completion extension, disconnect-reason decoding, and a reconnect watchdog.
#include "../core/wifi_station.h"

#include <ESP8266WiFi.h>

#include <cstring>

namespace fry_wifi {

namespace {

volatile uint8_t s_lastDiscReason = 0;
volatile bool s_l2Associated = false;
volatile bool s_dhcpTimedOut = false;
bool s_everConnected = false;
WiFiEventHandler s_evtDisc, s_evtConn, s_evtDhcpTo;

}  // namespace

bool connect(const char* ssid, const char* pass, uint32_t timeoutMs, fry::ProvErr* errOut) {
  s_lastDiscReason = 0;
  s_l2Associated = false;
  s_dhcpTimedOut = false;

  // After softAP-based provisioning the radio is still in AP/AP+STA mode; WiFi.mode(WIFI_STA)
  // alone does not drop it and the station can wedge in STATION_CONNECTING with zero events.
  WiFi.softAPdisconnect(true);
  WiFi.persistent(false);
  WiFi.mode(WIFI_STA);
  WiFi.setSleepMode(WIFI_NONE_SLEEP);
  // Default 802.11n has marginal RX on some APs: the station associates but DHCP OFFERs are
  // intermittently dropped. Forcing 11g measured 17/17 GOT_IP vs ~10-25% on 11n (sensmos, on
  // hardware). Throughput is irrelevant for this low-rate telemetry/relay node.
  WiFi.setPhyMode(WIFI_PHY_MODE_11G);
  delay(100);

  if (!s_evtConn) {
    s_evtDisc = WiFi.onStationModeDisconnected(
        [](const WiFiEventStationModeDisconnected& e) { s_lastDiscReason = (uint8_t)e.reason; });
    s_evtConn = WiFi.onStationModeConnected(
        [](const WiFiEventStationModeConnected&) { s_l2Associated = true; });
    s_evtDhcpTo = WiFi.onStationModeDHCPTimeout([]() { s_dhcpTimedOut = true; });
  }

  WiFi.begin(ssid, (pass && strlen(pass)) ? pass : "");

  unsigned long start = millis();
  unsigned long budget = timeoutMs;
  bool extended = false;
  while (millis() - start < budget) {
    if (WiFi.status() == WL_CONNECTED) {
      s_everConnected = true;
      Serial.printf("wifi connected ip=%s rssi=%d\n", WiFi.localIP().toString().c_str(), WiFi.RSSI());
      return true;
    }
    // L2 association succeeded but no lease yet — extend the window instead of declaring
    // failure (slow-DHCP guest networks can need up to +45s after association, per sensmos).
    if (s_l2Associated && !extended) {
      extended = true;
      budget += 45000;
      Serial.println("wifi: associated - extending wait for DHCP");
    }
    delay(250);
  }

  if (errOut) {
    if (s_l2Associated || s_dhcpTimedOut) {
      *errOut = fry::ProvErr::NoIp;
    } else {
      *errOut = fry::ProvErr::WifiAuth;  // covers auth failures and the undiagnosed case alike
    }
  }
  // WIFI_REASON_* (e.g. 2 AUTH_EXPIRE, 15 4WAY_HANDSHAKE_TIMEOUT, 201 NO_AP_FOUND, 202
  // AUTH_FAIL) is logged verbatim for diagnosis even though the mapping above only
  // distinguishes "associated" (NoIp) from "never associated" (WifiAuth).
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
    s_lost = now;
  }
}

}  // namespace fry_wifi
