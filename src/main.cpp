// Fry device firmware — entry point and boot sequence.
// load config -> if no credentials, start provisioning -> else connect WiFi -> start VPN ->
// begin the report loop. See PROTOCOL.md sections 1-3 for the two provisioning transports.
#include <Arduino.h>
#if defined(ARDUINO_ARCH_ESP8266)
#include <ESP8266WiFi.h>
#else
#include <WiFi.h>
#endif
#include "config.h"
#include "core/fry_config.h"
#include "core/miner_key.h"
#include "core/provisioning_transport.h"
#include "core/serial_commands.h"
#include "core/trigger_hooks.h"
#include "core/wifi_station.h"

#ifndef FRY_FIRMWARE_VERSION
#define FRY_FIRMWARE_VERSION "0.0.0-dev"
#endif
#ifndef FRY_CHIP
#define FRY_CHIP "UNKNOWN"
#endif

namespace {

enum class BootPhase { AwaitingProvisioning, ConnectingWifi, Ready };

BootPhase s_phase = BootPhase::AwaitingProvisioning;
char s_minerKey[40] = "IOT-PENDING";
char s_deviceName[32] = {0};
unsigned long s_lastHealthLogMs = 0;

void print_mac(char* out, size_t outLen) {
  uint8_t mac[6];
  WiFi.macAddress(mac);
  snprintf(out, outLen, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4],
           mac[5]);
}

// PROTOCOL.md section 9: `[health] up=<s> heap=<free> blk=<maxblock> rssi=<dbm> vpn=<up|down>
// relayed=<bytes> temp=<c|na>`. vpn/relayed are placeholders until T6 lands.
void emitHealthLogIfDue() {
  unsigned long now = millis();
  if (now - s_lastHealthLogMs < HEALTH_LOG_MS) return;
  s_lastHealthLogMs = now;
  Serial.printf("[health] up=%lus heap=%u blk=%u rssi=%d vpn=down relayed=0 temp=na\n",
                now / 1000, static_cast<unsigned>(ESP.getFreeHeap()),
#if defined(ARDUINO_ARCH_ESP8266)
                static_cast<unsigned>(ESP.getMaxFreeBlockSize()),
#else
                static_cast<unsigned>(ESP.getFreeHeap()),
#endif
                fry_wifi::isConnected() ? fry_wifi::rssi() : 0);
}

void attemptWifiConnect() {
  char ssid[33] = {0};
  char pass[65] = {0};
  fry_config::getWifi(ssid, sizeof(ssid), pass, sizeof(pass));

  fry::ProvErr err = fry::ProvErr::None;
  if (fry_wifi::connect(ssid, pass, WIFI_CONNECT_TIMEOUT_MS, &err)) {
    fry_provisioning::notifyWifiUp();
    fry_trigger_register_now();  // T5 overrides; weak default just logs and returns
    fry_provisioning::notifyApiOk();
    fry_trigger_start_vpn();  // T6 overrides
    s_phase = BootPhase::Ready;
  } else {
    if (err == fry::ProvErr::NoIp) {
      fry_provisioning::notifyWifiNoIp();
    } else {
      fry_provisioning::notifyWifiAuthFail();
    }
    // Stay in provisioning so the transport can surface the error and accept a retry.
    s_phase = BootPhase::AwaitingProvisioning;
  }
}

}  // namespace

void setup() {
  Serial.begin(115200);
  delay(200);

  char mac[18] = "00:00:00:00:00:00";
  print_mac(mac, sizeof(mac));

  fry_identity::ensureMinerKey(s_minerKey, sizeof(s_minerKey));
  fry_identity::getDeviceName(s_deviceName, sizeof(s_deviceName));

  Serial.printf("FRY boot v%s chip=%s mac=%s minerkey=%s\n", FRY_FIRMWARE_VERSION, FRY_CHIP, mac,
                s_minerKey);

#ifdef FRY_SERIAL_PROVISION
  fry_serial_init();
#endif

  if (fry_config::hasWifi() && fry_config::hasWallet()) {
    s_phase = BootPhase::ConnectingWifi;  // previously provisioned — skip straight to WiFi
  } else {
    fry_provisioning::init(s_deviceName, s_minerKey);
    s_phase = BootPhase::AwaitingProvisioning;
  }

  Serial.println("[boot] ready");
}

void loop() {
#ifdef FRY_SERIAL_PROVISION
  fry_serial_poll();
#endif

  switch (s_phase) {
    case BootPhase::AwaitingProvisioning:
      fry_provisioning::loop();
      fry_provisioning::tick();
      if (fry_provisioning::readyToConnect()) {
        s_phase = BootPhase::ConnectingWifi;
      }
      break;

    case BootPhase::ConnectingWifi:
      attemptWifiConnect();
      break;

    case BootPhase::Ready:
      fry_wifi::maintain();
      fry_provisioning::loop();  // keep serving /status (ESP8266) until AP teardown fires
      fry_provisioning::tick();
      fry_trigger_report_loop_tick();  // T5 overrides; weak default is a no-op
      emitHealthLogIfDue();
      break;
  }
}
