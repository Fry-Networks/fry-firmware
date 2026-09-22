// Fry device firmware — entry point and boot sequence.
// load config -> if no credentials, start provisioning -> else connect WiFi -> start VPN ->
// begin the report loop. See PROTOCOL.md sections 1-3 for the two provisioning transports.
#include <Arduino.h>
#if defined(ARDUINO_ARCH_ESP8266)
#include <ESP8266WiFi.h>
#else
#include <WiFi.h>
#endif
#include "boot_policy.h"
#include "config.h"
#include "core/fry_config.h"
#include "core/miner_key.h"
#include "core/ota_client.h"
#include "core/provisioning_transport.h"
#include "core/serial_commands.h"
#include "core/trigger_hooks.h"
#include "core/vpn_relay.h"
#include "core/wifi_station.h"
#include "heap_gate.h"
#include "reset_button.h"

#ifndef FRY_FIRMWARE_VERSION
#define FRY_FIRMWARE_VERSION "0.0.0-dev"
#endif
#ifndef FRY_CHIP
#define FRY_CHIP "UNKNOWN"
#endif

namespace {

using fry::BootPhase;

BootPhase s_phase = BootPhase::AwaitingProvisioning;
fry::BootPolicy s_bootPolicy;
fry::ResetButton s_resetButton;
unsigned long s_lastResetHintMs = 0;
char s_minerKey[40] = "FEM-PENDING";
char s_deviceName[32] = {0};
unsigned long s_lastHealthLogMs = 0;

// The only way to change phase. Routing every transition through the policy means no call site
// can forget to bring the provisioning transport up — which is precisely how a board whose stored
// WiFi credentials had gone stale used to land in AwaitingProvisioning with no radio running, and
// so become permanently invisible to the app. See lib/fry_core/boot_policy.h.
void setPhase(BootPhase phase) {
  s_phase = phase;
  if (s_bootPolicy.onPhaseEntry(phase)) {
    fry_provisioning::init(s_deviceName, s_minerKey);
  }
}

// Recovery of last resort, polled in every phase. Clears stored WiFi credentials and wallet so
// the board comes back up advertising for provisioning. fry_config::factoryReset() deliberately
// preserves the salt and miner key, so the device keeps its server identity across the reset.
void pollFactoryResetButton() {
  unsigned long now = millis();
  bool pressed = digitalRead(FRY_RESET_BUTTON_PIN) == LOW;

  if (s_resetButton.update(pressed, static_cast<uint32_t>(now))) {
    Serial.println("[reset] factory reset - clearing wifi + wallet, identity preserved");
    Serial.flush();
    fry_config::factoryReset();
    ESP.restart();
    return;
  }

  // Progress feedback, so a user holding the button can tell it is being seen.
  uint32_t held = s_resetButton.heldMs(static_cast<uint32_t>(now));
  if (held >= 1000 && now - s_lastResetHintMs >= 1000) {
    s_lastResetHintMs = now;
    Serial.printf("[reset] hold %lus/%lus\n", (unsigned long)(held / 1000),
                  (unsigned long)(fry::kFactoryResetHoldMs / 1000));
  }
}

void print_mac(char* out, size_t outLen) {
  uint8_t mac[6];
  WiFi.macAddress(mac);
  snprintf(out, outLen, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4],
           mac[5]);
}

// PROTOCOL.md section 9: `[health] up=<s> heap=<free> blk=<maxblock> rssi=<dbm> vpn=<up|down>
// relayed=<bytes> temp=<c|na>`. No temperature sensor in scope, so temp is always "na".
void emitHealthLogIfDue() {
  unsigned long now = millis();
  if (now - s_lastHealthLogMs < HEALTH_LOG_MS) return;
  s_lastHealthLogMs = now;
  // blk must be the largest CONTIGUOUS block, not total free. On ESP32 this printed getFreeHeap()
  // for both, so the field that the OTA gate actually decides on was invisible in every log we
  // have — a board could report blk=149668 while refusing an update for want of a 36 KB block.
  // fry::queryMaxFreeBlock() is the same source the gate reads.
  Serial.printf("[health] up=%lus heap=%u blk=%u rssi=%d vpn=%s relayed=%u temp=na\n",
                now / 1000, static_cast<unsigned>(ESP.getFreeHeap()),
                static_cast<unsigned>(fry::queryMaxFreeBlock()),
                fry_wifi::isConnected() ? fry_wifi::rssi() : 0, fry_vpn::isUp() ? "up" : "down",
                static_cast<unsigned>(fry_vpn::relayedBytes()));
}

void attemptWifiConnect() {
  char ssid[33] = {0};
  char pass[65] = {0};
  fry_config::getWifi(ssid, sizeof(ssid), pass, sizeof(pass));

  fry::ProvErr err = fry::ProvErr::None;
  if (fry_wifi::connect(ssid, pass, WIFI_CONNECT_TIMEOUT_MS, &err)) {
    fry_provisioning::notifyWifiUp();
    // registerInstallation() (T5's strong override) reports its own real outcome via
    // notifyApiOk()/notifyApiFail() — it must NOT be assumed to succeed here. Registration is
    // one optional subsystem, not a boot gate: VPN and the Ready-phase report loop start
    // unconditionally below regardless of whether it succeeds, so a hardwareapi outage or a
    // rejected miner code never stops WiFi, the relay endpoint, health logging, or OTA.
    fry_trigger_register_now();  // T5 overrides; weak default just logs and returns
    fry_trigger_start_vpn();  // T6 overrides
    setPhase(BootPhase::Ready);
  } else {
    // Back to provisioning so the transport can surface the error and accept a retry. On a board
    // that booted WITH credentials this is also where the transport starts for the first time —
    // notifyWifiAuthFail() below would otherwise be shouting down a radio that was never on.
    setPhase(BootPhase::AwaitingProvisioning);
    if (err == fry::ProvErr::NoIp) {
      fry_provisioning::notifyWifiNoIp();
    } else {
      fry_provisioning::notifyWifiAuthFail();
    }
  }
}

}  // namespace

void setup() {
  Serial.begin(115200);
  delay(200);

  pinMode(FRY_RESET_BUTTON_PIN, INPUT_PULLUP);  // BOOT button, active-low

  char mac[18] = "00:00:00:00:00:00";
  print_mac(mac, sizeof(mac));

  fry_identity::ensureMinerKey(s_minerKey, sizeof(s_minerKey));
  fry_identity::getDeviceName(s_deviceName, sizeof(s_deviceName));

  Serial.printf("FRY boot v%s chip=%s mac=%s minerkey=%s\n", FRY_FIRMWARE_VERSION, FRY_CHIP, mac,
                s_minerKey);

  fry_ota::init();  // may restart the device (manual rollback) — call before anything stateful

#ifdef FRY_SERIAL_PROVISION
  fry_serial_init();
#endif

  // Previously provisioned boards skip straight to the join; the transport is started lazily by
  // setPhase() if and when that join fails. Starting it here unconditionally is NOT an option on
  // ESP8266, where the transport is a softAP and bringing it up switches the radio to WIFI_AP.
  setPhase(fry::initialBootPhase(fry::hasBootCredentials(
      fry_config::hasWifi(), fry_config::hasWallet(), fry_config::hasProvDone())));

  Serial.println("[boot] ready");
}

void loop() {
#ifdef FRY_SERIAL_PROVISION
  fry_serial_poll();
#endif

  pollFactoryResetButton();  // every phase — a wedged board must still be recoverable

  switch (s_phase) {
    case BootPhase::AwaitingProvisioning:
      fry_provisioning::loop();
      fry_provisioning::tick();
      if (fry_provisioning::readyToConnect()) {
        setPhase(BootPhase::ConnectingWifi);
      }
      break;

    case BootPhase::ConnectingWifi:
      attemptWifiConnect();
      break;

    case BootPhase::Ready:
      fry_wifi::maintain();
      fry_provisioning::loop();  // keep serving /status (ESP8266) until AP teardown fires
      fry_provisioning::tick();
      fry_vpn::tick();  // ESP8266: pumps the SOCKS5 relay; ESP32: polls the WG handshake state
      fry_trigger_report_loop_tick();  // T5 overrides; weak default is a no-op
      emitHealthLogIfDue();
      break;
  }
}
