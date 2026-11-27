// Built only by the Pico / BK7231N envs (platformio.boards.ini defines FRY_BOARDS_PORT); the ESP envs compile all of src/.
#if defined(FRY_BOARDS_PORT)
// Entry point and boot sequence of the Pico and BK7231N boards: the same state machine as src/main.cpp (load config -> provisioning
// when there are no credentials -> join WiFi -> register/heartbeat/lease/PoC/OTA), over the board HAL. src/main.cpp is pinned by ~35
// source tests and is ESP-coupled (ESP.restart, vTaskDelay, the UI hooks), so the new boards carry their own copy of the sequence;
// the serial lines the QA gates grep for (PROTOCOL.md sections 9 and 11.7) are the same.
#include <Arduino.h>
#include <WiFi.h>

#include "../core/flash_print.h"
#include "../core/fry_config.h"
#include "../core/hardwareapi_client.h"
#include "../core/improv_serial_glue.h"
#include "../core/miner_key.h"
#include "../core/ota_client.h"
#include "../core/provisioning_transport.h"
#include "../core/trigger_hooks.h"
#include "../core/vpn_relay.h"
#include "../core/wifi_station.h"
#include "board_presets.h"
#include "boot_policy.h"
#include "flash_fmt.h"
#include "fry_board_hal.h"
#include "heap_gate.h"
#include "key_policy.h"
#include "reset_button.h"
#include "wifi_retry.h"

#ifdef FRY_RESET_BUTTON_PIN
#define FRY_BOARD_BUTTON_OVERRIDE 1
#endif
#include "config.h"

#ifndef FRY_FIRMWARE_VERSION
#define FRY_FIRMWARE_VERSION "0.0.0-dev"
#endif
#ifndef FRY_CHIP
#define FRY_CHIP "UNKNOWN"
#endif
#ifndef FRY_BUILD_ENV
#define FRY_BUILD_ENV "unknown"
#endif

namespace {

using fry::BootPhase;

BootPhase s_phase = BootPhase::AwaitingProvisioning;
fry::BootPolicy s_bootPolicy;
fry::ResetButton s_resetButton;
fry::JoinRetry s_joinRetry;  // background retry of the stored network
unsigned long s_lastResetHintMs = 0;
unsigned long s_lastHealthLogMs = 0;
char s_minerKey[40] = "FEM-PENDING";
char s_deviceName[32] = {0};
int s_buttonPin = -1;

// The only way to change phase: routing every transition through the policy means no call site can forget to bring the
// provisioning transport up (lib/fry_core/boot_policy.h).
void setPhase(BootPhase phase) {
  s_phase = phase;
  if (s_bootPolicy.onPhaseEntry(phase)) fry_provisioning::init(s_deviceName, s_minerKey);
}

// Recovery of last resort, polled in every phase. Clears stored WiFi credentials and wallet so the board comes back up advertising
// for provisioning; fry_config::factoryReset() keeps the salt and miner key, so the server identity survives.
void pollFactoryResetButton() {
  if (s_buttonPin < 0) return;
  const unsigned long now = millis();
  const bool pressed = fry::board::readButton(s_buttonPin);
  if (s_resetButton.update(pressed, static_cast<uint32_t>(now))) {
    FRY_PRINTLN("[reset] factory reset - clearing wifi + wallet, identity preserved");
    Serial.flush();
    fry_config::factoryReset();
    fry::board::restart();
    return;
  }
  const uint32_t held = s_resetButton.heldMs(static_cast<uint32_t>(now));
  if (held >= 1000 && now - s_lastResetHintMs >= 1000) {
    s_lastResetHintMs = now;
    FRY_PRINTF("[reset] hold %lus/%lus\n", static_cast<unsigned long>(held / 1000), static_cast<unsigned long>(fry::kFactoryResetHoldMs / 1000));
  }
}

// PROTOCOL.md section 9: `[health] up=<s> heap=<free> blk=<maxblock> rssi=<dbm> vpn=<up|down> relayed=<bytes> temp=<c|na>`.
void emitHealthLogIfDue() {
  const unsigned long now = millis();
  if (now - s_lastHealthLogMs < HEALTH_LOG_MS) return;
  s_lastHealthLogMs = now;
  FRY_PRINTF("[health] up=%lus heap=%u blk=%u rssi=%d vpn=%s relayed=%u temp=na\n", now / 1000,
             static_cast<unsigned>(fry::board::freeHeap()), static_cast<unsigned>(fry::queryMaxFreeBlock()),
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
    if (s_joinRetry.failures() > 0) {
      FRY_PRINTF("wifi: stored network reachable again after %u failed joins\n", static_cast<unsigned>(s_joinRetry.failures()));
    }
    s_joinRetry.onSuccess();
    // Registration is one optional subsystem, not a boot gate: it reports its own outcome via notifyApiOk()/notifyApiFail(), and
    // the relay hook and the Ready-phase report loop start whether or not it succeeds.
    fry_trigger_register_now();
    fry_trigger_start_vpn();
    fry_ota::noteStartupDone();
    setPhase(BootPhase::Ready);
  } else {
    // Back to provisioning so the transport can surface the error and accept a retry.
    setPhase(BootPhase::AwaitingProvisioning);
    s_joinRetry.onFailure(static_cast<uint32_t>(millis()), err);
    FRY_PRINTF("wifi: stored network not reachable - retry %u in %us\n", static_cast<unsigned>(s_joinRetry.failures()),
               static_cast<unsigned>(s_joinRetry.lastDelayMs() / 1000UL));
    if (err == fry::ProvErr::NoIp) {
      fry_provisioning::notifyWifiNoIp();
    } else if (err == fry::ProvErr::BadSsid) {
      fry_provisioning::notifyWifiNoAp();
    } else {
      fry_provisioning::notifyWifiAuthFail();
    }
  }
}

// True when the stored network should be joined again now (lib/fry_core/wifi_retry.h).
bool storedNetworkRetryNow() {
  const uint32_t now = static_cast<uint32_t>(millis());
  if (!s_joinRetry.due(now)) return false;
  const bool usable = fry::hasBootCredentials(fry_config::hasWifi(), fry_config::hasWallet(), fry_config::hasProvDone()) &&
                      fry::keyAllowsJoin(fry::kBuildKeyModel, s_minerKey[0] != 0);
  return s_joinRetry.decide(now, fry_provisioning::sessionState(), usable) == fry::RetryAction::Join;
}

void restartToApply(const char* why) {
  Serial.println(why);
  // Not a failure: a restart that is not a failure must not count against an image that is still pending (PROTOCOL.md 11.8).
  fry_ota::notePlannedRestart();
  Serial.flush();
  delay(300);
  fry::board::restart();
}

void onOwnerKeyChanged() {
  fry_identity::ensureMinerKey(s_minerKey, sizeof(s_minerKey));
  if (s_phase != BootPhase::Ready) return;
  restartToApply("[prov] miner key changed - restarting to register with the new key");
}

}  // namespace

void setup() {
  Serial.begin(115200);
#if defined(FRY_BOARD_PICO)
  // USB CDC: give the host a moment to open the port, so the boot banner is not lost.
  for (unsigned long t = millis(); !Serial && millis() - t < 3000;) delay(10);
#endif
  delay(200);

#ifdef FRY_BOARD_BUTTON_OVERRIDE
  s_buttonPin = FRY_RESET_BUTTON_PIN;
#else
  const fry::boards::Preset* preset = fry::boards::presetForOs(FRY_BUILD_ENV);
  s_buttonPin = preset ? preset->resetButtonPin : -1;
#endif
  if (s_buttonPin >= 0) pinMode(s_buttonPin, INPUT_PULLUP);  // active low
  fry_wifi::setWaitHook(pollFactoryResetButton);             // a hold is also seen during a (background) join

  uint8_t macb[6] = {0};
  fry::board::macAddress(macb);
  char mac[18];
  FRY_SNPRINTF(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X", macb[0], macb[1], macb[2], macb[3], macb[4], macb[5]);

  fry_identity::ensureMinerKey(s_minerKey, sizeof(s_minerKey));
  fry_identity::getDeviceName(s_deviceName, sizeof(s_deviceName));

  // The log only ever shows FEM-<U+2026>last4 (key_policy.h); NONE and the compiled-in FEM-PENDING placeholder stay readable.
  char keyMasked[12];
  const char* keyForLog = "NONE";
  if (strcmp(s_minerKey, "FEM-PENDING") == 0) {
    keyForLog = "FEM-PENDING";
  } else if (s_minerKey[0]) {
    fry::maskMinerKeyLast4(s_minerKey, keyMasked, sizeof(keyMasked));
    keyForLog = keyMasked;
  }
  FRY_PRINTF("FRY boot v%s chip=%s mac=%s minerkey=%s\n", FRY_FIRMWARE_VERSION, FRY_CHIP, mac, keyForLog);
  FRY_PRINTF("[boot] reset_reason=%u os=%s\n", static_cast<unsigned>(fry_hwapi::resetReason()), FRY_BUILD_ENV);

  fry_ota::init();
  fry_improv::init(s_deviceName, s_minerKey);  // no-op unless FRY_HAS_IMPROV

  // A board with stored credentials skips straight to the join; the transport starts lazily if that join fails. A USER_SUPPLIED
  // board without a miner key stays provisionable even with credentials stored: the transport is how the owner writes the key.
  const bool hasCredentials = fry::hasBootCredentials(fry_config::hasWifi(), fry_config::hasWallet(), fry_config::hasProvDone());
  const bool keyOk = fry::keyAllowsJoin(fry::kBuildKeyModel, s_minerKey[0] != 0);
  if (hasCredentials && !keyOk) FRY_PRINTLN("[boot] wifi credentials stored but no miner key - staying provisionable");
  setPhase(fry::initialBootPhase(hasCredentials && keyOk));

  FRY_PRINTLN("[boot] ready");
}

void loop() {
  fry_ota::loopGuard();

  // Improv Serial answers its read-only commands and the 0xF0 key write in every phase; Wi-Fi settings only while the provisioning
  // transport is up.
  fry_improv::poll(s_bootPolicy.transportStarted());
  if (fry_improv::consumeKeyChanged()) onOwnerKeyChanged();

  pollFactoryResetButton();  // every phase: a wedged board must still be recoverable

  switch (s_phase) {
    case BootPhase::AwaitingProvisioning:
      fry_provisioning::loop();
      fry_provisioning::tick();
      if (fry_provisioning::readyToConnect()) setPhase(BootPhase::ConnectingWifi);
      // Valid stored settings whose network was unreachable at boot: keep joining it in the background.
      if (s_phase == BootPhase::AwaitingProvisioning && storedNetworkRetryNow()) setPhase(BootPhase::ConnectingWifi);
      break;

    case BootPhase::ConnectingWifi:
      attemptWifiConnect();
      break;

    case BootPhase::Ready:
      fry_wifi::maintain();
      fry_provisioning::loop();
      fry_provisioning::tick();
      // A transport committed new settings while the board was already running: boot into them.
      if (fry_provisioning::readyToConnect()) {
        restartToApply("[prov] new settings committed while running - restarting to join with them");
      }
      fry_vpn::tick();
      fry_trigger_report_loop_tick();
      emitHealthLogIfDue();
      break;
  }

  fry::board::feedWatchdog();
  delay(1);  // yield to the radio / network stack at the end of every pass
}
#endif  // FRY_BOARDS_PORT
