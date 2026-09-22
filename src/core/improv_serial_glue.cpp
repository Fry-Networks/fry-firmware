// Improv Serial bridge — see improv_serial_glue.h. The wire format lives in lib/fry_core so it
// is unit-tested natively; everything here is I/O and policy.
#include "improv_serial_glue.h"

#if FRY_HAS_IMPROV

#include <cstdio>
#include <cstring>

#if defined(ARDUINO_ARCH_ESP8266)
#include <ESP8266WiFi.h>
#else
#include <WiFi.h>
#endif

#include "fry_config.h"
#include "improv_serial.h"
#include "provisioning_transport.h"
#include "wifi_station.h"

#ifndef FRY_FIRMWARE_VERSION
#define FRY_FIRMWARE_VERSION "0.0.0-dev"
#endif
#ifndef FRY_CHIP
#define FRY_CHIP "UNKNOWN"
#endif
#ifndef IMPROV_DEVICE_URL_BASE
#define IMPROV_DEVICE_URL_BASE "https://dashboard.frynetworks.com/new_registration"
#endif

namespace fry_improv {

namespace {

using fry::improv::Command;
using fry::improv::Error;
using fry::improv::Parser;
using fry::improv::Result;
using fry::improv::State;

Parser s_parser;
uint8_t s_out[fry::improv::kMaxPacket];
char s_deviceName[32] = {0};
char s_minerKey[40] = {0};
bool s_awaitingWifi = false;  // a wifi-settings command is committed and the join is in flight

#if !defined(ARDUINO_ARCH_ESP8266)
bool s_scanRunning = false;
#endif

void writePacket(size_t n) {
  if (!n) return;
  Serial.write(s_out, n);
  // A trailing newline, as ESPHome's improv_serial does: this UART also carries [health] log
  // lines, and it keeps the next log line off the tail of a packet in a human's terminal.
  Serial.write('\n');
  Serial.flush();
}

void sendState(State state) {
  writePacket(fry::improv::encodeCurrentState(state, s_out, sizeof(s_out)));
}

void sendError(Error error) {
  writePacket(fry::improv::encodeError(error, s_out, sizeof(s_out)));
}

void sendResult(Command command, const char* const* strings, uint8_t count) {
  writePacket(fry::improv::encodeRpcResult(static_cast<uint8_t>(command), strings, count, s_out,
                                           sizeof(s_out)));
}

State currentState() {
  if (fry_wifi::isConnected()) return State::Provisioned;
  return s_awaitingWifi ? State::Provisioning : State::Ready;
}

void sendDeviceInfo() {
  // The first string is the firmware NAME and must stay exactly "Fry Firmware": ESP Web Tools
  // compares it byte for byte against the "name" in the flasher manifest, and a mismatch makes
  // every later visit look like a different product to install rather than an update.
  const char* info[] = {"Fry Firmware", FRY_FIRMWARE_VERSION, FRY_CHIP, s_deviceName};
  sendResult(Command::RequestDeviceInfo, info, 4);
}

void handleWifiSettings() {
  char ssid[33] = {0};
  char pass[65] = {0};
  if (!fry::improv::decodeWifiSettings(s_parser.data(), s_parser.dataLen(), ssid, sizeof(ssid),
                                       pass, sizeof(pass))) {
    sendError(Error::InvalidRpc);
    return;
  }

  // The transport owns the FSM and the persist-before-Connecting ordering; main.cpp's loop sees
  // readyToConnect() and performs the join exactly as it does for a BLE or portal commit.
  if (!fry_provisioning::commitWifiOnlyCredentials(ssid, pass)) {
    sendError(Error::InvalidRpc);
    return;
  }
  s_awaitingWifi = true;
  sendState(State::Provisioning);
}

void handleScanRequest() {
#if defined(ARDUINO_ARCH_ESP8266)
  // On ESP8266 the provisioning transport IS a softAP: the radio is in WIFI_AP and a scan would
  // drop the portal the user may be standing in. Answer with the empty result that terminates a
  // scan response — the Improv client then offers a manual SSID field.
  sendResult(Command::RequestScannedWifi, nullptr, 0);
#else
  if (s_scanRunning) return;  // the running scan will answer; a second request adds nothing
  WiFi.mode(WIFI_STA);
  WiFi.scanNetworks(true /* async */, true /* show hidden */);
  s_scanRunning = true;
#endif
}

// An async scan is answered over later polls, so the loop is never blocked for the seconds a
// scan takes. One RPC result per network, then the empty result that ends the list.
void pollScan() {
#if !defined(ARDUINO_ARCH_ESP8266)
  if (!s_scanRunning) return;
  const int n = WiFi.scanComplete();
  if (n == WIFI_SCAN_RUNNING) return;
  s_scanRunning = false;
  if (n > 0) {
    for (int i = 0; i < n; i++) {
      char ssid[33] = {0};
      strncpy(ssid, WiFi.SSID(i).c_str(), sizeof(ssid) - 1);
      char rssi[8] = {0};
      snprintf(rssi, sizeof(rssi), "%d", static_cast<int>(WiFi.RSSI(i)));
      const char* row[] = {ssid, rssi, WiFi.encryptionType(i) == WIFI_AUTH_OPEN ? "NO" : "YES"};
      sendResult(Command::RequestScannedWifi, row, 3);
    }
  }
  sendResult(Command::RequestScannedWifi, nullptr, 0);
  WiFi.scanDelete();
#endif
}

// Reports the outcome of the join that a wifi-settings command started. WiFi up is the success
// condition, not the FSM's Connected state: that additionally waits for hardwareapi registration,
// which is an optional subsystem and must not hold up the flasher.
void pollWifiOutcome() {
  if (!s_awaitingWifi) return;

  if (fry_wifi::isConnected()) {
    s_awaitingWifi = false;
    sendState(State::Provisioned);
    char url[128];
    snprintf(url, sizeof(url), "%s#key=%s", IMPROV_DEVICE_URL_BASE, s_minerKey);
    const char* one[] = {url};
    sendResult(Command::WifiSettings, one, 1);
    return;
  }

  if (fry_provisioning::state() == fry::ProvState::Error) {
    const fry::ProvErr err = fry_provisioning::lastError();
    if (err == fry::ProvErr::WifiAuth || err == fry::ProvErr::NoIp) {
      s_awaitingWifi = false;
      sendError(Error::UnableToConnect);
      sendState(State::Ready);  // back to ready so the client can offer another network
    }
  }
}

void dispatch() {
  switch (static_cast<Command>(s_parser.command())) {
    case Command::WifiSettings:
      handleWifiSettings();
      break;
    case Command::RequestState:
      sendState(currentState());
      break;
    case Command::RequestDeviceInfo:
      sendDeviceInfo();
      break;
    case Command::RequestScannedWifi:
      handleScanRequest();
      break;
    default:
      // Declined, not ignored: a client that gets silence cannot tell a busy device from one
      // that does not implement the command.
      sendError(Error::UnknownCommand);
      break;
  }
}

}  // namespace

void init(const char* deviceName, const char* minerKey) {
  strncpy(s_deviceName, deviceName ? deviceName : "", sizeof(s_deviceName) - 1);
  strncpy(s_minerKey, minerKey ? minerKey : "", sizeof(s_minerKey) - 1);
}

void poll(bool transportRunning) {
  if (!transportRunning) return;

  // Bounded: a flood on the UART must not starve the rest of loop() (the factory-reset button is
  // polled there). One wifi-settings packet is 26 bytes, so this drains any real burst.
  for (int budget = 0; budget < 256 && Serial.available(); budget++) {
    switch (s_parser.feed(static_cast<uint8_t>(Serial.read()))) {
      case Result::Rpc:
        dispatch();
        break;
      case Result::BadChecksum:
      case Result::Malformed:
        sendError(Error::InvalidRpc);
        break;
      case Result::None:
        break;
    }
  }

  pollScan();
  pollWifiOutcome();
}

}  // namespace fry_improv

#endif  // FRY_HAS_IMPROV
