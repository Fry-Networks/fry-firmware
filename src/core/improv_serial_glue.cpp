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
#include "heap_gate.h"
#include "improv_scan.h"
#include "improv_serial.h"
#include "key_policy.h"
#include "miner_key.h"
#include "provisioning_transport.h"
#include "status_snapshot.h"
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
bool s_awaitingWifi = false;  // a wifi-settings command is committed and the join is in flight
bool s_keyChanged = false;    // a 0xF0 write stored a different key; see consumeKeyChanged()
unsigned long s_lastRpcMs = 0;  // when the last complete RPC arrived
// Round 2 F8: a client usually follows 0xF0 with 0x01 at once. The key-change restart waits for
// this much Improv silence, so it never cuts that 0x01 off (a following 0x01 restarts anyway).
const unsigned long kKeyRestartIdleMs = 3000;

bool s_scanRunning = false;
#if defined(ARDUINO_ARCH_ESP8266)
WiFiMode_t s_scanPrevMode = WIFI_OFF;  // restored when the scan ends
#endif
// A board that joined its network answers a scan at most every kRunningScanMinIntervalMs, so the
// window starts when a running-phase scan started; a refused request does not move it.
unsigned long s_lastRunningScanMs = 0;
bool s_haveLastRunningScan = false;
bool s_scanOnRunningBoard = false;  // the scan in flight was admitted on a joined running board

// Smallest contiguous free block a running board may scan with. Only the ESP8266 has one: its
// scan took ~146 bytes of the largest block per network, while the ESP32 family showed no drop (see
// kRunningScanMinBlockEsp8266).
#if defined(ARDUINO_ARCH_ESP8266)
const uint32_t kScanMinBlock = fry::improv::kRunningScanMinBlockEsp8266;
#else
const uint32_t kScanMinBlock = 0;
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

// The firmware NAME reported in the device-info result. ESP Web Tools compares it byte for byte
// against the "name" in docs/flash/manifest.json (`firmware===this._manifest.name` in the
// vendored bundle); a mismatch makes every later visit look like a different product to install
// rather than an update, and prompts an erase. tools/check_flasher_assets.py reads THIS literal
// out of THIS file and fails the release if the two have drifted apart.
const char kImprovFirmwareName[] = "Fry Firmware";

void sendDeviceInfo() {
  const char* info[] = {kImprovFirmwareName, FRY_FIRMWARE_VERSION, FRY_CHIP, s_deviceName};
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
  // Round 2 F8: accepted in every phase - USB is physical access, the same trust as 0xF0. On a
  // board that is already on Wi-Fi the commit makes src/main.cpp restart into the new settings, so
  // the outcome is not awaited here: the old connection must not be reported as the new one.
  const bool running = fry_wifi::isConnected();
  if (!fry_provisioning::commitWifiOnlyCredentials(ssid, pass)) {
    sendError(Error::InvalidRpc);
    return;
  }
  s_awaitingWifi = !running;
  sendState(State::Provisioning);
}

// 0xF0 FrySetMinerKey: the same setOwnerKey() handler BLE characteristic 09 and the ESP8266
// /provision key field end in, over the one transport that proves physical access.
void handleSetMinerKey() {
  char key[40] = {0};
  if (!fry::improv::decodeKeyWrite(s_parser.data(), s_parser.dataLen(), key, sizeof(key))) {
    sendError(Error::InvalidRpc);
    return;
  }
  bool changed = false;
  const fry::KeyWriteVerdict verdict =
      fry_identity::setOwnerKey(key, fry::KeyTransport::Usb, &changed);
  char masked[12];
  fry::maskMinerKey(key, masked, sizeof(masked));
  memset(key, 0, sizeof(key));
  writePacket(fry::improv::encodeKeyWriteResult(verdict, masked, s_out, sizeof(s_out)));
  if (verdict == fry::KeyWriteVerdict::Accept && changed) s_keyChanged = true;
}

void handleGetStatus() {
  fry::DeviceStatus status;
  fry_status::snapshot(status);
  writePacket(fry::improv::encodeFryStatus(status, s_out, sizeof(s_out)));
}

#if defined(ARDUINO_ARCH_ESP8266)
// Back to what it was, unless a join began meanwhile and has taken the mode over.
void restoreScanMode() {
  if (!s_awaitingWifi && WiFi.getMode() != s_scanPrevMode) WiFi.mode(s_scanPrevMode);
}
#endif

// True when a scan started and will be answered by pollScan().
bool handleScanRequest() {
  if (s_scanRunning) return false;  // the running scan will answer; a second request adds nothing
#if defined(ARDUINO_ARCH_ESP8266)
  // The provisioning transport on this chip is a softAP and the captive portal may be in use, so
  // the AP is never dropped: AP_STA keeps it up while the station side scans. A join in flight owns
  // the radio, so it gets the empty result that ends a scan.
  if (s_awaitingWifi) {
    sendResult(Command::RequestScannedWifi, nullptr, 0);
    return false;
  }
  s_scanPrevMode = WiFi.getMode();
  WiFi.mode(static_cast<WiFiMode_t>(s_scanPrevMode | WIFI_STA));
#else
  WiFi.mode(WIFI_STA);
#endif
  // A start that failed (the radio is busy joining, say) is an error, never an empty list.
  if (fry::improv::classifyScanStart(WiFi.scanNetworks(true /* async */, true /* show hidden */)) ==
      fry::improv::ScanStart::Failed) {
#if defined(ARDUINO_ARCH_ESP8266)
    restoreScanMode();
#endif
    sendError(Error::Unknown);
    return false;
  }
  s_scanRunning = true;
  return true;
}

// An async scan is answered over later polls, so the loop is never blocked for the seconds a
// scan takes. One RPC result per network, then the empty result that ends the list.
void pollScan() {
  if (!s_scanRunning) return;
  const int n = WiFi.scanComplete();
  const fry::improv::ScanPoll state = fry::improv::classifyScanPoll(n, s_scanOnRunningBoard);
  if (state == fry::improv::ScanPoll::Wait) return;
  s_scanRunning = false;
  if (state == fry::improv::ScanPoll::Failed) {
    WiFi.scanDelete();
#if defined(ARDUINO_ARCH_ESP8266)
    restoreScanMode();
#endif
    sendError(Error::Unknown);
    return;
  }
#if defined(ARDUINO_ARCH_ESP8266)
  // Reduced to one row per SSID, hidden dropped, bounded, strongest first (lib/fry_core/improv_scan).
  // ~1 KB would sit on the 4 KB ESP8266 cont stack and, as a static, in .bss for the whole uptime: it lives on the heap for this call only.
  fry::improv::ScanListSlot slot;
  fry::improv::ScanList* const listp = slot.acquire();
  if (!listp) {
    WiFi.scanDelete();
    restoreScanMode();
    sendError(Error::Unknown);
    return;
  }
  fry::improv::ScanList& list = *listp;
  for (int i = 0; i < n; i++) {
    list.add(WiFi.SSID(i).c_str(), static_cast<int>(WiFi.RSSI(i)),
             WiFi.encryptionType(i) != ENC_TYPE_NONE);
  }
  for (size_t i = 0; i < list.count(); i++) {
    char rssi[8] = {0};
    fry::improv::formatRssi(list.at(i).rssi, rssi, sizeof(rssi));
    const char* row[] = {list.at(i).ssid, rssi, fry::improv::authCell(list.at(i).secure)};
    sendResult(Command::RequestScannedWifi, row, 3);
  }
  sendResult(Command::RequestScannedWifi, nullptr, 0);
  WiFi.scanDelete();
  restoreScanMode();
#else
#line 232
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
    // Read now, not at init(): an 0xF0 write may have set the key since. Without one the URL
    // carries no #key= fragment rather than an empty one.
    char key[40] = {0};
    fry_identity::ensureMinerKey(key, sizeof(key));
    char url[128];
    if (key[0]) {
      snprintf(url, sizeof(url), "%s#key=%s", IMPROV_DEVICE_URL_BASE, key);
    } else {
      snprintf(url, sizeof(url), "%s", IMPROV_DEVICE_URL_BASE);
    }
    const char* one[] = {url};
    sendResult(Command::WifiSettings, one, 1);
    return;
  }

  if (fry_provisioning::state() == fry::ProvState::Error) {
    const fry::ProvErr err = fry_provisioning::lastError();
    if (err == fry::ProvErr::WifiAuth || err == fry::ProvErr::NoIp ||
        err == fry::ProvErr::BadSsid) {
      s_awaitingWifi = false;
      sendError(Error::UnableToConnect);
      sendState(State::Ready);  // back to ready so the client can offer another network
    }
  }
}

void dispatch(bool transportRunning) {
  switch (static_cast<Command>(s_parser.command())) {
    case Command::WifiSettings:
      handleWifiSettings();  // every phase since round 2 (PROTOCOL.md 11.8)
      break;
    case Command::RequestState:
      sendState(currentState());
      break;
    case Command::RequestDeviceInfo:
      sendDeviceInfo();
      break;
    case Command::RequestScannedWifi:
      // A board that joined its network is scanned only when that cannot disturb the station.
      if (fry::improv::admitScan(transportRunning, fry_wifi::isConnected(), s_haveLastRunningScan,
                                 millis(), s_lastRunningScanMs, fry::queryMaxFreeBlock(),
                                 kScanMinBlock) == fry::improv::ScanAdmit::Refuse) {
        sendError(Error::NotAuthorized);
        break;
      }
      if (handleScanRequest()) {
        s_scanOnRunningBoard = !transportRunning;
        if (!transportRunning) {
          s_lastRunningScanMs = millis();
          s_haveLastRunningScan = true;
        }
      }
      break;
    case Command::FrySetMinerKey:
      handleSetMinerKey();
      break;
    case Command::FryGetStatus:
      handleGetStatus();
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
  (void)minerKey;  // read fresh when needed: an 0xF0 write can change it at any time
}

void poll(bool transportRunning) {
  // Bounded: a flood on the UART must not starve the rest of loop() (the factory-reset button is
  // polled there). One wifi-settings packet is 26 bytes, so this drains any real burst.
  for (int budget = 0; budget < 256 && Serial.available(); budget++) {
    switch (s_parser.feed(static_cast<uint8_t>(Serial.read()))) {
      case Result::Rpc:
        s_lastRpcMs = millis();
        dispatch(transportRunning);
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

bool consumeKeyChanged() {
  if (!s_keyChanged || millis() - s_lastRpcMs < kKeyRestartIdleMs) return false;
  s_keyChanged = false;
  return true;
}

}  // namespace fry_improv

#endif  // FRY_HAS_IMPROV
