// BLE GATT provisioning transport for ESP32 / ESP32-S3 / ESP32-C3. PROTOCOL.md section 1.
#include "../core/provisioning_transport.h"

#include <NimBLEDevice.h>
#ifdef USING_NIMBLE_ARDUINO_HEADERS
#include "nimble/nimble/host/include/host/ble_hs.h"  // ble_hs_cfg.sm_sc_only
#else
#include "host/ble_hs.h"
#endif

#include <cstring>

#include "../core/fry_config.h"
#include "../core/miner_key.h"
#include "../core/status_snapshot.h"
#include "device_status.h"
#include "key_policy.h"
#include "provisioning_commit.h"

#ifndef FRY_FIRMWARE_VERSION
#define FRY_FIRMWARE_VERSION "0.0.0-dev"
#endif
#ifndef FRY_CHIP
#define FRY_CHIP "UNKNOWN"
#endif

namespace fry_provisioning {

namespace {

// 0x465259 = "FRY", 0x4652594e4554 = "FRYNET" — see PROTOCOL.md section 1.
const char* kServiceUuid = "46525900-0001-4000-8000-4652594e4554";
const char* kUuidSsid = "46525901-0001-4000-8000-4652594e4554";
const char* kUuidPass = "46525902-0001-4000-8000-4652594e4554";
const char* kUuidWallet = "46525903-0001-4000-8000-4652594e4554";
const char* kUuidDeviceName = "46525904-0001-4000-8000-4652594e4554";
const char* kUuidMinerKey = "46525905-0001-4000-8000-4652594e4554";
const char* kUuidStatus = "46525906-0001-4000-8000-4652594e4554";
const char* kUuidFwVer = "46525907-0001-4000-8000-4652594e4554";
const char* kUuidChip = "46525908-0001-4000-8000-4652594e4554";
// PROTOCOL.md section 11.3 (v1.1).
const char* kUuidKeyWrite = "46525909-0001-4000-8000-4652594e4554";
const char* kUuidDevStatus = "4652590a-0001-4000-8000-4652594e4554";

fry::ProvisioningFsm s_fsm;

NimBLECharacteristic* s_chSsid = nullptr;
NimBLECharacteristic* s_chPass = nullptr;
NimBLECharacteristic* s_chWallet = nullptr;
NimBLECharacteristic* s_chStatus = nullptr;
NimBLECharacteristic* s_chKey = nullptr;
NimBLECharacteristic* s_chKeyWrite = nullptr;
NimBLECharacteristic* s_chDevStatus = nullptr;

char s_pendingSsid[33] = {0};
char s_pendingPass[65] = {0};
// Characteristic 09: held in RAM only, persisted together with Wi-Fi at the wallet commit.
char s_pendingKey[37] = {0};

// PROTOCOL.md 11.9: 0A also says whether the reader's link is encrypted ("enc"), so a client can
// prove the link before it writes the key to 09. enc < 0: the one connected central's link, if any.
void setDevStatusValue(int enc = -1) {
  if (!s_chDevStatus) return;
  if (enc < 0) {
    NimBLEServer* server = NimBLEDevice::getServer();
    enc = (server && server->getConnectedCount() > 0 && server->getPeerInfo(0).isEncrypted()) ? 1 : 0;
  }
  fry::DeviceStatus status;
  fry_status::snapshot(status);
  char json[fry::kStatusJsonMax + 16];
  size_t n = fry::buildStatusJson(status, json, fry::kStatusJsonMax + 1);
  static const char kEnc[] = ",\"enc\":0}";
  if (n >= 2 && json[n - 1] == '}' && n - 1 + sizeof(kEnc) <= sizeof(json)) {
    memcpy(json + n - 1, kEnc, sizeof(kEnc));  // replaces the closing brace, adds the NUL
    json[n - 1 + 7] = enc ? '1' : '0';
    n += sizeof(kEnc) - 2;
  }
  s_chDevStatus->setValue(reinterpret_cast<const uint8_t*>(json), n);
}

void updateStatusChar() {
  if (!s_chStatus) return;
  // [state], or [4][legacy][detail] in Error: an old app reads byte 1 and sees 0-5 only.
  uint8_t buf[3];
  const size_t len = fry::encodeProvStatus(s_fsm.state(), s_fsm.error(), buf, sizeof(buf));
  s_chStatus->setValue(buf, len);
  s_chStatus->notify();
  if (s_chDevStatus) {
    setDevStatusValue();
    s_chDevStatus->notify();
  }
}

// Round 2 F5: a key staged by one central must never be committed by the next (a stranger stages
// a key, disconnects, and the owner's proto-1 app then commits Wi-Fi + wallet with it).
void clearStagedKey() { memset(s_pendingKey, 0, sizeof(s_pendingKey)); }

// Round 2 F7: a board running in an API-side Error is not re-provisioned over an unencrypted link
// (the 0.3.x rule). Logged once per session so a noisy central cannot flood the serial line.
bool s_loggedUntrusted = false;
bool dropUntrusted(const NimBLEConnInfo& connInfo) {
  if (connInfo.isEncrypted() || s_fsm.acceptsUntrustedWrites()) return false;
  if (!s_loggedUntrusted) {
    s_loggedUntrusted = true;
    Serial.println("[prov] ignored: unencrypted write while running - pair (write the key) first");
  }
  return true;
}

void rejectKey(fry::KeyWriteVerdict verdict) {
  fry::ProvInputs in;
  in.detail = fry::keyVerdictProvErr(verdict);
  s_fsm.feed(fry::ProvEvent::KeyRejected, in);
}

// Copies a BLE attribute value into a NUL-terminated fixed buffer, bounded by bufLen-1.
void copyAttrValue(NimBLECharacteristic* ch, char* buf, size_t bufLen, size_t* outLen) {
  NimBLEAttValue v = ch->getValue();
  size_t n = v.length();
  if (n > bufLen - 1) n = bufLen - 1;
  memcpy(buf, v.data(), n);
  buf[n] = 0;
  if (outLen) *outLen = v.length();  // report the UNCLAMPED length for validation
}

class ProvCallbacks : public NimBLECharacteristicCallbacks {
 public:
  // 05 and 0A are read fresh: the key can change over USB while the link is up.
  void onRead(NimBLECharacteristic* ch, NimBLEConnInfo& connInfo) override {
    if (ch == s_chKey) {
      char key[40] = {0};
      fry_identity::ensureMinerKey(key, sizeof(key));
      // As a C string: the array overload would publish all 40 bytes, trailing NULs included.
      ch->setValue(static_cast<const char*>(key));
    } else if (ch == s_chDevStatus) {
      setDevStatusValue(connInfo.isEncrypted() ? 1 : 0);
    }
  }

  void onWrite(NimBLECharacteristic* ch, NimBLEConnInfo& connInfo) override {
    if ((ch == s_chSsid || ch == s_chPass || ch == s_chWallet) && dropUntrusted(connInfo)) {
      return;  // not even copied: a later trusted commit must not pick it up
    }
    if (ch == s_chKeyWrite) {
      // PROTOCOL.md 11.9: 09 carries no ATT security flag, so the encryption check is ours. With
      // Secure Connections Only an encrypted link is always an LE Secure Connections one.
      if (!connInfo.isEncrypted()) {
        ch->setValue("");  // NimBLE stored the value before this callback: do not keep it
        Serial.println("[prov] key write ignored: link not encrypted - pair first (LE Secure Connections)");
        return;  // not copied
      }
      char key[40] = {0};
      size_t rawLen = 0;
      copyAttrValue(ch, key, sizeof(key), &rawLen);
      const fry::ProvState st = s_fsm.state();
      if (st == fry::ProvState::Connecting || st == fry::ProvState::Connected) {
        return;  // this session's commit already happened
      }
      const fry::KeyWriteVerdict verdict =
          rawLen == 36 ? fry_identity::checkOwnerKey(key, fry::KeyTransport::Ble)
                       : fry::KeyWriteVerdict::BadKey;
      if (verdict == fry::KeyWriteVerdict::Accept) {
        memcpy(s_pendingKey, key, sizeof(s_pendingKey));
        Serial.println("[prov] miner key staged over BLE - stored at the wallet commit");
      } else {
        memset(s_pendingKey, 0, sizeof(s_pendingKey));
        rejectKey(verdict);
        Serial.printf("[prov] miner key refused over BLE (%s)\n",
                      verdict == fry::KeyWriteVerdict::BadKey ? "bad_key" : "key_locked");
      }
      memset(key, 0, sizeof(key));
      ch->setValue("");  // the attribute buffer held the key too
      updateStatusChar();
    } else if (ch == s_chSsid) {
      size_t rawLen = 0;
      copyAttrValue(ch, s_pendingSsid, sizeof(s_pendingSsid), &rawLen);
      fry::ProvInputs in;
      in.ssidValid = (rawLen >= 1 && rawLen <= 32);
      in.linkTrusted = connInfo.isEncrypted();
      s_fsm.feed(fry::ProvEvent::SsidWritten, in);
      updateStatusChar();
    } else if (ch == s_chPass) {
      size_t rawLen = 0;
      copyAttrValue(ch, s_pendingPass, sizeof(s_pendingPass), &rawLen);
      fry::ProvInputs in;
      s_fsm.feed(fry::ProvEvent::PassWritten, in);  // password may legitimately be 0 bytes
      updateStatusChar();
    } else if (ch == s_chWallet) {
      char wallet[64] = {0};
      size_t rawLen = 0;
      copyAttrValue(ch, wallet, sizeof(wallet), &rawLen);
      fry::ProvInputs in;
      in.walletValid = (rawLen == 58);
      if (s_fsm.state() == fry::ProvState::Provisioning && in.walletValid) {
        // v1.1: a USER_SUPPLIED board commits only with a key - stored, or staged over 09 just now.
        char stored[40] = {0};
        fry_identity::ensureMinerKey(stored, sizeof(stored));
        if (!fry::keyAllowsJoin(fry::kBuildKeyModel, stored[0] != 0 || s_pendingKey[0] != 0)) {
          Serial.println("[prov] refused: no miner key - set it with the web setup page (USB) or app>=0.4");
          s_fsm.feed(fry::ProvEvent::KeyMissing, in);
          updateStatusChar();
          return;
        }
        if (s_pendingKey[0]) {
          const fry::KeyWriteVerdict verdict =
              fry_identity::setOwnerKey(s_pendingKey, fry::KeyTransport::Ble, nullptr);
          memset(s_pendingKey, 0, sizeof(s_pendingKey));
          if (verdict != fry::KeyWriteVerdict::Accept) {
            rejectKey(verdict);  // nothing persisted: no Wi-Fi, no wallet
            updateStatusChar();
            return;
          }
        }
      }
      // Commit semantics per PROTOCOL.md section 1: writing WALLET commits provisioning.
      // Persist BEFORE the FSM reports Connecting: loop() on the other core polls
      // readyToConnect() and reads the credentials back from NVS immediately, so feeding the
      // event first raced it into WiFi.begin("") ("SSID too long or missing").
      fry::commitOnWallet(s_fsm, in, [&]() {
        fry_config::setWifi(s_pendingSsid, s_pendingPass);
        fry_config::setWallet(wallet);
      });
      updateStatusChar();
    }
  }
};

ProvCallbacks s_callbacks;

class ServerCallbacks : public NimBLEServerCallbacks {
 public:
  void onConnect(NimBLEServer* server, NimBLEConnInfo& connInfo) override {
    (void)server;
    (void)connInfo;
    clearStagedKey();
    s_loggedUntrusted = false;
  }
  void onDisconnect(NimBLEServer* server, NimBLEConnInfo& connInfo, int reason) override {
    (void)server;
    (void)connInfo;
    (void)reason;
    clearStagedKey();
    // NimBLE-Arduino 2.x does not advertise again by itself. Advertise again only while the board
    // can still be provisioned: a Connected board stays quiet, as before, since 05 is readable.
    if (s_fsm.state() != fry::ProvState::Connected) NimBLEDevice::startAdvertising();
  }
};

ServerCallbacks s_serverCallbacks;

}  // namespace

void init(const char* deviceName, const char* minerKey) {
  NimBLEDevice::init(deviceName);
  NimBLEDevice::setMTU(185);  // PROTOCOL.md section 1: the central requests MTU 185
  // PROTOCOL.md sections 11.3/11.8/11.9: the key write (09) needs an encrypted link - LE Secure
  // Connections, Just Works, no bonding - which the client sets up by pairing before it writes 09.
  // Nothing else on the service requires it, so an app that never writes a key is never asked to pair.
  NimBLEDevice::setSecurityAuth(/*bonding=*/false, /*mitm=*/false, /*sc=*/true);
  NimBLEDevice::setSecurityIOCap(BLE_HS_IO_NO_INPUT_OUTPUT);
  // sc=true only PREFERS Secure Connections; a central proposing legacy Just Works (TK = 0) would
  // otherwise get a passively decryptable link. Refuse legacy pairing outright (round 2 F5).
  ble_hs_cfg.sm_sc_only = 1;

  NimBLEServer* server = NimBLEDevice::createServer();
  server->setCallbacks(&s_serverCallbacks);
  NimBLEService* service = server->createService(kServiceUuid);

  s_chSsid = service->createCharacteristic(kUuidSsid, NIMBLE_PROPERTY::WRITE);
  s_chPass = service->createCharacteristic(kUuidPass, NIMBLE_PROPERTY::WRITE);
  // NimBLE reassembles long/prepared writes transparently before onWrite fires, so the 58-byte
  // wallet value arrives whole in getValue() even if the central's MTU request failed and it
  // fell back to a queued prepared write (PROTOCOL.md section 1, MTU).
  s_chWallet = service->createCharacteristic(kUuidWallet, NIMBLE_PROPERTY::WRITE);
  s_chSsid->setCallbacks(&s_callbacks);
  s_chPass->setCallbacks(&s_callbacks);
  s_chWallet->setCallbacks(&s_callbacks);

  NimBLECharacteristic* chName = service->createCharacteristic(kUuidDeviceName, NIMBLE_PROPERTY::READ);
  chName->setValue(deviceName);

  // Round 2 F6 (PROTOCOL.md 11.8): plain READ with the full key, as in v1, so app 0.3.x - which
  // reads 05 first with a 5 s timeout - is never stopped by a pairing prompt. The key WRITE (09)
  // stays encrypted.
  s_chKey = service->createCharacteristic(kUuidMinerKey, NIMBLE_PROPERTY::READ);
  s_chKey->setValue(minerKey ? minerKey : "");  // "" without a key; refreshed on every read
  s_chKey->setCallbacks(&s_callbacks);

  s_chStatus = service->createCharacteristic(kUuidStatus, NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::NOTIFY);
  updateStatusChar();

  NimBLECharacteristic* chFw = service->createCharacteristic(kUuidFwVer, NIMBLE_PROPERTY::READ);
  chFw->setValue(FRY_FIRMWARE_VERSION);

  NimBLECharacteristic* chChip = service->createCharacteristic(kUuidChip, NIMBLE_PROPERTY::READ);
  chChip->setValue(FRY_CHIP);

  // v1.1, appended after the v1 characteristics so their order is unchanged. Plain WRITE (11.9):
  // in Secure Connections Only mode NimBLE refuses any attribute that needs security unless the
  // link is authenticated (MITM), which Just Works never is, so a WRITE_ENC 09 could not be
  // written at all. onWrite refuses the key on an unencrypted link instead.
  s_chKeyWrite = service->createCharacteristic(kUuidKeyWrite, NIMBLE_PROPERTY::WRITE);
  s_chKeyWrite->setCallbacks(&s_callbacks);
  s_chDevStatus = service->createCharacteristic(kUuidDevStatus,
                                                NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::NOTIFY);
  s_chDevStatus->setCallbacks(&s_callbacks);
  setDevStatusValue();

  // NimBLEService::start() is deprecated in NimBLE-Arduino 2.5.x — services now start
  // automatically when the server starts (implicitly, on the first advertising start below).

  // Name+UUID together exceed the 31-byte advertisement budget, so the 128-bit service UUID
  // goes in the ADVERTISEMENT and the device name goes in the SCAN RESPONSE (section 1).
  NimBLEAdvertisementData advData;
  advData.setFlags(0x06);  // LE General Discoverable + BR/EDR not supported
  advData.addServiceUUID(kServiceUuid);

  NimBLEAdvertisementData scanData;
  scanData.setName(deviceName);

  NimBLEAdvertising* advertising = NimBLEDevice::getAdvertising();
  advertising->setAdvertisementData(advData);
  advertising->setScanResponseData(scanData);
  advertising->enableScanResponse(true);
  advertising->start();

  Serial.printf("BLE advertising name=%s svc=465259\n", deviceName);
}

bool commitWifiOnlyCredentials(const char* ssid, const char* pass) {
  if (!ssid) return false;
  // A previous join failed and parked the FSM in Error, or the board is already running on settings
  // committed earlier this boot (Connected / Connecting): an Improv client starts over either way
  // (round 2 F8). Only this entry point does it — the app-facing paths behave exactly as before.
  fry::resetForWifiOnlyCommit(s_fsm);

  const size_t ssidLen = strlen(ssid);
  fry::ProvInputs in;
  in.ssidValid = (ssidLen >= 1 && ssidLen <= 32);
  s_fsm.feed(fry::ProvEvent::SsidWritten, in);
  if (!in.ssidValid) {
    updateStatusChar();
    return false;
  }

  fry::commitWifiOnly(s_fsm, [&]() {
    fry_config::setWifi(ssid, pass ? pass : "");
    fry_config::setProvDone();  // no wallet to stand in for "committed" on this path
  });
  updateStatusChar();
  return s_fsm.readyToConnect();
}

void loop() {
  // NimBLE services connections on its own host task; nothing to pump here.
}

fry::ProvState state() { return s_fsm.state(); }
fry::ProvErr lastError() { return s_fsm.error(); }
bool readyToConnect() { return s_fsm.readyToConnect(); }

void notifyWifiUp() {
  s_fsm.feed(fry::ProvEvent::WifiUp, {});
  updateStatusChar();
}
void notifyWifiAuthFail() {
  s_fsm.feed(fry::ProvEvent::WifiAuthFail, {});
  updateStatusChar();
}
void notifyWifiNoIp() {
  s_fsm.feed(fry::ProvEvent::WifiNoIp, {});
  updateStatusChar();
}
void notifyApiOk() {
  s_fsm.feed(fry::ProvEvent::ApiOk, {});
  updateStatusChar();
  // Advertising restarted after a handoff disconnect (onDisconnect) ends once the board is Connected.
  NimBLEServer* server = NimBLEDevice::getServer();
  if (s_fsm.state() == fry::ProvState::Connected && server && server->getConnectedCount() == 0) {
    NimBLEDevice::stopAdvertising();
  }
}
void notifyApiFail(fry::ProvErr detail) {
  fry::ProvInputs in;
  in.detail = detail;
  s_fsm.feed(fry::ProvEvent::ApiFail, in);
  updateStatusChar();
}
void notifyKeyMissing() {
  s_fsm.feed(fry::ProvEvent::KeyMissing, {});
  updateStatusChar();
}

void tick() {
  // No mandated teardown for BLE in PROTOCOL.md (section 3's AP-teardown rule is ESP8266-only).
  // The link is never dropped from this side either: the app holds it until Connected + 5 s
  // (section 11.3) and disconnects itself.
}

}  // namespace fry_provisioning
