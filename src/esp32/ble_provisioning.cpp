// BLE GATT provisioning transport for ESP32 / ESP32-S3 / ESP32-C3. PROTOCOL.md section 1.
#include "../core/provisioning_transport.h"

#include <NimBLEDevice.h>

#include <cstring>

#include "../core/fry_config.h"

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

fry::ProvisioningFsm s_fsm;

NimBLECharacteristic* s_chSsid = nullptr;
NimBLECharacteristic* s_chPass = nullptr;
NimBLECharacteristic* s_chWallet = nullptr;
NimBLECharacteristic* s_chStatus = nullptr;

char s_pendingSsid[33] = {0};
char s_pendingPass[65] = {0};

void updateStatusChar() {
  if (!s_chStatus) return;
  uint8_t buf[2];
  buf[0] = static_cast<uint8_t>(s_fsm.state());
  size_t len = 1;
  if (s_fsm.state() == fry::ProvState::Error) {
    buf[1] = static_cast<uint8_t>(s_fsm.error());
    len = 2;
  }
  s_chStatus->setValue(buf, len);
  s_chStatus->notify();
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
  void onWrite(NimBLECharacteristic* ch, NimBLEConnInfo& connInfo) override {
    (void)connInfo;
    if (ch == s_chSsid) {
      size_t rawLen = 0;
      copyAttrValue(ch, s_pendingSsid, sizeof(s_pendingSsid), &rawLen);
      fry::ProvInputs in;
      in.ssidValid = (rawLen >= 1 && rawLen <= 32);
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
      bool changed = s_fsm.feed(fry::ProvEvent::WalletWritten, in);
      if (changed && s_fsm.state() == fry::ProvState::Connecting) {
        // Commit semantics per PROTOCOL.md section 1: writing WALLET commits provisioning.
        fry_config::setWifi(s_pendingSsid, s_pendingPass);
        fry_config::setWallet(wallet);
      }
      updateStatusChar();
    }
  }
};

ProvCallbacks s_callbacks;

}  // namespace

void init(const char* deviceName, const char* minerKey) {
  NimBLEDevice::init(deviceName);
  NimBLEDevice::setMTU(185);  // PROTOCOL.md section 1: the central requests MTU 185

  NimBLEServer* server = NimBLEDevice::createServer();
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

  NimBLECharacteristic* chKey = service->createCharacteristic(kUuidMinerKey, NIMBLE_PROPERTY::READ);
  chKey->setValue(minerKey);

  s_chStatus = service->createCharacteristic(kUuidStatus, NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::NOTIFY);
  updateStatusChar();

  NimBLECharacteristic* chFw = service->createCharacteristic(kUuidFwVer, NIMBLE_PROPERTY::READ);
  chFw->setValue(FRY_FIRMWARE_VERSION);

  NimBLECharacteristic* chChip = service->createCharacteristic(kUuidChip, NIMBLE_PROPERTY::READ);
  chChip->setValue(FRY_CHIP);

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
}
void notifyApiFail() {
  s_fsm.feed(fry::ProvEvent::ApiFail, {});
  updateStatusChar();
}

void tick() {
  // No mandated teardown for BLE in PROTOCOL.md (section 3's AP-teardown rule is ESP8266-only).
}

}  // namespace fry_provisioning
