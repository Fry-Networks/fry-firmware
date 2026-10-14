// GATT characteristic 4652590b: the app's Olostep opt-in write (1 byte, 0x00 off / 0x01 on).
// ON is a consent action, so it is accepted only from an encrypted link (the same rule as the
// owner-key write); OFF is accepted from any link. Empty unless FRY_HAS_OLOSTEP.
#include "../core/olostep_exec.h"

#if FRY_HAS_OLOSTEP && !defined(ARDUINO_ARCH_ESP8266)

#include <Arduino.h>
#include <NimBLEDevice.h>

#include "olostep_optin.h"

namespace {
const char* kUuidOlostepOptIn = "4652590b-0001-4000-8000-4652594e4554";
NimBLECharacteristic* s_chOlostepOptIn = nullptr;
}  // namespace

void fry_olostep_ble_create(NimBLEService* service, NimBLECharacteristicCallbacks* callbacks) {
  s_chOlostepOptIn = service->createCharacteristic(kUuidOlostepOptIn, NIMBLE_PROPERTY::WRITE);
  s_chOlostepOptIn->setCallbacks(callbacks);
}

bool fry_olostep_ble_handle_write(NimBLECharacteristic* ch, NimBLEConnInfo& connInfo) {
  if (ch == nullptr || ch != s_chOlostepOptIn) return false;
  const NimBLEAttValue v = ch->getValue();
  switch (fry_olostep::olostepOptInWrite(v.data(), v.size(), connInfo.isEncrypted())) {
    case fry_olostep::OptInWrite::SetOn:
      setOlostepOptIn(true);
      fry_olostep_optin_changed();
      Serial.println("[prov] olostep opt-in: ON");
      break;
    case fry_olostep::OptInWrite::SetOff:
      setOlostepOptIn(false);
      fry_olostep_optin_changed();
      Serial.println("[prov] olostep opt-in: OFF");
      break;
    case fry_olostep::OptInWrite::Ignore:
      Serial.println("[prov] olostep opt-in write ignored (ON needs an encrypted link)");
      break;
  }
  return true;
}

#endif
