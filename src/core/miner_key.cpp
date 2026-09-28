#include "miner_key.h"

#include <cstring>

#include "fry_config.h"
#include "miner_identity.h"
#include "sha256.h"

#if defined(ARDUINO_ARCH_ESP8266)
#include <ESP8266WiFi.h>
#else
#include <WiFi.h>
#include <esp_random.h>
#endif

namespace fry_identity {

namespace {

uint32_t hwRandom32() {
#if defined(ARDUINO_ARCH_ESP8266)
  // ESP8266 hardware RNG register (thermal-noise backed). Always active, no WiFi required —
  // salt must be generatable on the very first boot before any network config exists.
  return *reinterpret_cast<volatile uint32_t*>(0x3FF20E44);
#else
  return esp_random();
#endif
}

void generateSalt(uint8_t out[16]) {
  for (int i = 0; i < 4; i++) {
    uint32_t r = hwRandom32();
    out[i * 4 + 0] = static_cast<uint8_t>(r >> 24);
    out[i * 4 + 1] = static_cast<uint8_t>(r >> 16);
    out[i * 4 + 2] = static_cast<uint8_t>(r >> 8);
    out[i * 4 + 3] = static_cast<uint8_t>(r);
  }
}

void copyKey(char* out, size_t outLen, const char* key) {
  if (!out || outLen == 0) return;
  strncpy(out, key, outLen - 1);
  out[outLen - 1] = 0;
}

const char* chipTag() {
#if defined(FRY_CHIP)
  return FRY_CHIP;
#else
  return "UNKNOWN";
#endif
}

bool s_waitLogged = false;

const char* transportName(fry::KeyTransport t) {
  switch (t) {
    case fry::KeyTransport::Usb:
      return "usb";
    case fry::KeyTransport::Ble:
      return "ble";
    case fry::KeyTransport::SoftApSecure:
      return "softap";
    case fry::KeyTransport::SoftApOpen:
      return "open-softap";
  }
  return "?";
}

// Policy inputs from the store: is a key there, is it the same one, has hardwareapi accepted it.
fry::KeyWriteVerdict evaluate(const char* key, fry::KeyTransport transport, char* stored,
                              size_t storedLen, bool* same) {
  const bool hasKey = fry_config::getMinerKey(stored, storedLen) && stored[0];
  *same = hasKey && key && strcmp(stored, key) == 0;
  return fry::mayWriteKey(fry::kBuildKeyModel, transport, hasKey, hasKey && fry_config::getKeyOk(),
                          fry::isAcceptableOwnerKey(key), *same);
}

}  // namespace

void getMac6(uint8_t mac6[3]) {
  uint8_t mac[6];
  WiFi.macAddress(mac);
  mac6[0] = mac[3];
  mac6[1] = mac[4];
  mac6[2] = mac[5];
}

void ensureMinerKey(char* outKey, size_t outKeyLen) {
  const bool present = fry_config::getMinerKey(outKey, outKeyLen);
  const fry::BootKeyAction action = fry::decideBootKey(fry::kBuildKeyModel, present, outKey);
  if (action == fry::BootKeyAction::Wait) {
    if (outKey && outKeyLen) outKey[0] = 0;
    if (!s_waitLogged) {
      s_waitLogged = true;
      Serial.println("[identity] no miner key - waiting for the owner's FEM- key (web setup page over "
                     "USB, app >= 0.4, or the setup AP)");
    }
    return;
  }
  if (action == fry::BootKeyAction::Keep) {
    return;  // already stored - never regenerate or replace (PROTOCOL.md section 4)
  }
  if (action == fry::BootKeyAction::MigrateLegacy) {
    // A board flashed before the 2026-09-18 prefix change holds an "IOT-<hex>" key. Only the
    // namespace prefix moved, so rewrite it in place and keep the hex: same device, same
    // identity. A stored key that is neither valid nor legacy is left exactly as it is —
    // ensureMinerKey never replaces a key that exists (PROTOCOL.md section 4).
    char migrated[37];
    if (!fry::migrateLegacyMinerKey(outKey, migrated, sizeof(migrated))) {
      return;
    }
    // Write, then read back through a FRESH store handle (fry_config opens one per call, so a
    // successful read proves it reached NVS / LittleFS rather than a cached copy). One retry.
    for (int attempt = 0; attempt < 2; attempt++) {
      fry_config::setMinerKey(migrated);
      char readBack[40] = {0};
      if (fry_config::getMinerKey(readBack, sizeof(readBack)) && strcmp(readBack, migrated) == 0) {
        copyKey(outKey, outKeyLen, migrated);
        Serial.println("[identity] migrated legacy key prefix IOT- -> FEM- (hex preserved)");
        return;
      }
    }
    // The store would not take it. Run this boot on the migrated key anyway so nothing downstream
    // sees the legacy prefix; the write is attempted again on the next boot.
    copyKey(outKey, outKeyLen, migrated);
    Serial.println("[identity] legacy key migration could not be persisted - using the migrated "
                   "key for this boot, retrying on the next one");
    return;
  }

  // Mint: DEVICE_KEEPS builds only (decideBootKey never returns it for USER_SUPPLIED).
  uint8_t mac6[3];
  getMac6(mac6);

  uint8_t salt[16];
  if (!fry_config::getSalt(salt)) {
    generateSalt(salt);
    fry_config::setSalt(salt);
  }

  fry::computeMinerKey(mac6, salt, outKey, outKeyLen);
  fry_config::setMinerKey(outKey);
}

fry::KeyWriteVerdict checkOwnerKey(const char* key, fry::KeyTransport transport) {
  char stored[40] = {0};
  bool same = false;
  return evaluate(key, transport, stored, sizeof(stored), &same);
}

fry::KeyWriteVerdict setOwnerKey(const char* key, fry::KeyTransport transport, bool* changed) {
  if (changed) *changed = false;
  char stored[40] = {0};
  bool same = false;
  const fry::KeyWriteVerdict verdict = evaluate(key, transport, stored, sizeof(stored), &same);
  char masked[12];
  fry::maskMinerKey(key, masked, sizeof(masked));
  if (verdict != fry::KeyWriteVerdict::Accept) {
    Serial.printf("[identity] owner key refused via %s: %s\n", transportName(transport),
                  verdict == fry::KeyWriteVerdict::BadKey ? "bad_key" : "key_locked");
    return verdict;
  }
  if (same) return verdict;  // already the stored key: nothing to write, nothing to reset

  // Same write-then-read-back-through-a-fresh-handle rule as the legacy migration above.
  bool stored_ok = false;
  for (int attempt = 0; attempt < 2 && !stored_ok; attempt++) {
    fry_config::setMinerKey(key);
    char readBack[40] = {0};
    stored_ok = fry_config::getMinerKey(readBack, sizeof(readBack)) && strcmp(readBack, key) == 0;
  }
  if (!stored_ok) {
    Serial.printf("[identity] owner key via %s could not be persisted\n", transportName(transport));
    return fry::KeyWriteVerdict::StoreFailed;
  }
  // A different key is a different installation: the old install id, device token and WireGuard
  // peer all belong to the previous key on the server.
  fry_config::clearInstallation();
  fry_config::clearVpn();
  fry_config::setKeySrc("user");
  fry_config::setKeyOk(false);
  if (changed) *changed = true;
  Serial.printf("[identity] owner key stored via %s (%s)\n", transportName(transport), masked);
  return verdict;
}

void getDeviceName(char* outName, size_t outNameLen) {
  uint8_t mac6[3];
  getMac6(mac6);
  fry::formatDeviceName(chipTag(), mac6, outName, outNameLen);
}

void ensureInstallId(char* outId, size_t outIdLen) {
  String existing = fry_config::getInstallId();
  if (existing.length() == 32) {
    strncpy(outId, existing.c_str(), outIdLen - 1);
    outId[outIdLen - 1] = 0;
    return;
  }

  uint8_t raw[16];
  for (int i = 0; i < 4; i++) {
    uint32_t r = hwRandom32();
    raw[i * 4 + 0] = static_cast<uint8_t>(r >> 24);
    raw[i * 4 + 1] = static_cast<uint8_t>(r >> 16);
    raw[i * 4 + 2] = static_cast<uint8_t>(r >> 8);
    raw[i * 4 + 3] = static_cast<uint8_t>(r);
  }
  fry::bytesToHexUpper(raw, 16, outId, outIdLen);
  for (size_t i = 0; outId[i]; i++) {
    if (outId[i] >= 'A' && outId[i] <= 'F') outId[i] += 32;  // lowercase, cosmetic only
  }
  fry_config::setInstallId(outId);
}

}  // namespace fry_identity
