#include "miner_key.h"

#include "fry_config.h"
#include "miner_identity.h"

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

const char* chipTag() {
#if defined(FRY_CHIP)
  return FRY_CHIP;
#else
  return "UNKNOWN";
#endif
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
  if (fry_config::getMinerKey(outKey, outKeyLen)) {
    return;  // already generated — never regenerate (PROTOCOL.md section 4)
  }

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

void getDeviceName(char* outName, size_t outNameLen) {
  uint8_t mac6[3];
  getMac6(mac6);
  fry::formatDeviceName(chipTag(), mac6, outName, outNameLen);
}

}  // namespace fry_identity
