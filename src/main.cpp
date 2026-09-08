// Fry device firmware — entry point.
#include <Arduino.h>
#if defined(ARDUINO_ARCH_ESP8266)
#include <ESP8266WiFi.h>
#else
#include <WiFi.h>
#endif
#include "config.h"
#include "core/miner_key.h"
#include "core/serial_commands.h"

#ifndef FRY_FIRMWARE_VERSION
#define FRY_FIRMWARE_VERSION "0.0.0-dev"
#endif
#ifndef FRY_CHIP
#define FRY_CHIP "UNKNOWN"
#endif

static void print_mac(char* out, size_t outLen) {
  uint8_t mac[6];
  WiFi.macAddress(mac);
  snprintf(out, outLen, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4],
           mac[5]);
}

void setup() {
  Serial.begin(115200);
  delay(200);

  char mac[18] = "00:00:00:00:00:00";
  print_mac(mac, sizeof(mac));

  char minerKey[40] = "IOT-PENDING";
  fry_identity::ensureMinerKey(minerKey, sizeof(minerKey));

  Serial.printf("FRY boot v%s chip=%s mac=%s minerkey=%s\n", FRY_FIRMWARE_VERSION, FRY_CHIP, mac,
                minerKey);

#ifdef FRY_SERIAL_PROVISION
  fry_serial_init();
#endif

  Serial.println("[boot] ready");
}

void loop() {
#ifdef FRY_SERIAL_PROVISION
  fry_serial_poll();
#endif
}
