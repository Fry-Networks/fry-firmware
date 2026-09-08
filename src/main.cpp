// Fry device firmware — entry point.
// T1: boot banner only. Provisioning / networking / VPN / OTA are wired in by later tasks.
#include <Arduino.h>
#if defined(ARDUINO_ARCH_ESP8266)
#include <ESP8266WiFi.h>
#elif defined(ARDUINO_ARCH_ESP32)
#include <esp_mac.h>
#endif
#include "config.h"

#ifndef FRY_FIRMWARE_VERSION
#define FRY_FIRMWARE_VERSION "0.0.0-dev"
#endif
#ifndef FRY_CHIP
#define FRY_CHIP "UNKNOWN"
#endif

static void print_mac(char* out, size_t outLen) {
#if defined(ESP32)
  uint8_t mac[6];
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  snprintf(out, outLen, "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
#else
  uint8_t mac[6];
  WiFi.macAddress(mac);
  snprintf(out, outLen, "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
#endif
}

void setup() {
  Serial.begin(115200);
  delay(200);

  char mac[18] = "00:00:00:00:00:00";
#if defined(ARDUINO_ARCH_ESP32) || defined(ARDUINO_ARCH_ESP8266)
  print_mac(mac, sizeof(mac));
#endif

  Serial.printf("FRY boot v%s chip=%s mac=%s minerkey=IOT-PENDING\n",
                FRY_FIRMWARE_VERSION, FRY_CHIP, mac);
  Serial.println("[boot] ready");
}

void loop() {}
