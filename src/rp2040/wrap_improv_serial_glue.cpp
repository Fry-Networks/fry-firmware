// Built only by the Pico / BK7231N envs (platformio.boards.ini defines FRY_BOARDS_PORT); the ESP envs compile all of src/.
#if defined(FRY_BOARDS_PORT)
// src/core/improv_serial_glue.cpp for arduino-pico, unchanged, behind a small forwarding object: the glue scans with the ESP32-style
// WiFi calls (scanNetworks(async, showHidden), String SSID(i), WIFI_AUTH_OPEN), arduino-pico's scan API has the ESP8266 shapes
// (scanNetworks(async), const char* SSID(i), ENC_TYPE_NONE). Only this translation unit sees the macro.
#include <Arduino.h>
#include <WiFi.h>

namespace {
struct FryPicoWifiScanCompat {
  WiFiMode_t getMode() { return WiFi.getMode(); }
  void mode(WiFiMode_t m) { WiFi.mode(m); }
  int scanNetworks(bool async, bool /*showHidden*/) { return WiFi.scanNetworks(async); }
  int scanComplete() { return WiFi.scanComplete(); }
  void scanDelete() { WiFi.scanDelete(); }
  String SSID(int i) { return String(WiFi.SSID(static_cast<uint8_t>(i))); }
  int32_t RSSI(int i) { return WiFi.RSSI(static_cast<uint8_t>(i)); }
  uint8_t encryptionType(int i) { return WiFi.encryptionType(static_cast<uint8_t>(i)); }
};
FryPicoWifiScanCompat fry_pico_wifi_scan;
}  // namespace

#define WiFi fry_pico_wifi_scan
#define WIFI_AUTH_OPEN ENC_TYPE_NONE
#include "../core/improv_serial_glue.cpp"
#endif  // FRY_BOARDS_PORT
