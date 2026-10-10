// Keeps a freshly OTA'd image PENDING_VERIFY past arduino-esp32's initArduino(), which otherwise
// marks every running image valid before setup() ever runs and so defeats the bootloader's app
// rollback. src/core/ota_client.cpp marks it valid on the first hardwareapi answer and rolls it back
// when none arrives (see lib/fry_core/ota_health.h). ESP32 family only: platformio.ini keeps
// src/esp32/ out of the ESP8266 build, whose core has no such hook.
#include <Arduino.h>

extern "C" bool verifyRollbackLater() { return true; }
