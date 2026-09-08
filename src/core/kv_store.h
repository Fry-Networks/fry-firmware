#pragma once
// Chip-agnostic key-value store alias. ESP32/S3/C3 use the native NVS-backed Preferences
// class; ESP8266 (no Preferences in its Arduino core) uses the LittleFS-JSON port in
// src/esp8266/prefs_store.h. Both expose the same method names, so src/core/fry_config.cpp
// does not need any #ifdef beyond this one header.
#if defined(ARDUINO_ARCH_ESP8266)
#include "../esp8266/prefs_store.h"
using KvStore = PrefsStore;
#else
#include <Preferences.h>
using KvStore = Preferences;
#endif
