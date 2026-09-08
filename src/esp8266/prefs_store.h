#pragma once
// PrefsStore — Preferences-compatible key-value store on LittleFS, ESP8266 only.
// ESP8266 Arduino core ships no Preferences/NVS class, so fry_config.cpp uses this on ESP8266
// and the native Preferences class on ESP32/S3/C3, behind the same method names. One JSON file
// per namespace (/fry_ns_<name>.json); binary values are base64-encoded.
// Ported from the sensmos-firmware PrefsStore (hardware-proven crash-safe atomic writes).
#include <Arduino.h>

class PrefsStore {
 public:
  bool begin(const char* ns, bool readOnly = false);
  void end();

  String getString(const char* key, const String& defaultValue = "");
  size_t getString(const char* key, char* value, size_t maxLen);
  size_t putString(const char* key, const char* value);
  size_t putString(const char* key, const String& value) { return putString(key, value.c_str()); }

  bool getBool(const char* key, bool defaultValue = false);
  size_t putBool(const char* key, bool value);
  int32_t getInt(const char* key, int32_t defaultValue = 0);
  size_t putInt(const char* key, int32_t value);
  uint32_t getUInt(const char* key, uint32_t defaultValue = 0);
  size_t putUInt(const char* key, uint32_t value);
  uint8_t getUChar(const char* key, uint8_t defaultValue = 0);
  size_t putUChar(const char* key, uint8_t value);

  size_t getBytes(const char* key, void* buf, size_t maxLen);
  size_t putBytes(const char* key, const void* value, size_t len);
  size_t getBytesLength(const char* key);

  bool isKey(const char* key);
  bool remove(const char* key);
  bool clear();

 private:
  char _path[48] = {0};
  bool _open = false;
  bool _readOnly = false;
  bool _dirty = false;
  void* _doc = nullptr;  // JsonDocument* (kept opaque to avoid pulling ArduinoJson into every TU)
  bool load();
  bool save();
};
