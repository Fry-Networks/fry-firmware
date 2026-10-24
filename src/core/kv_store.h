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

#include "nvs_absent.h"

// Preferences plus the one thing NVS needs on this firmware. A READ-ONLY begin() of a namespace
// that does not exist yet makes ESP-IDF log "[E][Preferences.cpp:50] begin(): nvs_open failed:
// NOT_FOUND" on every call, and a namespace that is only created at provisioning time (fry_vpn on
// any board that has not provisioned WireGuard) is polled once per loop pass: 4326 lines in 54 s in
// capture e32-a3b-224212. lib/fry_core/nvs_absent.h remembers the namespaces NVS has answered
// NOT_FOUND for and this class skips the open, so that line is paid once per namespace instead of
// once per pass. Every successful begin() and every write forgets the namespace again, so a
// namespace that appears later is read normally on the very next pass.
//
// Everything else forwards to Preferences unchanged; when begin() did not start (including the
// skipped-open case) the getters return their defaults exactly as an unopened Preferences does.
class NvsStore {
 public:
  bool begin(const char* name, bool readOnly = false) {
    started_ = false;
    name_ = nullptr;
    if (name == nullptr) return false;
    if (readOnly && absent().isAbsent(name)) return false;  // known absent: no ESP-IDF open at all
    started_ = prefs_.begin(name, readOnly);
    if (started_) {
      name_ = name;
      absent().notePresent(name);  // a successful open proves the namespace exists
    } else if (readOnly) {
      absent().noteAbsent(name);  // logged by ESP-IDF once, then skipped from now on
    }
    return started_;
  }
  void end() {
    prefs_.end();
    started_ = false;
    name_ = nullptr;
  }

  bool clear() {
    noteWritten();
    return prefs_.clear();
  }
  bool remove(const char* key) {
    noteWritten();
    return prefs_.remove(key);
  }

  size_t putUChar(const char* key, uint8_t value) {
    noteWritten();
    return prefs_.putUChar(key, value);
  }
  size_t putUInt(const char* key, uint32_t value) {
    noteWritten();
    return prefs_.putUInt(key, value);
  }
  size_t putBool(const char* key, bool value) {
    noteWritten();
    return prefs_.putBool(key, value);
  }
  size_t putString(const char* key, const char* value) {
    noteWritten();
    return prefs_.putString(key, value);
  }
  size_t putString(const char* key, String value) {
    noteWritten();
    return prefs_.putString(key, value);
  }
  size_t putBytes(const char* key, const void* value, size_t len) {
    noteWritten();
    return prefs_.putBytes(key, value, len);
  }

  bool isKey(const char* key) { return started_ && prefs_.isKey(key); }
  uint8_t getUChar(const char* key, uint8_t defaultValue = 0) {
    return started_ ? prefs_.getUChar(key, defaultValue) : defaultValue;
  }
  uint32_t getUInt(const char* key, uint32_t defaultValue = 0) {
    return started_ ? prefs_.getUInt(key, defaultValue) : defaultValue;
  }
  bool getBool(const char* key, bool defaultValue = false) {
    return started_ ? prefs_.getBool(key, defaultValue) : defaultValue;
  }
  size_t getString(const char* key, char* value, size_t maxLen) {
    return started_ ? prefs_.getString(key, value, maxLen) : 0;
  }
  String getString(const char* key, String defaultValue = String()) {
    return started_ ? prefs_.getString(key, defaultValue) : defaultValue;
  }
  size_t getBytesLength(const char* key) { return started_ ? prefs_.getBytesLength(key) : 0; }
  size_t getBytes(const char* key, void* buf, size_t maxLen) {
    return started_ ? prefs_.getBytes(key, buf, maxLen) : 0;
  }

  // The absence memory is process-wide: every store instance writes the same NVS.
  static fry::NvsAbsentCache& absent() {
    static fry::NvsAbsentCache cache;
    return cache;
  }

 private:
  // A write means the namespace exists from now on (nvs_open READWRITE creates it), so drop any
  // remembered absence before the call rather than after: if the call fails, the next read simply
  // pays one open and re-learns the absence.
  void noteWritten() {
    if (started_ && name_ != nullptr) absent().notePresent(name_);
  }

  Preferences prefs_;
  const char* name_ = nullptr;
  bool started_ = false;
};

using KvStore = NvsStore;
#endif
