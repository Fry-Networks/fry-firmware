#pragma once
// Preferences-compatible key-value store for the boards that have no NVS (RP2040/RP2350: LittleFS, BK7231N: FlashDB). src/core/
// kv_store.h wraps `Preferences` for every non-ESP8266 chip; the shim Preferences.h in src/<plat>/shim makes that name this class,
// so src/core/fry_config.cpp and the hardwareapi client run unchanged. One blob per "<namespace>.<key>" (lib/fry_core/kv_map.h).
//
// Backend contract (all static, single-threaded use from loop()):
//   bool mount();                                   // once; formats a blank volume
//   int  size(const char* flat);                    // blob length, -1 absent
//   int  read(const char* flat, uint8_t*, size_t);  // bytes read, -1 absent
//   bool write(const char* flat, const uint8_t*, size_t);  // all or nothing: a reset mid-write leaves the old or the new blob
//   bool erase(const char* flat);
//   void each(void (*cb)(const char* flat, void* ctx), void* ctx);
#include <Arduino.h>

#include <stdlib.h>

#include "kv_map.h"

namespace fry_boards {

constexpr size_t kMaxBlob = 1024;

template <class B>
class PreferencesT {
 public:
  bool begin(const char* name, bool readOnly = false) {
    open_ = false;
    if (!fry::kv::validName(name)) return false;
    if (!B::mount()) return false;
    strncpy(ns_, name, sizeof(ns_) - 1);
    ns_[sizeof(ns_) - 1] = '\0';
    ro_ = readOnly;
    open_ = true;
    return true;
  }
  void end() { open_ = false; }

  bool clear() {
    if (!open_ || ro_) return false;
    // Collect first, erase after: erasing while a backend iterates would invalidate its cursor.
    struct Ctx {
      const char* ns;
      char names[24][fry::kv::kFlatMax];
      int n;
    } ctx;
    ctx.ns = ns_;
    ctx.n = 0;
    B::each(
        [](const char* flat, void* c) {
          Ctx* x = static_cast<Ctx*>(c);
          if (x->n < 24 && fry::kv::inNamespace(flat, x->ns)) {
            strncpy(x->names[x->n], flat, fry::kv::kFlatMax - 1);
            x->names[x->n][fry::kv::kFlatMax - 1] = '\0';
            x->n++;
          }
        },
        &ctx);
    bool ok = true;
    for (int i = 0; i < ctx.n; i++) ok = B::erase(ctx.names[i]) && ok;
    return ok;
  }
  bool remove(const char* key) {
    char flat[fry::kv::kFlatMax];
    if (!open_ || ro_ || !mk(key, flat)) return false;
    return B::erase(flat);
  }

  size_t putUChar(const char* key, uint8_t v) { return putRaw(key, &v, 1); }
  size_t putBool(const char* key, bool v) { return putUChar(key, v ? 1 : 0); }
  size_t putUInt(const char* key, uint32_t v) {
    uint8_t b[4];
    fry::kv::encodeU32(v, b);
    return putRaw(key, b, 4);
  }
  size_t putString(const char* key, const char* value) {
    if (!value) return 0;
    const size_t n = strlen(value) + 1;
    if (n > kMaxBlob) return 0;
    return putRaw(key, reinterpret_cast<const uint8_t*>(value), n) ? n - 1 : 0;
  }
  size_t putString(const char* key, String value) { return putString(key, value.c_str()); }
  size_t putBytes(const char* key, const void* value, size_t len) {
    if (!value || len > kMaxBlob) return 0;
    return putRaw(key, static_cast<const uint8_t*>(value), len);
  }

  bool isKey(const char* key) {
    char flat[fry::kv::kFlatMax];
    return open_ && mk(key, flat) && B::size(flat) >= 0;
  }
  uint8_t getUChar(const char* key, uint8_t def = 0) {
    uint8_t v;
    return getRaw(key, &v, 1) == 1 ? v : def;
  }
  bool getBool(const char* key, bool def = false) { return getUChar(key, def ? 1 : 0) != 0; }
  uint32_t getUInt(const char* key, uint32_t def = 0) {
    uint8_t b[4];
    return getRaw(key, b, 4) == 4 ? fry::kv::decodeU32(b, 4, def) : def;
  }
  size_t getString(const char* key, char* value, size_t maxLen) {
    if (!value || maxLen == 0) return 0;
    value[0] = '\0';
    uint8_t* blob = static_cast<uint8_t*>(malloc(kMaxBlob));
    if (!blob) return 0;
    const int n = getRaw(key, blob, kMaxBlob);
    size_t got = 0;
    if (n > 0) got = fry::kv::decodeString(blob, static_cast<size_t>(n), value, maxLen);
    free(blob);
    return got;
  }
  String getString(const char* key, String def = String()) {
    uint8_t* blob = static_cast<uint8_t*>(malloc(kMaxBlob + 1));
    if (!blob) return def;
    const int n = getRaw(key, blob, kMaxBlob);
    String out = def;
    if (n > 0) {
      blob[n] = 0;
      out = String(reinterpret_cast<const char*>(blob));
    }
    free(blob);
    return out;
  }
  size_t getBytesLength(const char* key) {
    char flat[fry::kv::kFlatMax];
    if (!open_ || !mk(key, flat)) return 0;
    const int n = B::size(flat);
    return n < 0 ? 0 : static_cast<size_t>(n);
  }
  size_t getBytes(const char* key, void* buf, size_t maxLen) {
    const int n = getRaw(key, static_cast<uint8_t*>(buf), maxLen);
    return n < 0 ? 0 : static_cast<size_t>(n);
  }

 private:
  bool mk(const char* key, char* flat) const { return fry::kv::flatKey(ns_, key, flat, fry::kv::kFlatMax); }
  size_t putRaw(const char* key, const uint8_t* v, size_t n) {
    char flat[fry::kv::kFlatMax];
    if (!open_ || ro_ || !mk(key, flat)) return 0;
    return B::write(flat, v, n) ? n : 0;
  }
  int getRaw(const char* key, uint8_t* out, size_t cap) {
    char flat[fry::kv::kFlatMax];
    if (!open_ || !mk(key, flat)) return -1;
    return B::read(flat, out, cap);
  }

  char ns_[16] = {0};
  bool open_ = false;
  bool ro_ = false;
};

}  // namespace fry_boards
