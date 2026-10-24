#pragma once
// Namespace-absence memory for the NVS-backed KvStore (src/core/kv_store.h).
//
// Why this exists: on the ESP32 family Preferences::begin() is nvs_open(), and opening a namespace
// that does not exist yet makes ESP-IDF log
//   [E][Preferences.cpp:50] begin(): nvs_open failed: NOT_FOUND
// on EVERY call. A polled read of a namespace that is only created at provisioning time - exactly
// the shape of fry_config::hasVpnConfig(), reached from fry_vpn::tick() on every loop pass - so
// turns the serial console into a flood: measured on capture e32-a3b-224212, 4326 such lines in
// 54 s (t=233..54012 ms, ~12 ms apart = one per loop pass) on a board whose NVS held only
// cal_data/nimble_bond/fry_wifi/fry.
//
// The store therefore remembers which namespaces NVS has answered NOT_FOUND for and skips the open
// on a READ-ONLY begin() until that namespace is written. Presence is re-learned by every
// successful begin() (nvs_open in READWRITE creates the namespace, so a writable begin that
// succeeds proves it) and by every write, so no caller has to remember to invalidate anything, and
// a namespace that appears later is read normally on the very next pass. Fails open: an unknown
// name is never treated as absent, so a missed invalidation costs one open, never a hidden value.
//
// Pure C++ (no Arduino, no NVS) so `pio test -e native` pins the rule instead of a comment.
// Fixed capacity, no allocation: at most kCapacity namespaces are remembered, each up to
// kMaxNameLen-1 characters. A longer (or empty) name is simply not cached, which leaves that call
// behaving exactly as it did before this cache existed.
#include <cstddef>
#include <cstring>

namespace fry {

class NvsAbsentCache {
 public:
  enum { kCapacity = 8, kMaxNameLen = 24 };

  // True when `name` is remembered as absent, i.e. the caller must not pay for an open.
  bool isAbsent(const char* name) const { return find(name) >= 0; }

  // Remember that NVS answered NOT_FOUND for `name`. Idempotent; evicts round-robin when full, so
  // a run of distinct namespaces cannot grow this past kCapacity.
  void noteAbsent(const char* name) {
    if (name == nullptr) return;
    const size_t len = std::strlen(name);
    if (len == 0 || len >= static_cast<size_t>(kMaxNameLen)) return;  // not cacheable
    int i = find(name);
    if (i < 0) {
      i = next_;
      next_ = (next_ + 1) % kCapacity;
      if (!used_[i]) ++size_;
      used_[i] = true;
    }
    std::memcpy(names_[i], name, len + 1);
  }

  // Forget `name`: it exists now (a begin() succeeded, or something wrote it).
  void notePresent(const char* name) {
    const int i = find(name);
    if (i < 0) return;
    used_[i] = false;
    names_[i][0] = '\0';
    --size_;
  }

  void reset() {
    for (int i = 0; i < kCapacity; ++i) {
      used_[i] = false;
      names_[i][0] = '\0';
    }
    size_ = 0;
    next_ = 0;
  }

  int size() const { return size_; }

 private:
  int find(const char* name) const {
    if (name == nullptr || name[0] == '\0') return -1;
    for (int i = 0; i < kCapacity; ++i) {
      if (used_[i] && std::strcmp(names_[i], name) == 0) return i;
    }
    return -1;
  }

  char names_[kCapacity][kMaxNameLen] = {};
  bool used_[kCapacity] = {};
  int size_ = 0;
  int next_ = 0;
};

}  // namespace fry
