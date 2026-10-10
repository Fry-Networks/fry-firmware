#pragma once
// T8: Preferences::getString logs an [E] "nvs_get_str len fail: <key> NOT_FOUND" when the key does
// not exist, so an expected state (a board that has no VPN config yet) must never read the key.
// Header-only and templated so a native test can drive it with a fake store.
#include <cstddef>

namespace fry {

template <class Str, class Store>
Str kvGetStringIfKey(Store& store, const char* key) {
  if (!store.isKey(key)) return Str("");
  return store.getString(key, "");
}

// Preferences::begin(ns, readOnly=true) on a namespace that was never written logs an [E]
// "nvs_open failed: NOT_FOUND". A board with no VPN config has no fry_vpn namespace, so the read
// is skipped (and the store never opened) unless `nsExists(ns)` says it is there. nsExists must
// probe without logging and without writing flash (nvs_open READONLY, not a read-write open).
template <class Str, class Store, class NsExistsFn>
Str kvGetStringGuarded(NsExistsFn nsExists, Store& store, const char* ns, const char* key) {
  if (!nsExists(ns)) return Str("");
  store.begin(ns, true);
  Str v = kvGetStringIfKey<Str>(store, key);
  store.end();
  return v;
}

// Reads `key` as a C string into out/outLen only when the namespace AND the key exist (a raw
// Preferences::getString(key, char*, len) logs [E] for a missing key). Returns whether it was read.
template <class Store, class NsExistsFn>
bool kvGetCStringGuarded(NsExistsFn nsExists, Store& store, const char* ns, const char* key, char* out, size_t outLen) {
  if (!nsExists(ns)) return false;
  store.begin(ns, true);
  const bool has = store.isKey(key);
  if (has) store.getString(key, out, outLen);
  store.end();
  return has;
}

// Generic optional read: `def` when the namespace or the key is absent, else read(store). The store
// is not even opened for a missing namespace (Preferences::begin(ns, true) logs [E] NOT_FOUND).
template <class T, class Store, class NsExistsFn, class ReadFn>
T kvReadGuarded(NsExistsFn nsExists, Store& store, const char* ns, const char* key, T def, ReadFn read) {
  if (!nsExists(ns)) return def;
  store.begin(ns, true);
  T v = store.isKey(key) ? read(store) : def;
  store.end();
  return v;
}

// True exactly once: for a log line that states an expected condition (T8: "no VPN config").
class OnceFlag {
 public:
  bool first() {
    if (done_) return false;
    done_ = true;
    return true;
  }

 private:
  bool done_ = false;
};

}  // namespace fry
