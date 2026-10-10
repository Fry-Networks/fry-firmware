#pragma once
// T8: Preferences::getString logs an [E] "nvs_get_str len fail: <key> NOT_FOUND" when the key does
// not exist, so an expected state (a board that has no VPN config yet) must never read the key.
// Header-only and templated so a native test can drive it with a fake store.
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
