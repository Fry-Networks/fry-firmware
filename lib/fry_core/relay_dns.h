#pragma once
// Host-keyed IPv4 cache in front of the relay's name resolution (src/esp32/vpn_wireguard.cpp).
//
// The 0.4.11 relay called WiFi.hostByName() from inside its select loop, so one slow lookup stalled
// every other slot. Resolution is now a bounded asynchronous job polled once per service tick (see
// the DNS section of vpn_wireguard.cpp); this is the cache in front of it, so a repeated CONNECT to
// the same name costs no lookup at all and a name that just failed is not retried on every request.
//
// Sizes are fixed (kDnsCacheEntries) and the eviction is LRU, so the cache costs the same whatever
// the client sends. `now` is a free-running 32-bit millisecond counter (wrap-safe comparisons), as
// everywhere in fry_relay.
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace fry_relay {

constexpr int kDnsCacheEntries = 4;
constexpr size_t kDnsHostCap = 256;  // fry::Socks5ConnectRequest::host is char[256]

// DNS names are case-insensitive; the cache compares and stores them folded to lower case.
inline char dnsFoldChar(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

inline bool dnsHostEq(const char* a, const char* b) {
  while (*a != 0 && *b != 0) {
    if (dnsFoldChar(*a) != dnsFoldChar(*b)) return false;
    a++;
    b++;
  }
  return *a == *b;
}

// True once `now` has reached `at`, on a wrapping counter.
inline bool dnsReached(uint32_t now, uint32_t at) { return static_cast<int32_t>(now - at) >= 0; }

// An entry with ip == 0 is a NEGATIVE entry: the name failed to resolve at storedMs and must not be
// retried until its (shorter) ttl runs out.
struct DnsCacheEntry {
  char host[kDnsHostCap] = {0};
  uint32_t ip = 0;  // host order, bit 31 = first octet (fry::parseIpv4Cidr convention)
  uint32_t storedMs = 0;
  uint32_t ttlMs = 0;
  uint32_t usedMs = 0;  // LRU stamp, refreshed on every hit
  bool valid = false;

  bool expired(uint32_t now) const { return dnsReached(now, storedMs + ttlMs); }
};

class DnsCache {
 public:
  void reset() {
    for (int i = 0; i < kDnsCacheEntries; i++) entries_[i] = DnsCacheEntry();
  }

  // A positive, unexpired entry for `host`: fills *ip and refreshes its LRU stamp.
  bool lookup(const char* host, uint32_t now, uint32_t* ip) {
    DnsCacheEntry* e = find(host, now);
    if (e == nullptr || e->ip == 0) return false;
    e->usedMs = now;
    if (ip != nullptr) *ip = e->ip;
    return true;
  }

  // An unexpired NEGATIVE entry for `host`: do not start another lookup yet.
  bool blocked(const char* host, uint32_t now) const {
    if (host == nullptr || host[0] == 0) return false;
    for (int i = 0; i < kDnsCacheEntries; i++) {
      const DnsCacheEntry& e = entries_[i];
      if (e.valid && !e.expired(now) && dnsHostEq(e.host, host)) return e.ip == 0;
    }
    return false;
  }

  // Records a resolved address. ip == 0 is rejected (use storeFailure).
  void store(const char* host, uint32_t ip, uint32_t now, uint32_t ttlMs) {
    if (ip == 0) return;
    put(host, ip, now, ttlMs);
  }

  // Records a failed lookup, with its own (shorter) lifetime.
  void storeFailure(const char* host, uint32_t now, uint32_t ttlMs) { put(host, 0, now, ttlMs); }

  // How many entries currently hold a live value (either sign). Test/bench visibility.
  int liveCount(uint32_t now) const {
    int n = 0;
    for (int i = 0; i < kDnsCacheEntries; i++) {
      if (entries_[i].valid && !entries_[i].expired(now)) n++;
    }
    return n;
  }

 private:
  DnsCacheEntry* find(const char* host, uint32_t now) {
    if (host == nullptr || host[0] == 0) return nullptr;
    for (int i = 0; i < kDnsCacheEntries; i++) {
      DnsCacheEntry& e = entries_[i];
      if (e.valid && !e.expired(now) && dnsHostEq(e.host, host)) return &e;
    }
    return nullptr;
  }

  void put(const char* host, uint32_t ip, uint32_t now, uint32_t ttlMs) {
    if (host == nullptr || host[0] == 0) return;
    const size_t len = strlen(host);
    if (len >= kDnsHostCap) return;  // cannot be represented: never cache it (lookup would miss too)
    DnsCacheEntry* slot = nullptr;
    // An entry for the same name (live or expired) is reused in place.
    for (int i = 0; i < kDnsCacheEntries && slot == nullptr; i++) {
      if (entries_[i].valid && dnsHostEq(entries_[i].host, host)) slot = &entries_[i];
    }
    // Otherwise a free/expired entry.
    for (int i = 0; i < kDnsCacheEntries && slot == nullptr; i++) {
      if (!entries_[i].valid || entries_[i].expired(now)) slot = &entries_[i];
    }
    // Otherwise the least recently used one.
    if (slot == nullptr) {
      int lru = 0;
      for (int i = 1; i < kDnsCacheEntries; i++) {
        if (static_cast<int32_t>(entries_[i].usedMs - entries_[lru].usedMs) < 0) lru = i;
      }
      slot = &entries_[lru];
    }
    for (size_t i = 0; i < len; i++) slot->host[i] = dnsFoldChar(host[i]);
    slot->host[len] = 0;
    slot->ip = ip;
    slot->storedMs = now;
    slot->ttlMs = ttlMs;
    slot->usedMs = now;
    slot->valid = true;
  }

  DnsCacheEntry entries_[kDnsCacheEntries];
};

}  // namespace fry_relay
