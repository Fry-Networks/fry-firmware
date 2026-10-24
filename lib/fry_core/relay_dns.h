#pragma once
// Host-keyed IPv4 cache and resolver-job pool in front of the relay's name resolution
// (src/esp32/vpn_wireguard.cpp).
//
// The 0.4.11 relay called WiFi.hostByName() from inside its select loop, so one slow lookup stalled
// every other slot. Resolution is now a bounded asynchronous job polled once per service tick (see
// the DNS section of vpn_wireguard.cpp): the cache in front of it means a repeated CONNECT to the
// same name costs no lookup and a name that just failed is not retried on every request, and the
// job pool bounds how many lookups can exist at once.
//
// The pool is where the accounting lives, because getting it wrong starves the relay: a job holds
// one of kDnsJobs slots from begin() until it is BOTH finished and unreferenced (finishSlot /
// sweep). A slot that takes the cache-hit path must give its finished job back, or two long-lived
// hostname sessions pin both jobs and every later hostname gets no lookup at all.
//
// Sizes are fixed (kDnsCacheEntries, kDnsJobs) and eviction is LRU, so both cost the same whatever
// the client sends. `now` is a free-running 32-bit millisecond counter (wrap-safe comparisons), as
// everywhere in fry_relay.
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace fry_relay {

constexpr int kDnsCacheEntries = 4;
constexpr size_t kDnsHostCap = 256;  // fry::Socks5ConnectRequest::host is char[256]
constexpr int kDnsJobs = 2;          // concurrent resolve jobs (the shim keeps one task each)

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

// One asynchronous lookup. `done`, `ok` and `ip` are written by the resolver task; `refs` and
// `cached` by the relay task only.
struct DnsJob {
  char host[kDnsHostCap] = {0};
  uint32_t ip = 0;    // host order; meaningful only when ok
  bool ok = false;    // the name resolved to a non-zero address
  bool done = false;  // the resolver task finished (success or failure)
  bool cached = false;
  int refs = 0;       // client slots currently waiting on this job
  bool live = false;  // occupies one of the kDnsJobs slots
};

// Fixed pool of resolve jobs with the reference accounting the relay's NeedConnect path needs.
class DnsJobs {
 public:
  // The live job already resolving `host`, or nullptr.
  DnsJob* find(const char* host) {
    if (host == nullptr || host[0] == 0) return nullptr;
    for (int i = 0; i < kDnsJobs; i++) {
      if (jobs_[i].live && dnsHostEq(jobs_[i].host, host)) return &jobs_[i];
    }
    return nullptr;
  }

  // Attaches the caller to `host`'s job, creating one if a slot is free, and takes a reference.
  // nullptr means every job slot is busy with other names (or the name cannot be represented):
  // the caller must fail the request on its own budget rather than block or grow.
  // *created tells the caller to start a resolver task for the returned job.
  DnsJob* begin(const char* host, bool* created) {
    if (created != nullptr) *created = false;
    DnsJob* j = find(host);
    if (j != nullptr) {
      j->refs++;
      return j;
    }
    if (host == nullptr || host[0] == 0) return nullptr;
    const size_t len = strlen(host);
    if (len >= kDnsHostCap) return nullptr;
    for (int i = 0; i < kDnsJobs; i++) {
      DnsJob& n = jobs_[i];
      if (n.live) continue;
      for (size_t k = 0; k < len; k++) n.host[k] = host[k];
      n.host[len] = 0;
      n.ip = 0;
      n.ok = false;
      n.done = false;
      n.cached = false;
      n.refs = 1;
      n.live = true;
      if (created != nullptr) *created = true;
      return &n;
    }
    return nullptr;
  }

  // Drops one slot's reference. A job that is already settled and now unreferenced gives its pool
  // slot back immediately, so the next name in this very pass can use it; a job whose resolver is
  // still running stays live (the sweep frees it once it finishes, so its answer is not lost).
  void release(DnsJob* j) {
    if (j == nullptr || !j->live || j->refs <= 0) return;
    j->refs--;
    if (j->refs == 0 && j->cached) freeSlot(*j);
  }

  // Puts a finished job's result (address or failure) into `cache`, once. True when it is done.
  bool finish(DnsJob* j, DnsCache& cache, uint32_t now, uint32_t okTtlMs, uint32_t failTtlMs) {
    if (j == nullptr || !j->live || !j->done) return false;
    if (!j->cached) {
      if (j->ok) {
        cache.store(j->host, j->ip, now, okTtlMs);
      } else {
        cache.storeFailure(j->host, now, failTtlMs);
      }
      j->cached = true;
    }
    return true;
  }

  // The slot's own job, when it is finished: settle it, then drop the slot's reference and clear
  // the pointer. This is what keeps a session that already has its answer from holding a resolver
  // slot for the rest of its life. Returns true when the job was finished.
  bool finishSlot(DnsJob*& slotJob, DnsCache& cache, uint32_t now, uint32_t okTtlMs,
                  uint32_t failTtlMs) {
    if (!finish(slotJob, cache, now, okTtlMs, failTtlMs)) return false;
    release(slotJob);
    slotJob = nullptr;
    return true;
  }

  // Settles every finished job and frees the ones nothing waits on any more, so the answer of a job
  // whose slot was evicted or closed is still cached for the next request.
  void sweep(DnsCache& cache, uint32_t now, uint32_t okTtlMs, uint32_t failTtlMs) {
    for (int i = 0; i < kDnsJobs; i++) {
      DnsJob& j = jobs_[i];
      if (!j.live) continue;
      finish(&j, cache, now, okTtlMs, failTtlMs);
      if (j.cached && j.refs == 0) freeSlot(j);
    }
  }

  // True while at least one job is still resolving: the shim must then poll it, not sleep.
  bool pending() const {
    for (int i = 0; i < kDnsJobs; i++) {
      if (jobs_[i].live && !jobs_[i].done) return true;
    }
    return false;
  }

  int liveCount() const {
    int n = 0;
    for (int i = 0; i < kDnsJobs; i++) {
      if (jobs_[i].live) n++;
    }
    return n;
  }
  int freeCount() const { return kDnsJobs - liveCount(); }

 private:
  static void freeSlot(DnsJob& j) {
    j.host[0] = 0;
    j.ip = 0;
    j.ok = false;
    j.done = false;
    j.cached = false;
    j.refs = 0;
    j.live = false;
  }

  DnsJob jobs_[kDnsJobs];
};

}  // namespace fry_relay
