// WireGuard VPN endpoint for ESP32/S3/C3, using droscy/esp_wireguard (verified Arduino-usable:
// plain extern "C" API over lwIP's netif, library.json declares "frameworks": ["espidf",
// "arduino"], and esp_wireguard_connect() does NOT install the WG interface as the default route
// on its own — esp_wireguard_set_default() is a separate, deliberate call that this file never
// makes, satisfying the "must not kill the relay" constraint).
#include "../core/vpn_relay.h"

#include <WiFi.h>
#include <esp_bt.h>
#include <esp_wireguard.h>
#include <fcntl.h>
#include <lwip/opt.h>
#include <lwip/sockets.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <new>

#include "../core/fry_config.h"
#include "../core/hardwareapi_client.h"
#include "relay_dns.h"
#include "relay_guard.h"
#include "relay_latency.h"
#include "socks5_parse.h"
#include "socks_relay_core.h"
#include "wg_provision.h"
#include "wg_provision_client.h"

#if IP_NAPT
#include <lwip/lwip_napt.h>
#endif

// esp_wireguard 0.4.5 defaults WIREGUARD_MAX_SRC_IPS to 1 (wireguard-platform.h), filled
// unconditionally with the device's OWN tunnel /32. That leaves zero room for a route back to
// the server's own tunnel IP, so every reply the server sends gets ERR_RTE: the handshake
// reports "up" but no data ever crosses (seen on the bench as a live tunnel that never answers a
// ping). [esp32common] in platformio.ini raises this to 4 - one slot for the device's own /32
// (which esp_wireguard always fills) plus lib/fry_core/wg_provision.h's kWgMaxPlannedRoutes (3).
// This is a compile-time check that the flag actually landed, not just a runtime assumption.
#ifndef CONFIG_WIREGUARD_MAX_SRC_IPS
#error "CONFIG_WIREGUARD_MAX_SRC_IPS is unset - see the comment above and [esp32common] in platformio.ini"
#elif CONFIG_WIREGUARD_MAX_SRC_IPS != 4
#error "CONFIG_WIREGUARD_MAX_SRC_IPS must be exactly 4 - see the comment above"
#endif

namespace fry_vpn {

namespace {

wireguard_config_t s_wgConfig;
wireguard_ctx_t s_wgCtx;
bool s_initialized = false;
bool s_wasUp = false;
volatile uint32_t s_relayedBytes = 0;

// Relay connect-latency summary for the installation heartbeat. The ring belongs to the relay task
// (the only writer); the three published values are plain 32-bit words so the loop task can read
// them without a lock. A heartbeat that races one connect sees the previous triple: these are
// trend numbers, and relay_samples says how many connects they were computed from.
fry_relay::LatencyRing s_latency;
volatile uint32_t s_latP50 = 0;
volatile uint32_t s_latP95 = 0;
volatile uint32_t s_latSamples = 0;

// Config strings must outlive the wireguard_config_t (esp_wireguard keeps the pointers, does
// not copy them), so these are file-scope statics rather than locals in init().
String s_priv, s_pub, s_psk, s_addr, s_netmask, s_endpoint;

#if !IP_NAPT
// Fallback when this build's lwIP has no NAPT compiled in. This is not a build-flag choice we
// could flip — it is structurally impossible on this framework, confirmed two independent ways
// (v0.2.0):
//   1. `CONFIG_LWIP_IP_FORWARD is not set` in the baked sdkconfig for every ESP32-family chip
//      this project targets (esp32, esp32c3, esp32s2, esp32s3 — framework-arduinoespressif32's
//      tools/sdk/<chip>/sdkconfig), which is what lwipopts.h's IP_NAPT macro (CONFIG_LWIP_IPV4_NAPT)
//      ultimately gates.
//   2. A byte scan of the prebuilt tools/sdk/esp32/lib/liblwip.a shows the NAPT symbols
//      themselves — ip_napt_enable, ip_napt_init, ip4_napt_forward — are ALL ABSENT (zero
//      matches). lwip_napt.h ships as a header, but the corresponding .c was never compiled into
//      this static library, so no #define or build_flag on our side can turn NAPT on; it would
//      need a rebuilt liblwip.a, which is outside this firmware repo.
// Since transparent IP-level NAT isn't possible, this runs a "simple in-tunnel TCP forwarder": a
// SOCKS5 CONNECT relay (the same tested parser as the ESP8266 endpoint) on its own FreeRTOS task,
// so it can block on socket I/O without stalling the main loop(). A tunnel peer that knows the
// device's WG address can reach this relay and ask it to CONNECT out via the STA uplink — a
// reduced-scope substitute for full transparent NAT, not a general-purpose router.
//
// Structure: ONE task, ONE select() loop, up to FRY_RELAY_SLOTS clients at once. All protocol and
// scheduling decisions live in lib/fry_core/socks_relay_core.* (pure C++, covered by
// test/test_socks_relay_core); this file only performs the system calls and reports each result,
// together with errno captured right after the call, back to that core. Raw lwIP sockets are used
// instead of WiFiServer/WiFiClient on purpose: WiFiClient::connected()/available() decide a socket
// is dead from an errno that may belong to an older call, and WiFiServer::accept() cannot be
// waited on (its listening fd is private), which forced the old 5 ms poll.
//
// Per-client slots are heap-allocated on accept and freed on close, so an idle relay holds no
// buffers (about 2.3 KB per active client). One task with a select loop was chosen over a task per
// client because each task would pin its own >=4 KB stack, and the heap is the scarce resource on
// both chips.
//
// Passing on a FIN: when one side finishes and its data has been forwarded, the other side is told.
// shutdown(SHUT_WR) is only used on a socket that was read to EOF: recv() == 0 made lwIP apply
// SHUT_RD (TF_RXCLOSED), so the SHUT_WR takes the full-close branch and detaches the netconn from
// its pcb (IDF 4.4.7: api_lib.c:776, tcp.c:526, api_msg.c:1011-1012, :1127; the later free of the
// pcb skips the error callback, tcp_in.c:611). Toward a peer that is still open the descriptor is
// closed instead (FinAction): a half-close there leaves the netconn on a pcb that turns TIME_WAIT,
// lwIP frees TIME_WAIT pcbs without telling the netconn once 16 pcbs exist (tcp_alloc), and the EOF
// recv (api_msg.c:1007) and the close() then work on freed memory, the latter freeing it again:
// "CORRUPT HEAP: Bad head" in multi_heap_free under relay load. Cost, as in 0.4.7: a client that
// half-closes and waits for the reply loses it; unread client bytes go if the server ends first.
//
// A close() is abortive: lwIP answers what the peer still sends afterwards (its TLS close_notify, its
// FIN) with an RST. So when the client finishes first, the upstream gets Timing::finGraceMs to finish
// on its own before the descriptor is closed (the upstream's data is dropped meanwhile). A server that
// closes after the client's close_notify then ends the session with FINs only; one that waits for the
// FIN is closed when the grace runs out. The timer arms that close, so the loop carries it out right
// after onTimer (FinAction in socks_relay_core.h).
//
// Compile-time hypotheses, both default ON; -DFRY_RELAY_H5=0 / -DFRY_RELAY_H7=0 switch each one
// off again (the previous behaviour), so they can still be measured one at a time:
//   FRY_RELAY_H5  upstream connect is asynchronous: connect() is started non-blocking and the
//                 select loop finishes it, bounded by Timing::connectMs (3000 ms). A blackholed
//                 upstream therefore no longer stalls the other clients: in a host harness (not
//                 part of this repository) another client's request completed after 295 ms with
//                 it ON against 2909 ms with it OFF, while the upstream was blackholed (267 ms
//                 with no stalled upstream at all). OFF keeps the 0.4.7 behaviour of waiting for
//                 the connect inline (same 3000 ms bound) while every other client waits.
//   FRY_RELAY_H7  WiFi.setSleep(false) while the relay runs: no modem power-save, so a packet is
//                 not held until the next beacon/DTIM. One bench ESP32 pinged on the LAN at a
//                 1 s cadence: with modem sleep ON 5% loss and 123 ms average, with it OFF 0%
//                 loss and 30 ms. Constraint: the WiFi/Bluetooth coexistence code aborts the
//                 firmware when modem sleep is switched off while the BT controller is enabled,
//                 i.e. modem sleep is mandatory then. BLE provisioning enables the controller and
//                 nothing disables it again within a boot, so setSleep(false) is only called
//                 when the controller is not enabled; a boot that started BLE keeps modem sleep
//                 on until the next boot without BLE.
#ifndef FRY_RELAY_H5
#define FRY_RELAY_H5 1
#endif
#ifndef FRY_RELAY_H7
#define FRY_RELAY_H7 1
#endif
// 1 forwards every FIN with shutdown(SHUT_WR), whatever state the peer is in. That is the
// behaviour described above that corrupts the heap; it exists only to reproduce it on a bench board.
#ifndef FRY_RELAY_HALFCLOSE
#define FRY_RELAY_HALFCLOSE 0
#endif
#ifndef FRY_RELAY_SLOTS
#define FRY_RELAY_SLOTS 4
#endif
#ifndef FRY_RELAY_STACK_BYTES
#define FRY_RELAY_STACK_BYTES 4096
#endif
static_assert(FRY_RELAY_SLOTS >= 1 && FRY_RELAY_SLOTS <= fry_relay::kMaxSlots,
              "FRY_RELAY_SLOTS must be 1..fry_relay::kMaxSlots");

constexpr uint32_t kRelayStatEvery = 20;       // log the stack high-water mark every N closes
constexpr uint32_t kRelayEvictMinAgeMs = 1000;  // a stalled handshake may be evicted after this
constexpr uint32_t kRelayMaxSelectMs = 1000;
constexpr uint32_t kRelayFullSelectMs = 100;    // pool full: look again soon for an evictable slot
constexpr uint32_t kRelayDnsPollMs = 50;        // a resolver job is in flight: how often to look at it

struct RelayStats {
  uint32_t closed = 0, done = 0, hsTimeout = 0, hsEof = 0, hsBad = 0, connFail = 0, connTimeout = 0;
  uint32_t idle = 0, ioErr = 0, evicted = 0, fdGuard = 0, selFail = 0, einprog = 0, noMem = 0;
  uint32_t finHalf = 0, finClose = 0;
  uint32_t srcDrop = 0;  // accepted peers dropped for a source address outside the tunnel subnet
  uint32_t dnsFail = 0;  // requests failed because the name did not resolve inside the budget
};

bool setNonBlocking(int fd) {
  const int fl = fcntl(fd, F_GETFL, 0);
  return fl >= 0 && fcntl(fd, F_SETFL, fl | O_NONBLOCK) == 0;
}

void closeFd(int& fd) {
  if (fd >= 0) close(fd);
  fd = -1;
}

// Nagle would hold a small write until the previous one is acknowledged, which on a relayed TLS
// session is most of the added latency. Both sockets of a slot are relay sockets, so both are set.
bool setNoDelay(int fd) {
  int one = 1;
  return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0;
}

// Binds to the device's OWN tunnel address (host order, as fry::parseIpv4Cidr returns it), never
// INADDR_ANY: on INADDR_ANY the relay is an open proxy on the uplink, reachable by every host the
// device can see. A bind that fails is retried by the caller, exactly as before.
int openListener(uint32_t bindIp, uint16_t port) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(bindIp);
  sa.sin_port = htons(port);
  if (bind(fd, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) < 0 || listen(fd, 4) < 0 ||
      !setNonBlocking(fd) || !fry_relay::fdInRange(fd, FD_SETSIZE)) {
    close(fd);
    return -1;
  }
  return fd;
}

// ---- name resolution: bounded, asynchronous, cached -------------------------------------------
//
// 0.4.11 called WiFi.hostByName() from startConnect(), i.e. from inside the select loop, so one
// slow lookup (a dead resolver, a 5 s retry cycle) stopped every other slot from being serviced.
// Now a lookup runs in its own short-lived task and the loop only polls a flag once per pass:
//   * the slot stays in Phase::NeedConnect, whose existing Timing::connectMs budget bounds the
//     wait (onTimer -> ConnectTimeout). onConnectStarted() restarts that budget, so a lookup that
//     finishes in time still gets the full connectMs for the connect itself.
//   * the result (address or failure) is cached, so a repeated CONNECT to the same name needs no
//     lookup and a failed name is not retried until its negative entry expires.
//   * at most kDnsJobs tasks exist; a request for a third distinct name waits for a free job and
//     fails on the NeedConnect budget, so a busy or broken resolver never grows the heap.
//
// All of this is in the relay task, which is created once, so the state is file-scope.
constexpr uint32_t kDnsTtlMs = 300000;     // a resolved address stays usable for 5 min
constexpr uint32_t kDnsFailTtlMs = 15000;  // a name that just failed is not retried for 15 s
constexpr int kDnsJobs = 2;                 // concurrent resolver tasks
constexpr uint32_t kDnsStackBytes = 3072;   // the task only waits on lwIP's own DNS callback

struct DnsJob {
  char host[256];
  IPAddress ip;
  volatile bool done;  // written by the resolver task, published with a memory barrier
  bool ok;
  int refs;     // client slots currently waiting on this job
  bool cached;  // the result has been put into s_dns.cache
};

DnsJob* s_dnsJobs[kDnsJobs] = {};  // every live resolve, whether or not a slot still waits on it

struct DnsState {
  fry_relay::DnsCache cache;
  DnsJob* job[FRY_RELAY_SLOTS] = {};  // per slot: the job it is waiting on (borrowed reference)
};
DnsState s_dns;

void dnsTaskFn(void* arg) {
  DnsJob* j = static_cast<DnsJob*>(arg);
  IPAddress ip;
  if (WiFi.hostByName(j->host, ip)) {
    j->ip = ip;
    j->ok = true;
  }
  __sync_synchronize();  // the address above must be visible before `done`
  j->done = true;
  vTaskDelete(nullptr);
}

DnsJob* dnsFind(const char* host) {
  for (int i = 0; i < kDnsJobs; i++) {
    if (s_dnsJobs[i] != nullptr && strcmp(s_dnsJobs[i]->host, host) == 0) return s_dnsJobs[i];
  }
  return nullptr;
}

// The job already resolving `host`, or a new one; nullptr when every job slot is busy.
DnsJob* dnsBegin(const char* host) {
  DnsJob* j = dnsFind(host);
  if (j != nullptr) return j;
  if (strlen(host) >= sizeof(DnsJob::host)) return nullptr;  // cannot be represented: fail the request
  for (int i = 0; i < kDnsJobs; i++) {
    if (s_dnsJobs[i] != nullptr) continue;
    DnsJob* n = new (std::nothrow) DnsJob();
    if (n == nullptr) return nullptr;
    strncpy(n->host, host, sizeof(n->host) - 1);
    n->host[sizeof(n->host) - 1] = 0;
    n->done = false;
    n->ok = false;
    n->refs = 0;
    n->cached = false;
    if (xTaskCreate(dnsTaskFn, "fry_dns", kDnsStackBytes, n, 1, nullptr) != pdPASS) {
      delete n;
      return nullptr;
    }
    s_dnsJobs[i] = n;
    return n;
  }
  return nullptr;
}

// Drops one slot's reference; the sweep frees the job once it is done and unreferenced.
void dnsRelease(DnsJob*& j) {
  if (j == nullptr) return;
  if (j->refs > 0) j->refs--;
  j = nullptr;
}

// Settles finished jobs into the cache and frees the ones nothing waits on any more, so a job whose
// slot was evicted or closed still caches its answer for the next request.
void dnsSweep(uint32_t now) {
  for (int i = 0; i < kDnsJobs; i++) {
    DnsJob* j = s_dnsJobs[i];
    if (j == nullptr) continue;
    if (!j->cached && j->done) {
      __sync_synchronize();
      if (j->ok) {
        s_dns.cache.store(j->host, ntohl(static_cast<uint32_t>(j->ip)), now, kDnsTtlMs);
      } else {
        s_dns.cache.storeFailure(j->host, now, kDnsFailTtlMs);
      }
      j->cached = true;
    }
    if (j->cached && j->refs == 0) {
      s_dnsJobs[i] = nullptr;
      delete j;
    }
  }
}

bool dnsBusy() {
  for (int i = 0; i < kDnsJobs; i++) {
    if (s_dnsJobs[i] != nullptr) return true;
  }
  return false;
}

bool isSet(int fd, fd_set* set) { return fry_relay::fdInRange(fd, FD_SETSIZE) && FD_ISSET(fd, set); }

int sockError(int fd) {
  int so = 0;
  socklen_t len = sizeof(so);
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so, &len) < 0) return errno ? errno : EIO;
  return so;
}

#if !FRY_RELAY_H5
// Inline wait for a non-blocking connect to finish, bounded by budgetMs. Returns 0 on success or
// the errno-style reason. Blocks the whole relay task, exactly as WiFiClient::connect did.
int waitConnectInline(int fd, uint32_t budgetMs) {
  const uint32_t t0 = millis();
  for (;;) {
    const uint32_t spent = millis() - t0;
    if (spent >= budgetMs) return ETIMEDOUT;
    const uint32_t left = budgetMs - spent;
    fd_set wr;
    FD_ZERO(&wr);
    FD_SET(fd, &wr);
    struct timeval tv = {static_cast<time_t>(left / 1000), static_cast<suseconds_t>((left % 1000) * 1000)};
    errno = 0;
    const int r = select(fd + 1, nullptr, &wr, nullptr, &tv);
    const int e = errno;
    switch (fry_relay::classifySelect(r, e)) {
      case fry_relay::SelectAction::Ready:
        return sockError(fd);
      case fry_relay::SelectAction::Timeout:
        return ETIMEDOUT;
      case fry_relay::SelectAction::Interrupted:
        break;
      case fry_relay::SelectAction::Failed:
        return e ? e : EIO;
    }
  }
}
#endif

int sideFd(const fry_relay::Slot& s, fry_relay::Side x) {
  return x == fry_relay::Side::Client ? s.clientFd : s.upFd;
}

// recv() into the slot's destination and report the result. True if anything but "would block".
bool doRecv(fry_relay::Slot& s, fry_relay::Side from, uint32_t now, RelayStats& st) {
  size_t room = 0;
  uint8_t* dst = fry_relay::recvDest(s, from, room);
  if (room == 0) return false;
  const bool relaying = s.phase == fry_relay::Phase::Relay;
  errno = 0;
  const long n = recv(sideFd(s, from), dst, room, MSG_DONTWAIT);
  const int e = errno;
  if (n < 0 && (e == EINPROGRESS || e == EALREADY)) st.einprog++;
  if (n > 0 && relaying) s_relayedBytes += static_cast<uint32_t>(n);
  fry_relay::onRecv(s, from, n, e, now);
  return fry_relay::classifyRecv(n, e) != fry_relay::IoResult::WouldBlock;
}

bool doSend(fry_relay::Slot& s, fry_relay::Side to, uint32_t now, RelayStats& st) {
  size_t len = 0;
  const uint8_t* src = fry_relay::sendSrc(s, to, len);
  if (len == 0) return false;
  errno = 0;
  const long n = send(sideFd(s, to), src, len, MSG_DONTWAIT);
  const int e = errno;
  if (n < 0 && (e == EINPROGRESS || e == EALREADY)) st.einprog++;
  if (n < 0 && e == ENOMEM) st.noMem++;
  fry_relay::onSend(s, to, n, e, now);
  return fry_relay::classifySend(n, e) != fry_relay::IoResult::WouldBlock;
}

// Publishes the ring's current summary for the installation heartbeat (fry_vpn::relayLatency).
// Only successful connects are recorded, and the time measured is the connect itself: onConnectStarted()
// resets Slot::phaseStartMs when the connect is issued, so a lookup or a wait for a resolver never
// shows up as connect latency.
void recordLatency(uint32_t ms) {
  s_latency.add(ms);
  s_latP50 = s_latency.p50Ms();
  s_latP95 = s_latency.p95Ms();
  s_latSamples = s_latency.count();
}

void connectResult(fry_relay::Slot& s, bool ok, uint32_t now) {
  if (ok && s.phase == fry_relay::Phase::Connecting) recordLatency(now - s.phaseStartMs);
  fry_relay::onConnectResult(s, ok, now);
}

// Starts the upstream connect to an address that is already resolved (`ip` is host order, the
// convention fry::parseIpv4Cidr and fry_relay::DnsCache use).
void connectTo(fry_relay::Slot& s, uint32_t ip, uint32_t now, RelayStats& st) {
  using namespace fry_relay;
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    connectResult(s, false, now);
    return;
  }
  if (!fdInRange(fd, FD_SETSIZE) || !setNonBlocking(fd)) {
    close(fd);
    st.fdGuard++;
    connectResult(s, false, now);
    return;
  }
  setNoDelay(fd);
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(s.req.port);
  sa.sin_addr.s_addr = htonl(ip);
  errno = 0;
  const int r = connect(fd, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa));
  const int e = errno;
  switch (classifyConnectStart(r, e)) {
    case ConnectStart::Done:
      onConnectStarted(s, fd, now);
      connectResult(s, true, millis());
      break;
    case ConnectStart::InProgress:
#if FRY_RELAY_H5
      onConnectStarted(s, fd, now);  // the select loop finishes it, bounded by Timing::connectMs (from now)
#else
    {
      const int err = waitConnectInline(fd, Timing().connectMs);
      onConnectStarted(s, fd, now);
      connectResult(s, err == 0, millis());
    }
#endif
      break;
    case ConnectStart::Failed:
      close(fd);
      connectResult(s, false, now);
      break;
  }
}

// Phase::NeedConnect: resolve from the cache or start/join a resolver job, and never block on DNS.
// Returns true when the slot moved on (the connect started, or the request failed); false while it
// is still waiting, in which case the next pass polls again and onTimer's Timing::connectMs budget
// (Phase::NeedConnect) bounds the wait.
bool needConnect(fry_relay::Slot& s, int idx, uint32_t now, RelayStats& st) {
  using namespace fry_relay;
  uint32_t ip = 0;
  if (s_dns.cache.lookup(s.req.host, now, &ip)) {
    connectTo(s, ip, now, st);
    return true;
  }
  if (s_dns.cache.blocked(s.req.host, now)) {
    st.dnsFail++;  // this name failed a moment ago: fail fast for kDnsFailTtlMs
    onConnectResult(s, false, now);
    return true;
  }
  DnsJob*& job = s_dns.job[idx];
  if (job == nullptr) {
    job = dnsBegin(s.req.host);
    if (job == nullptr) return false;  // no job slot or no heap: the connect budget fails the slot
    job->refs++;
  }
  if (!job->done) return false;  // the resolver task is still running
  __sync_synchronize();
  const bool ok = job->ok;
  const uint32_t addr = ok ? ntohl(static_cast<uint32_t>(job->ip)) : 0;
  if (ok) {
    s_dns.cache.store(job->host, addr, now, kDnsTtlMs);
  } else {
    s_dns.cache.storeFailure(job->host, now, kDnsFailTtlMs);
  }
  job->cached = true;
  dnsRelease(s_dns.job[idx]);
  if (!ok) {
    st.dnsFail++;
    onConnectResult(s, false, now);
    return true;
  }
  connectTo(s, addr, now, st);
  return true;
}

void tally(RelayStats& st, const fry_relay::Slot& s) {
  using fry_relay::CloseReason;
  st.closed++;
  switch (s.reason) {
    case CloseReason::Done: st.done++; break;
    case CloseReason::HandshakeTimeout: st.hsTimeout++; break;
    case CloseReason::HandshakeEof: st.hsEof++; break;
    case CloseReason::HandshakeBad: st.hsBad++; break;
    case CloseReason::ConnectFail: st.connFail++; break;
    case CloseReason::ConnectTimeout: st.connTimeout++; break;
    case CloseReason::Idle:
    case CloseReason::HalfCloseTimeout: st.idle++; break;
    case CloseReason::Evicted: st.evicted++; break;
    case CloseReason::FdGuard: st.fdGuard++; break;
    default: st.ioErr++; break;
  }
}

void releaseSlot(fry_relay::Slot*& s, RelayStats& st) {
  tally(st, *s);
  closeFd(s->clientFd);
  closeFd(s->upFd);
  delete s;
  s = nullptr;
}

// One line every kRelayStatEvery closed connections (and after the first), so the stack
// high-water mark and the close-reason mix can be read off a bench board. No addresses, keys or
// tokens.
void logStats(const RelayStats& st) {
  Serial.printf("socks5: stat closed=%u done=%u hs_to=%u hs_eof=%u hs_bad=%u cfail=%u cto=%u idle=%u ",
                static_cast<unsigned>(st.closed), static_cast<unsigned>(st.done),
                static_cast<unsigned>(st.hsTimeout), static_cast<unsigned>(st.hsEof),
                static_cast<unsigned>(st.hsBad), static_cast<unsigned>(st.connFail),
                static_cast<unsigned>(st.connTimeout), static_cast<unsigned>(st.idle));
  Serial.printf("ioerr=%u evict=%u fdg=%u selfail=%u einprog=%u nomem=%u stack_free_min=%u/%u heap=%u minheap=%u "
                "fin_half=%u fin_close=%u srcdrop=%u dnsfail=%u\n",
                static_cast<unsigned>(st.ioErr), static_cast<unsigned>(st.evicted),
                static_cast<unsigned>(st.fdGuard), static_cast<unsigned>(st.selFail),
                static_cast<unsigned>(st.einprog), static_cast<unsigned>(st.noMem),
                static_cast<unsigned>(uxTaskGetStackHighWaterMark(nullptr)),
                static_cast<unsigned>(FRY_RELAY_STACK_BYTES),
                static_cast<unsigned>(ESP.getFreeHeap()), static_cast<unsigned>(ESP.getMinFreeHeap()),
                static_cast<unsigned>(st.finHalf), static_cast<unsigned>(st.finClose),
                static_cast<unsigned>(st.srcDrop), static_cast<unsigned>(st.dnsFail));
}

#if !FRY_RELAY_HALFCLOSE
constexpr int kRelayDrainReads = 8;  // reads discarded before a FIN toward an open peer becomes a close()

// Closes `fd` after reading and discarding what it already holds: lwIP answers close() on a socket
// with received-but-unread bytes by resetting the connection and dropping everything it has not
// sent yet, which would cut off the reply that was just queued toward that peer. `scratch` is an
// idle slot buffer.
void drainAndClose(int& fd, uint8_t* scratch, size_t room) {
  for (int i = 0; i < kRelayDrainReads; i++) {
    if (recv(fd, scratch, room, MSG_DONTWAIT) <= 0) break;
  }
  closeFd(fd);
}
#endif

// Passes on the FIN the core has armed toward `side`'s peer (see FinAction in socks_relay_core.h).
void forwardFin(fry_relay::Slot& s, fry_relay::Side side, uint32_t now, RelayStats& st) {
  using namespace fry_relay;
  int& fd = side == Side::Client ? s.clientFd : s.upFd;
#if FRY_RELAY_HALFCLOSE
  (void)now;
  (void)st;
  if (takeShutdown(s, side) && fd >= 0) shutdown(fd, SHUT_WR);
#else
  switch (takeFinAction(s, side)) {
    case FinAction::None:
      break;
    case FinAction::HalfClose:
      if (fd >= 0) shutdown(fd, SHUT_WR);
      st.finHalf++;
      break;
    case FinAction::Close:
      if (fd >= 0) {
        // The FIN is only armed once the buffer that feeds this side is empty, so it can serve as scratch.
        drainAndClose(fd, side == Side::Client ? s.u2c : s.c2u, kBufSize);
        st.finClose++;
      }
      onSideClosed(s, side, now);
      break;
  }
#endif
}

// One socket-level service pass over a slot after select(). Returns true if anything happened.
bool serviceSlot(fry_relay::Slot& s, int idx, bool rdC, bool rdU, bool wrU, uint32_t now, RelayStats& st) {
  using namespace fry_relay;
  bool progress = false;
  if (s.phase == Phase::Connecting && wrU) {
    connectResult(s, sockError(s.upFd) == 0, now);
    progress = true;
  }
  if (rdC) progress |= doRecv(s, Side::Client, now, st);
  if (s.phase == Phase::NeedConnect) {
    // Never blocks on DNS now: a cache hit connects here, a miss joins a resolver job or starts
    // one and this slot is polled again next pass.
    progress |= needConnect(s, idx, now, st);
    now = millis();  // FRY_RELAY_H5=0 still finishes the connect inline in this call
  }
  progress |= doSend(s, Side::Up, now, st);
  if (rdU) progress |= doRecv(s, Side::Up, now, st);
  progress |= doSend(s, Side::Client, now, st);
  forwardFin(s, Side::Up, now, st);
  forwardFin(s, Side::Client, now, st);
  return progress;
}

// After a failed select() the fd_sets are indeterminate. Find the descriptor that is no longer
// valid and drop its slot; whatever remains is retried after a short backoff.
bool fdAlive(int fd) { return fd < 0 || fcntl(fd, F_GETFL, 0) >= 0; }

// The device's own tunnel address, as the listener and the source guard both need it.
struct TunnelAddr {
  uint32_t ip = 0;  // host order, bit 31 = first octet
  int prefix = 0;
};

// Returns true once accept() has produced a descriptor, so a listener that stays readable while
// accept() keeps failing (EMFILE, ECONNABORTED) does not count as progress and still gets the
// anti-spin yield in the main loop.
bool acceptClients(int listenFd, const TunnelAddr& tun, fry_relay::Slot** slots, uint32_t now,
                   RelayStats& st) {
  using namespace fry_relay;
  bool accepted = false;
  for (int i = 0; i < FRY_RELAY_SLOTS; i++) {
    // Only accept when there is room (or a stalled handshake to evict); otherwise the waiting
    // connection stays in the listen backlog instead of being accepted and dropped.
    if (poolFreeIndex(slots, FRY_RELAY_SLOTS) < 0 &&
        poolEvictIndex(slots, FRY_RELAY_SLOTS, now, kRelayEvictMinAgeMs) < 0) {
      return accepted;
    }
    struct sockaddr_in peer;
    socklen_t plen = sizeof(peer);
    const int fd = accept(listenFd, reinterpret_cast<struct sockaddr*>(&peer), &plen);
    if (fd < 0) return accepted;  // EAGAIN: backlog drained (or a transient error: select fires again)
    accepted = true;
    // The relay is only for tunnel peers. Even though the listener is bound to the tunnel address,
    // the source is checked as well and a stranger is dropped here, before a slot or a buffer is
    // spent on it: a bind on a multi-homed stack (or a mis-set wgAddr) must not turn this into an
    // open proxy. srcdrop is in the stat line as the bench-visible counter.
    if (plen < sizeof(peer) || !ipInSubnet(ntohl(peer.sin_addr.s_addr), tun.ip, tun.prefix)) {
      bumpSaturating(st.srcDrop);
      if (st.srcDrop == 1) {
        char tunStr[16];
        fry::formatIpv4(tun.ip, tunStr, sizeof(tunStr));
        Serial.printf("socks5: dropping peers outside %s/%d (srcdrop=%u)\n", tunStr, tun.prefix,
                      static_cast<unsigned>(st.srcDrop));
      }
      close(fd);
      continue;
    }
    int idx = poolFreeIndex(slots, FRY_RELAY_SLOTS);
    if (idx < 0) {
      idx = poolEvictIndex(slots, FRY_RELAY_SLOTS, now, kRelayEvictMinAgeMs);
      slotForceClose(*slots[idx], CloseReason::Evicted);
      dnsRelease(s_dns.job[idx]);
      releaseSlot(slots[idx], st);
    }
    if (!fdInRange(fd, FD_SETSIZE) || !setNonBlocking(fd)) {
      st.fdGuard++;
      close(fd);
      continue;
    }
    Slot* s = new (std::nothrow) Slot;
    if (!s) {
      st.noMem++;
      close(fd);
      continue;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));  // as WiFiServer::available did
    setNoDelay(fd);
    dnsRelease(s_dns.job[idx]);  // a stale reference from the previous occupant of this slot
    slotInit(*s, fd, now);
#if FRY_RELAY_HALFCLOSE
    s->finGraceMs = 0;  // the bench switch restores the old behaviour as a whole
#else
    s->finGraceMs = Timing().finGraceMs;
#endif
    slots[idx] = s;
  }
  return accepted;
}

void relayTaskFn(void*) {
  using namespace fry_relay;
  const Timing timing;
  const uint16_t port = static_cast<uint16_t>(fry_config::getSocksPort());

  // The listener binds to the device's own tunnel address, never INADDR_ANY (see openListener).
  // With no tunnel address there is nothing to bind to and no subnet to guard, so the relay simply
  // does not run: one state-change line, no fallback to an open proxy.
  TunnelAddr tun;
  const String wgAddr = fry_config::getWgAddr();
  if (!fry::parseIpv4Cidr(wgAddr.c_str(), &tun.ip, &tun.prefix) || tun.prefix < kMinTunnelPrefix) {
    Serial.println("socks5: relay disabled - no usable tunnel address (fry/wgAddr), not listening");
    return;
  }
  char tunStr[16];
  fry::formatIpv4(tun.ip, tunStr, sizeof(tunStr));

  int listenFd = -1;
  for (uint32_t tries = 0; listenFd < 0; tries++) {
    listenFd = openListener(tun.ip, port);
    if (listenFd >= 0) break;
    if (tries % 10 == 0) Serial.printf("socks5: listen %s:%u failed errno=%d, retrying\n", tunStr, port, errno);
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
  Serial.printf("socks5: listening %s:%u slots=%d h5=%d h7=%d hc=%d fg=%u\n", tunStr, port, FRY_RELAY_SLOTS,
                FRY_RELAY_H5, FRY_RELAY_H7, FRY_RELAY_HALFCLOSE,
                static_cast<unsigned>(FRY_RELAY_HALFCLOSE ? 0u : Timing().finGraceMs));
#if FRY_RELAY_H7
  if (esp_bt_controller_get_status() != ESP_BT_CONTROLLER_STATUS_ENABLED) {
    // persists across reconnects (WiFiGenericClass::_sleepEnabled)
    if (WiFi.setSleep(false)) {
      Serial.println("socks5: wifi modem-sleep off (H7)");
    } else {
      Serial.println("socks5: modem-sleep off failed");
    }
  } else {
    Serial.println("socks5: modem-sleep kept on (BT controller enabled)");
  }
#endif

  Slot* slots[FRY_RELAY_SLOTS] = {};
  RelayStats st;
  uint32_t selFails = 0;
  uint32_t lastLoggedClosed = 0;

  for (;;) {
    uint32_t now = millis();
    // Finished resolver jobs are settled here first, so a slot waiting on one sees its answer in
    // this same pass.
    dnsSweep(now);
    for (int i = 0; i < FRY_RELAY_SLOTS; i++) {
      if (!slots[i]) continue;
      onTimer(*slots[i], timing, now);
      // A FIN whose grace time ran out is armed by the timer, not by a socket event: no select() result
      // brings the slot to serviceSlot() for it, so it is carried out here.
      forwardFin(*slots[i], Side::Up, now, st);
      forwardFin(*slots[i], Side::Client, now, st);
    }
    for (int i = 0; i < FRY_RELAY_SLOTS; i++) {
      if (slots[i] && slotClosed(*slots[i])) {
        dnsRelease(s_dns.job[i]);  // the job finishes on its own and still caches its answer
        releaseSlot(slots[i], st);
      }
    }
    if (st.closed != lastLoggedClosed && (st.closed == 1 || st.closed % kRelayStatEvery == 0)) {
      lastLoggedClosed = st.closed;
      logStats(st);
    }

    const bool poolFull = poolFreeIndex(slots, FRY_RELAY_SLOTS) < 0;
    const bool watchListen = !poolFull || poolEvictIndex(slots, FRY_RELAY_SLOTS, now, kRelayEvictMinAgeMs) >= 0;
    WatchList wl;
    buildWatchList(slots, FRY_RELAY_SLOTS, listenFd, watchListen, FD_SETSIZE, wl);
    bool dropped = false;
    for (int i = 0; i < FRY_RELAY_SLOTS; i++) {
      if (slots[i] && wl.slotBad[i]) {
        slotForceClose(*slots[i], CloseReason::FdGuard);
        dnsRelease(s_dns.job[i]);
        releaseSlot(slots[i], st);
        dropped = true;
      }
    }
    if (wl.listenBad) {
      closeFd(listenFd);
      while ((listenFd = openListener(tun.ip, port)) < 0) vTaskDelay(pdMS_TO_TICKS(1000));
      dropped = true;
    }
    if (dropped) continue;

    fd_set rd, wr;
    FD_ZERO(&rd);
    FD_ZERO(&wr);
    for (int i = 0; i < wl.n; i++) {
      if (wl.w[i].rd) FD_SET(wl.w[i].fd, &rd);
      if (wl.w[i].wr) FD_SET(wl.w[i].fd, &wr);
    }
    uint32_t tmo = poolSelectTimeoutMs(slots, FRY_RELAY_SLOTS, timing, now,
                                       poolFull ? kRelayFullSelectMs : kRelayMaxSelectMs);
    // A slot waiting on a resolver has no descriptor in the select() set, so nothing would wake the
    // loop when its answer lands: poll at this cadence until every job has settled.
    if (dnsBusy() && tmo > kRelayDnsPollMs) tmo = kRelayDnsPollMs;
    int sr = 0;
    int se = 0;
    if (wl.n == 0) {
      vTaskDelay(pdMS_TO_TICKS(tmo ? tmo : 1));
    } else {
      struct timeval tv = {static_cast<time_t>(tmo / 1000), static_cast<suseconds_t>((tmo % 1000) * 1000)};
      errno = 0;
      sr = select(wl.maxFd + 1, &rd, &wr, nullptr, &tv);
      se = errno;
    }
    now = millis();
    const SelectAction act = classifySelect(sr, se);
    if (act == SelectAction::Failed) {
      st.selFail++;
      selFails++;
      for (int i = 0; i < FRY_RELAY_SLOTS; i++) {
        if (slots[i] && (!fdAlive(slots[i]->clientFd) || !fdAlive(slots[i]->upFd))) {
          slotForceClose(*slots[i], CloseReason::IoError);
          dnsRelease(s_dns.job[i]);
          releaseSlot(slots[i], st);
        }
      }
      if (!fdAlive(listenFd)) {
        closeFd(listenFd);
        while ((listenFd = openListener(tun.ip, port)) < 0) vTaskDelay(pdMS_TO_TICKS(1000));
      }
      vTaskDelay(pdMS_TO_TICKS(selectFailBackoffMs(selFails)));
      continue;
    }
    selFails = 0;
    if (act != SelectAction::Ready) continue;  // timeout / EINTR: the timers run at the top

    bool progress = false;
    for (int i = 0; i < FRY_RELAY_SLOTS; i++) {
      Slot* s = slots[i];
      if (!s) continue;
      now = millis();  // an earlier slot may have finished an inline connect (FRY_RELAY_H5=0)
      progress |= serviceSlot(*s, i, isSet(s->clientFd, &rd), isSet(s->upFd, &rd), isSet(s->upFd, &wr),
                              now, st);
      if (slotClosed(*s)) {
        dnsRelease(s_dns.job[i]);
        releaseSlot(slots[i], st);
      }
    }
    // Existing slots are serviced BEFORE new connections are accepted: a handshake whose bytes are
    // already queued must not be evicted as "stalled" because the loop was busy.
    if (watchListen && isSet(listenFd, &rd)) {
      now = millis();
      progress |= acceptClients(listenFd, tun, slots, now, st);
    }
    if (!progress) vTaskDelay(1);  // readable/writable but nothing moved (e.g. ENOMEM): do not spin
  }
}
#endif  // !IP_NAPT

}  // namespace

// esp_wireguard_connect() returns ESP_ERR_RETRY (0x201) while the endpoint's asynchronous
// DNS resolution is still in flight. It is an advisory to call again, not a failure - the
// library starts a second resolution itself in case the first ran too early. Treating it as
// fatal is why the tunnel never came up (seen as: wg: connect failed err=513).
static constexpr int      WG_CONNECT_ATTEMPTS = 10;
static constexpr uint32_t WG_CONNECT_RETRY_MS = 500;

// How often tick() retries loadConfig()+bringUp() while neither has succeeded yet (e.g. NTP
// isn't synced yet at boot, or the fetch client hasn't provisioned a config yet). This governs
// only the LOCAL esp_wireguard bring-up attempt, which has no HTTP-style failure to classify;
// the network FETCH itself (src/esp32/wg_provision_client.cpp) uses
// lib/fry_core/wg_provision.h's classifyWgFetch/wgRetryDelayMs schedule instead.
static constexpr unsigned long WG_BRINGUP_RETRY_MS = 5000;

namespace {
bool s_initAttempted = false;  // esp_wireguard_init() must never be called more than once ever
unsigned long s_lastBringUpAttemptMs = 0;
}  // namespace

// True once a config exists AND this build trusts it. Production ESP32 builds only trust a
// SERVER-provisioned config (wgProvAt != 0, set by wg_provision_client.cpp after a successful
// POST); FRY_SERIAL_PROVISION lab builds keep trusting whatever the `set_wg` serial command
// wrote, exactly as before this change (wgProvAt is never set on that path).
bool provisioningGateOpen() {
#ifdef FRY_SERIAL_PROVISION
  return true;
#else
  return fry_config::getWgProvAt() != 0;
#endif
}

// Loads the persisted config into the file-scope String/wgConfig fields. Returns false (and logs
// exactly the historical message) when no config is stored yet at all.
bool loadConfig() {
  s_priv = fry_config::getWgPriv();
  s_pub = fry_config::getWgPeerPub();
  s_psk = fry_config::getWgPsk();
  s_addr = fry_config::getWgAddr();  // e.g. "10.13.13.2/24"
  s_endpoint = fry_config::getWgEndpoint();

  if (s_priv.length() == 0 || s_pub.length() == 0 || s_endpoint.length() == 0) {
    Serial.println("wg: no VPN config - skipping");
    return false;
  }

  uint32_t addrIp;
  int addrPrefix;
  char netmaskBuf[16];
  if (fry::parseIpv4Cidr(s_addr.c_str(), &addrIp, &addrPrefix) &&
      fry::formatIpv4(fry::prefixToMask(addrPrefix), netmaskBuf, sizeof(netmaskBuf)) > 0) {
    s_netmask = netmaskBuf;
  } else {
    // Historical fallback: the lab `set_wg` serial command has always required a literal
    // "/24" address (serial_commands.cpp's cmdSetWg rejects anything else), so a config
    // written before this change - or any value that fails to parse - keeps behaving exactly
    // as it always did rather than failing closed.
    s_netmask = "255.255.255.0";
  }
  int slash = s_addr.indexOf('/');
  s_addr = (slash >= 0) ? s_addr.substring(0, slash) : s_addr;
  return true;
}

// Applies lib/fry_core/wg_provision.h's planned route list (persisted as a `;`-joined CIDR
// string) via esp_wireguard_add_allowed_ip, once the tunnel is up. This is the runtime half of
// the WIREGUARD_MAX_SRC_IPS fix - the build-time half is the static_assert-equivalent #error
// block above requiring CONFIG_WIREGUARD_MAX_SRC_IPS == 4.
void applyAllowedIps() {
  String csv = fry_config::getWgAllowed();
  int start = 0;
  while (start <= static_cast<int>(csv.length())) {
    int sep = csv.indexOf(';', start);
    String entry = (sep < 0) ? csv.substring(start) : csv.substring(start, sep);
    if (entry.length() > 0) {
      uint32_t ip;
      int prefix;
      if (fry::parseIpv4Cidr(entry.c_str(), &ip, &prefix)) {
        char ipStr[16];
        char maskStr[16];
        fry::formatIpv4(ip, ipStr, sizeof(ipStr));
        fry::formatIpv4(fry::prefixToMask(prefix), maskStr, sizeof(maskStr));
        esp_err_t err = esp_wireguard_add_allowed_ip(&s_wgCtx, ipStr, maskStr);
        Serial.printf("wg: allowed-ip %s/%s %s\n", ipStr, maskStr,
                      err == ESP_OK ? "ok" : "FAILED");
      }
    }
    if (sep < 0) break;
    start = sep + 1;
  }
}

// The actual esp_wireguard init/connect. Safe to call repeatedly while it keeps failing (NTP not
// synced yet, or a transient connect failure) - esp_wireguard_init() itself only ever runs once
// per boot, guarded by s_initAttempted, per the "never init twice" rule.
bool bringUp() {
  // A WireGuard handshake with an unset clock cannot succeed, so honour the result rather
  // than discarding it - proceeding would spend the retry budget on a misleading error.
  if (!fry_hwapi::ensureNtpSynced()) {  // PROTOCOL.md / T6
    Serial.println("wg: NTP not synced - skipping handshake");
    return false;
  }

  memset(&s_wgConfig, 0, sizeof(s_wgConfig));
  s_wgConfig.private_key = s_priv.c_str();
  s_wgConfig.public_key = s_pub.c_str();
  s_wgConfig.preshared_key = s_psk.length() ? s_psk.c_str() : nullptr;
  s_wgConfig.address = s_addr.c_str();
  s_wgConfig.netmask = s_netmask.c_str();
  s_wgConfig.endpoint = s_endpoint.c_str();
  s_wgConfig.port = static_cast<uint16_t>(fry_config::getWgPort());
  s_wgConfig.persistent_keepalive = static_cast<uint16_t>(fry_config::getWgKeepalive());

  esp_err_t err;
  if (!s_initAttempted) {
    s_initAttempted = true;
    err = esp_wireguard_init(&s_wgConfig, &s_wgCtx);
    if (err != ESP_OK) {
      Serial.printf("wg: init failed err=%d\n", static_cast<int>(err));
      return false;
    }
  }
  for (int attempt = 1; attempt <= WG_CONNECT_ATTEMPTS; ++attempt) {
    err = esp_wireguard_connect(&s_wgCtx);
    if (err != ESP_ERR_RETRY) break;  // success, or a real failure worth reporting
    Serial.printf("wg: endpoint DNS pending, retry %d/%d\n", attempt, WG_CONNECT_ATTEMPTS);
    delay(WG_CONNECT_RETRY_MS);
  }
  if (err != ESP_OK) {
    Serial.printf("wg: connect failed err=%d\n", static_cast<int>(err));
    return false;
  }
  // Deliberately NEVER call esp_wireguard_set_default(&s_wgCtx) — that would make the WG
  // interface the default route and kill this device's own STA-routed traffic (T6 constraint).
  s_initialized = true;
  applyAllowedIps();

#if IP_NAPT
  ip_addr_t staIp = {};
  staIp.type = IPADDR_TYPE_V4;
  staIp.u_addr.ip4.addr = static_cast<uint32_t>(WiFi.localIP());
  ip_napt_enable(staIp, 1);
  Serial.println("wg: NAPT enabled");
#else
  Serial.println("wg: NAPT not compiled into this framework's liblwip.a (CONFIG_LWIP_IP_FORWARD "
                  "unset) - falling back to the SOCKS5 tunnel-only relay");
  xTaskCreate(relayTaskFn, "fry_relay", FRY_RELAY_STACK_BYTES, nullptr, 1, nullptr);
#endif
  return true;
}

void init() {
  if (!loadConfig()) return;
  if (!provisioningGateOpen()) {
    Serial.println("wg: config present but not yet server-provisioned - deferring bring-up");
    return;  // tick() retries once the fetch client (or, in a lab build, `set_wg`) commits one
  }
  bringUp();
}

void tick() {
  if (!s_initialized) {
#ifndef FRY_SERIAL_PROVISION
    // Drives its own retry/backoff schedule (lib/fry_core/wg_provision.h's
    // classifyWgFetch/wgRetryDelayMs); a no-op once a config already exists. Lab builds skip
    // this entirely - they only ever get a config from the `set_wg` serial command.
    fry_wg_provision::tick();
#endif
    unsigned long now = millis();
    if (now - s_lastBringUpAttemptMs < WG_BRINGUP_RETRY_MS) return;
    s_lastBringUpAttemptMs = now;
    if (!loadConfig()) return;
    if (!provisioningGateOpen()) return;
    bringUp();
    return;
  }
  bool up = (esp_wireguard_peer_is_up(&s_wgCtx) == ESP_OK);
  if (up && !s_wasUp) {
    char pub8[9] = {0};
    strncpy(pub8, s_wgConfig.public_key, 8);
    Serial.printf("wg: handshake ok peer=%s endpoint=%s:%u\n", pub8, s_wgConfig.endpoint,
                  s_wgConfig.port);
  }
  s_wasUp = up;
}

bool isUp() { return s_initialized && s_wasUp; }
uint32_t relayedBytes() { return s_relayedBytes; }

RelayLatency relayLatency() {
  RelayLatency l;
  l.samples = s_latSamples;  // read first: it says what the other two describe
  l.p50Ms = s_latP50;
  l.p95Ms = s_latP95;
  return l;
}

}  // namespace fry_vpn

extern "C" void fry_trigger_start_vpn() { fry_vpn::init(); }
