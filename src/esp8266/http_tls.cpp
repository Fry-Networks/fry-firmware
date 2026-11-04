#include "../core/http_tls.h"
#include "../core/flash_print.h"
#include "../core/wifi_station.h"

#include "heap_gate.h"
#include "mfln_cache.h"
#include "tls_sizing.h"
#include "tls_boot_gate.h"
#include "tls_trust.h"
#include "ntp_kick.h"
#include "config.h"
#include "tls_anchors.h"

#include <new>
#include <time.h>

namespace fry_http {

namespace {

// "host" (or "host:port") of "scheme://host[:port]/path...", held in a stack buffer, not a String: it is taken before the heap
// sample in beginHttpsUrl and must leave the heap as it found it. No port/userinfo support needed: every URL this firmware
// calls is a plain https://host/path. extractHost is false when it does not fit (no trust set has a name that long).
struct HostName {
  char buf[64];
  const char* c_str() const { return buf; }
  operator String() const { return String(buf); }  // for the helpers that take a String; never instantiated on the production path
};
bool extractHost(const char* url, char* out, size_t cap) {
  const char* start = strstr(url, "://");
  start = start ? start + 3 : url;
  const char* end = strchr(start, '/');
  const size_t n = end ? static_cast<size_t>(end - start) : strlen(start);
  if (n + 1 > cap) return false;
  memcpy(out, start, n);
  out[n] = '\0';
  return true;
}

// The active trust-anchor set. The anchors are const data in flash (src/esp8266/tls_anchors.h, generated from data/cert), so
// choosing a set allocates nothing and frees nothing: it only points at the one for the host being called. A
// WiFiClientSecure keeps a raw pointer to it, which is always valid (flash), so no client can be left holding a freed list.
struct TrustState {
  const BearSSL::X509List* list;
  fry::TrustSet set;
};
TrustState gTrust = {nullptr, fry::TrustSet::None};
bool gNtpKicked = false;
uint32_t gNtpKickedMs = 0;

// Starts SNTP when the clock is unset, at most once per ntpRestartDue interval. Never waits.
void kickSntpIfNeeded() {
  if (fry::tlsClockSane(static_cast<int64_t>(time(nullptr)))) return;
  if (!fry::ntpRestartDue(gNtpKicked, millis(), gNtpKickedMs)) return;
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  gNtpKicked = true;
  gNtpKickedMs = millis();
}

// Whether the last beginHttpsUrl() refusal was the heap check (a retry soon may succeed) and not a clock, host or anchor failure.
bool s_lastRefusalHeap = false;

// Hides the pointer's origin from the optimiser: the layout check below must read the mirror through the framework's own
// accessors at run time, not be folded against the data it was built from.
inline const BearSSL::X509List* opaqueList(const BearSSL::X509List* p) {
  __asm__ __volatile__("" : "+r"(p));
  return p;
}

bool ensureTrustAnchors(fry::TrustSet want) {
  if (gTrust.list && gTrust.set == want) return true;
  gTrust.list = nullptr;
  gTrust.set = fry::TrustSet::None;
  const BearSSL::X509List* l = fry::anchorListFor(want);
  if (!l) return false;
  const BearSSL::X509List* o = opaqueList(l);
  if (o->getCount() != fry::trustSetCount(want) || !o->getTrustAnchors() || o->getTrustAnchors()[0].dn.len == 0 ||
      !(o->getTrustAnchors()[0].flags & BR_X509_TA_CA)) {
    Serial.printf_P(PSTR("tls: anchor list layout unexpected - refusing\n"));
    return false;
  }
  gTrust.list = l;
  gTrust.set = want;
  return true;
}

bool probeMfln512(const char* host, void*) {
  return WiFiClientSecure::probeMaxFragmentLength(host, 443, 512);
}

#if defined(FRY_TLS_BENCH)
// =============================================================================================
// BENCH ONLY (oneshot esp7, C1). Compiled only with -DFRY_TLS_BENCH=1, which only
// [env:esp8266_tlsbench] sets; no production env defines it, so none of this is in a shipped
// image. It answers one question the source cannot: does a BearSSL X.509 trust-anchor set fit
// in this chip's heap at the moment beginHttpsUrl() sets TLS up, and does validation then
// actually REFUSE a connection it cannot vouch for while ACCEPTING the real hosts?
//
// Ordering matters and mirrors the production design: the anchor set is built BEFORE the heap
// sample, so fr::planTls() decides against the heap as it will really be (anchors resident).
// If the plan still passes and the probe handshakes succeed, C1 fits; if the plan now refuses,
// it does not and C1 ships as a BLOCKER with these numbers.
//
// Prints, one line each, prefix "bench:":
//   anchors built n=.. cost_free=.. cost_blk=..   heap the anchor set costs, measured
//   sizes client_ctx=.. minimal_ctx=.. ...        the structures a handshake allocates
//   anchor i=.. cert=.. dn=.. key=..              per-anchor bytes (cert DER + DN + public key)
//   ta host=.. n=.. now=.. ntp=.. rx=.. tx=..     the installed anchor set at THIS call
//   plan host=.. refused                          planTls refused with anchors resident
//   negctl host=.. ok=0 ssl_err=.. msg=".."       NO anchors installed: must be refused
//   probe host=.. ok=1 ssl_err=0 used_free=..     anchors installed: real host, real handshake
//   bigprobe host=.. rx=16384 tx=512 ok=..        the OTA image-download sizing, once per boot
// At most 3 handshakes on the first host, 1 on each later one, 4 hosts, then it stops.
#include <time.h>

#include "tls_bench_anchors.h"

BearSSL::X509List* gBenchAnchors = nullptr;
uint32_t gBenchAnchorFree = 0;
uint32_t gBenchAnchorBlk = 0;
char gBenchProbedHosts[4][48];
uint8_t gBenchProbedCount = 0;
bool gBenchNegDone = false;
bool gBenchBigDone = false;

bool benchClockOk() { return static_cast<time_t>(time(nullptr)) > static_cast<time_t>(1600000000); }

uint32_t benchUsed(uint32_t before, uint32_t after) { return after <= before ? before - after : 0; }

void benchPrepare() {
  if (gBenchAnchors) {
    Serial.printf_P(PSTR("bench: anchors resident n=%u cost_free=%u cost_blk=%u free=%u blk=%u\n"),
                    static_cast<unsigned>(gBenchAnchors->getCount()),
                    static_cast<unsigned>(gBenchAnchorFree), static_cast<unsigned>(gBenchAnchorBlk),
                    static_cast<unsigned>(ESP.getFreeHeap()),
                    static_cast<unsigned>(fry::queryMaxFreeBlock()));
    return;
  }
  const uint32_t f0 = ESP.getFreeHeap();
  const uint32_t b0 = fry::queryMaxFreeBlock();
  gBenchAnchors = new BearSSL::X509List(kBenchAnchorsPem);
  const uint32_t f1 = ESP.getFreeHeap();
  const uint32_t b1 = fry::queryMaxFreeBlock();
  if (!gBenchAnchors || gBenchAnchors->getCount() == 0) {
    Serial.printf_P(PSTR("bench: anchors FAILED free=%u blk=%u (no anchors parsed - numbers below are meaningless)\n"),
                    static_cast<unsigned>(f1), static_cast<unsigned>(b1));
    return;
  }
  gBenchAnchorFree = benchUsed(f0, f1);
  gBenchAnchorBlk = benchUsed(b0, b1);
  Serial.printf_P(PSTR("bench: anchors built n=%u cost_free=%u cost_blk=%u free=%u blk=%u\n"),
                  static_cast<unsigned>(gBenchAnchors->getCount()),
                  static_cast<unsigned>(gBenchAnchorFree), static_cast<unsigned>(gBenchAnchorBlk),
                  static_cast<unsigned>(f1), static_cast<unsigned>(b1));
  Serial.printf_P(PSTR("bench: sizes client_ctx=%u minimal_ctx=%u ta_struct=%u cert_struct=%u\n"),
                  static_cast<unsigned>(sizeof(br_ssl_client_context)),
                  static_cast<unsigned>(sizeof(br_x509_minimal_context)),
                  static_cast<unsigned>(sizeof(br_x509_trust_anchor)),
                  static_cast<unsigned>(sizeof(br_x509_certificate)));
  const br_x509_certificate* certs = gBenchAnchors->getX509Certs();
  const br_x509_trust_anchor* tas = gBenchAnchors->getTrustAnchors();
  for (size_t i = 0; i < gBenchAnchors->getCount(); i++) {
    uint32_t key = 0;
    if (tas[i].pkey.key_type == BR_KEYTYPE_RSA) {
      key = tas[i].pkey.key.rsa.nlen + tas[i].pkey.key.rsa.elen;
    } else if (tas[i].pkey.key_type == BR_KEYTYPE_EC) {
      key = tas[i].pkey.key.ec.qlen;
    }
    Serial.printf_P(PSTR("bench: anchor i=%u cert=%u dn=%u key=%u type=%u\n"),
                    static_cast<unsigned>(i), static_cast<unsigned>(certs[i].data_len),
                    static_cast<unsigned>(tas[i].dn.len), static_cast<unsigned>(key),
                    static_cast<unsigned>(tas[i].pkey.key_type));
  }
}

// One real handshake on the caller's client, using whatever buffers/auth it carries right now.
void benchProbe(WiFiClientSecure& sec, const char* tag, const String& host) {
  const uint32_t f0 = ESP.getFreeHeap();
  const uint32_t b0 = fry::queryMaxFreeBlock();
  const bool ok = sec.connect(host.c_str(), 443);
  const uint32_t f1 = ESP.getFreeHeap();
  const uint32_t b1 = fry::queryMaxFreeBlock();
  char msg[64] = {0};
  const int err = ok ? 0 : sec.getLastSSLError(msg, sizeof(msg));
  Serial.printf_P(PSTR("bench: %s host=%s ok=%d ssl_err=%d msg=\"%s\" free=%u used_free=%u blk=%u used_blk=%u\n"),
                  tag, host.c_str(), ok ? 1 : 0, err, msg, static_cast<unsigned>(f0),
                  static_cast<unsigned>(benchUsed(f0, f1)), static_cast<unsigned>(b0),
                  static_cast<unsigned>(benchUsed(b0, b1)));
  if (ok) Serial.printf_P(PSTR("bench: %s mfln=%d\n"), tag, sec.getMFLNStatus());
  sec.stop();
  yield();
  Serial.printf_P(PSTR("bench: %s after_stop free=%u blk=%u\n"), tag,
                  static_cast<unsigned>(ESP.getFreeHeap()),
                  static_cast<unsigned>(fry::queryMaxFreeBlock()));
}

void benchAfterPlan(WiFiClientSecure& sec, const String& host, fry::TlsSizing sizing, int rx, int tx) {
  if (!gBenchAnchors || gBenchAnchors->getCount() == 0) return;
  const time_t now = time(nullptr);
  sec.setTrustAnchors(gBenchAnchors);
  sec.setX509Time(now);
  Serial.printf_P(PSTR("bench: ta host=%s n=%u now=%ld ntp=%d rx=%d tx=%d free=%u blk=%u\n"),
                  host.c_str(), static_cast<unsigned>(gBenchAnchors->getCount()),
                  static_cast<long>(now), benchClockOk() ? 1 : 0, rx, tx,
                  static_cast<unsigned>(ESP.getFreeHeap()),
                  static_cast<unsigned>(fry::queryMaxFreeBlock()));
  (void)sizing;

  bool seen = false;
  for (uint8_t i = 0; i < gBenchProbedCount; i++) {
    if (strcmp(gBenchProbedHosts[i], host.c_str()) == 0) seen = true;
  }
  if (seen || gBenchProbedCount >= 4) {
    Serial.printf_P(PSTR("bench: probe host=%s skipped (already probed this boot)\n"), host.c_str());
    return;
  }
  strncpy(gBenchProbedHosts[gBenchProbedCount], host.c_str(), sizeof(gBenchProbedHosts[0]) - 1);
  gBenchProbedHosts[gBenchProbedCount][sizeof(gBenchProbedHosts[0]) - 1] = 0;
  gBenchProbedCount++;

  // Negative control FIRST: with no trust anchors at all this handshake must FAIL. If it
  // succeeds, validation is not on and every "probe ok=1" line below proves nothing.
  if (!gBenchNegDone) {
    gBenchNegDone = true;
    sec.setTrustAnchors(nullptr);
    benchProbe(sec, "negctl", host);
    sec.setTrustAnchors(gBenchAnchors);
    sec.setX509Time(time(nullptr));
  }

  benchProbe(sec, "probe", host);

  // The OTA image-download sizing (16384/512), measured once on a real handshake. Skipped when
  // this call already uses it, and the caller's own buffers are restored afterwards so the
  // request this function is setting up runs exactly as it would without the probe.
  if (!gBenchBigDone && rx != static_cast<int>(fry::kTlsBigRxBytes)) {
    gBenchBigDone = true;
    sec.setBufferSizes(fry::kTlsBigRxBytes, fry::kTlsTxBytes);
    benchProbe(sec, "bigprobe", host);
    if (rx > 0 && tx > 0) sec.setBufferSizes(rx, tx);
    sec.setTrustAnchors(gBenchAnchors);
    sec.setX509Time(time(nullptr));
  }
}

void benchRefused(const String& host, const fry::HeapSample& heap, const fry::TlsFloors& floors) {
  Serial.printf_P(PSTR("bench: plan host=%s refused_with_anchors_resident free=%u blk=%u floor_free=%u floor_blk=%u ta_n=%u\n"),
                  host.c_str(), static_cast<unsigned>(heap.freeTotal),
                  static_cast<unsigned>(heap.maxBlock), static_cast<unsigned>(floors.freeTotal),
                  static_cast<unsigned>(floors.block),
                  static_cast<unsigned>(gBenchAnchors ? gBenchAnchors->getCount() : 0));
}

#endif  // FRY_TLS_BENCH

}  // namespace

// The URL arrives as a C string and is never copied to the heap before the heap sample below: a redirect hop passes the
// Location from the caller's stack (src/core/ota_client.cpp getFollowingHops), and a heap copy of it sitting in the middle of
// the region this call is about to measure is what split that region. http.begin() at the end builds its own Strings, after the
// sample, which is where the session needs them.
bool beginHttpsUrl(HTTPClient& http, WiFiClientSecure& sec, const char* url, bool mflnProbeWorthwhile, bool smallReply) {
  s_lastRefusalHeap = false;
#if defined(FRY_TLS_BENCH)
  // BENCH ONLY: build the trust-anchor set BEFORE the sample below, so planTls() judges the heap
  // exactly as production will, with the anchors already resident.
  benchPrepare();
  int benchRx = 0;
  int benchTx = 0;
#define FRY_BENCH_SIZES(r, t) do { benchRx = (r); benchTx = (t); } while (0)
#else
#define FRY_BENCH_SIZES(r, t) do {} while (0)
#endif
  // The served chain is validated against a root anchor (lib/fry_core/tls_trust.h). Fail closed: an unknown host, a clock
  // that SNTP has not set, or an anchor set that will not build ends the call here, before any connection exists. A missing
  // clock starts SNTP (rate-limited) and returns without waiting; the caller's usual retry finds it set.
  HostName host;
  if (!url || !extractHost(url, host.buf, sizeof(host.buf))) {
    Serial.printf_P(PSTR("tls: refusing - host missing or too long\n"));
    return false;
  }
  const fry::TrustSet trust = fry::trustSetForHost(host.c_str());
  if (trust == fry::TrustSet::None) {
    Serial.printf_P(PSTR("tls: refusing %s - no trust anchors for this host\n"), host.c_str());
    return false;
  }
  const time_t now = time(nullptr);
  if (!fry::tlsClockSane(static_cast<int64_t>(now))) {
    kickSntpIfNeeded();
    Serial.printf_P(PSTR("tls: refusing %s - clock not set yet, waiting for SNTP\n"), host.c_str());
    return false;
  }
  // Anchors resident BEFORE the sample below, so planTls() judges the heap as it will really be. Building the set frees
  // the previous one first, so a manifest-only or earlier-hop set never sits next to this one.
  if (!ensureTrustAnchors(trust)) {
    Serial.printf_P(PSTR("tls: refusing %s - trust anchors did not load\n"), host.c_str());
    return false;
  }
  Serial.printf_P(PSTR("tls: trust set=%s n=%u free=%u blk=%u\n"), fry::trustSetName(trust),
                  static_cast<unsigned>(fry::trustSetCount(trust)), static_cast<unsigned>(ESP.getFreeHeap()),
                  static_cast<unsigned>(fry::queryMaxFreeBlock()));

  // hardwareapi may honour MFLN (letting us run a 512/512-byte TLS buffer instead of the
  // default 16 KB/16 KB); GitHub (used by T7's OTA client, which shares this same helper's
  // pattern conceptually) does not, and a 16 KB receive buffer needs both HEAP_GATE_OTA free
  // heap AND HEAP_GATE_OTA_BLOCK contiguous headroom or the handshake will OOM this chip's
  // ~50 KB heap.
  // Buffer sizing has to account for the MFLN probe itself, not just the buffers we go on to
  // request. probeMaxFragmentLength() opens its own throwaway TLS session with BearSSL still
  // on its DEFAULT 16384+16384 buffers — about 32 KB of contiguous allocation — before any
  // sizing of ours takes effect. Measured on COM11 at heap=42464 blk=34200 the probe alone
  // crashed the chip (Exception (4), rst cause:4, wdt reset).
  //
  // So: only probe when there is genuinely room for the big path. When there is not, skip the
  // probe and take the cheap 512/512 buffers. hardwareapi honours MFLN, so registration, lease
  // renewal and PoC keep working on a fragmented heap. A peer that does NOT honour it (GitHub,
  // i.e. OTA) is NOT given 512/512: the 0.3.3 bench board soft-reset (Exception 4) in that
  // handshake, so fry::planTls refuses the session instead and the caller gets `false`.
  // Gating everything on the OTA-sized threshold would block those small calls too.
  //
  // One sample, no bounded wait here. This helper runs on every HTTPS call, and spinning up to
  // 3 s each time starved the loop badly enough to trip the software watchdog. The bounded
  // wait still applies where it belongs, at the OTA download gate in src/core/ota_client.cpp.
  // A caller that already knows the peer refuses MFLN (GitHub, i.e. OTA) must not pay for the
  // probe. Measured on this board: the OTA manifest fetch passed the gate, ran the probe, and
  // still returned HTTP -1, because peak demand was max(32 KB probe, 16.4 KB iobuf) rather than
  // the 16.4 KB the gate was sized for. The gate SAMPLES and does not RESERVE, so the block it
  // saw did not survive to the allocation. Skipping the probe removes the 32 KB spike entirely
  // and leaves only the buffers we actually intend to use.
  // ONE sample drives the verdict and the buffer choice (fry::planTls, tested natively), taken now
  // that `sec` exists: constructing a WiFiClientSecure allocates BearSSL's 6200 B stack thunk, so a
  // sample taken before it (checkNow's gate) overstates what is left. A short heap is no longer
  // allowed to fall through to 512/512 for a peer that does not honour MFLN - see tls_sizing.h.
  // The OTA gates in ota_client.cpp sampled BEFORE `sec` and its HTTPClient existed; this sample is after, so it is
  // judged against their floors less what the constructor took (the thunk above + the clients). The raw gate numbers
  // here refused every OTA manifest check 15 ms after the gate had passed it ("manifest fetch begin failed").
  const fry::HeapSample heap{static_cast<uint32_t>(ESP.getFreeHeap()), fry::queryMaxFreeBlock()};
  // Three sessions, three measured needs (lib/fry_core/ota_heap_budget.h): the manifest (Medium 8192/512), the image
  // download (Big 16384/512, a peer that does not honour MFLN), and a peer that may honour MFLN, whose 32 KB probe
  // allocates after the constructor so the original floors are already in its terms.
  uint32_t gateFree = HEAP_GATE_OTA;
  uint32_t gateBlock = HEAP_GATE_OTA_BLOCK;
  if (smallReply) {
    gateFree = HEAP_GATE_OTA_MANIFEST;
    gateBlock = HEAP_GATE_OTA_MANIFEST_BLOCK;
  } else if (!mflnProbeWorthwhile) {
    gateFree = HEAP_GATE_OTA_DOWNLOAD;
    gateBlock = HEAP_GATE_OTA_DOWNLOAD_BLOCK;
  }
  const fry::TlsFloors floors = fry::tlsFloorsAtBegin(gateFree, gateBlock, mflnProbeWorthwhile);
  const fry::TlsPlan plan =
      fry::planTls(heap, floors.freeTotal, floors.block, mflnProbeWorthwhile, smallReply);
  switch (plan.sizing) {
    case fry::TlsSizing::Refuse:
      // printf_P/PSTR: the string stays in flash instead of costing ~130 B of the 80 KB heap budget.
      Serial.printf_P(PSTR("tls: refusing %s - heap too short for the big buffers and the peer does "
                           "not honour MFLN (need blk>=%u free>=%u, have blk=%u free=%u)\n"),
                      host.c_str(), static_cast<unsigned>(floors.block),
                      static_cast<unsigned>(floors.freeTotal), static_cast<unsigned>(heap.maxBlock),
                      static_cast<unsigned>(heap.freeTotal));
#if defined(FRY_TLS_BENCH)
      benchRefused(host, heap, floors);
#endif
      s_lastRefusalHeap = true;
      return false;
    case fry::TlsSizing::Small:
      FRY_PRINTLN("tls: low contiguous heap - MFLN probe skipped, 512/512");
      sec.setBufferSizes(512, 512);
      FRY_BENCH_SIZES(512, 512);
      break;
    case fry::TlsSizing::Big:
      // blk is logged because the 30 s [health] line samples far too coarsely to catch this peak,
      // and HTTP -1 collapses connect-refused, iobuf-OOM and handshake-failure into one code. This
      // is the only place the deciding quantity is visible at the deciding moment.
      FRY_PRINTF("tls: peer does not honour MFLN - probe skipped, 16384/512 (blk=%u)\n",
                    static_cast<unsigned>(heap.maxBlock));
      sec.setBufferSizes(16384, 512);
      FRY_BENCH_SIZES(16384, 512);
      break;
    case fry::TlsSizing::Medium:
      // The OTA manifest: github.com honours MFLN 512, the last hop (release-assets) does not and sends one 4146 B
      // Certificate record, then a ~2 KB JSON. 8192 holds that 1.98x over for 8 KB less heap than 16384.
      Serial.printf_P(PSTR("tls: small replies expected - probe skipped, %u/%u (blk=%u)\n"),
                      static_cast<unsigned>(fry::kTlsMediumRxBytes), static_cast<unsigned>(fry::kTlsTxBytes),
                      static_cast<unsigned>(heap.maxBlock));
      sec.setBufferSizes(fry::kTlsMediumRxBytes, fry::kTlsTxBytes);
      FRY_BENCH_SIZES(fry::kTlsMediumRxBytes, fry::kTlsTxBytes);
      break;
    case fry::TlsSizing::ProbeFirst: {
      // The probe is a throwaway ~32 KB session plus a TIME_WAIT pcb: ask once per host per boot, not on
      // every call (positive answers only, see lib/fry_core/mfln_cache.h).
      static fry::MflnCache mflnCache;
      if (!fry::mflnHonours(mflnCache, host.c_str(), probeMfln512, nullptr)) {
        sec.setBufferSizes(16384, 512);
        FRY_BENCH_SIZES(16384, 512);
      } else {
        sec.setBufferSizes(512, 512);
        FRY_BENCH_SIZES(512, 512);
      }
      break;
    }
  }

#if defined(FRY_TLS_BENCH)
  benchAfterPlan(sec, host, plan.sizing, benchRx, benchTx);
#endif
#undef FRY_BENCH_SIZES

  sec.setTrustAnchors(gTrust.list);
  sec.setX509Time(now);
  if (!http.begin(sec, url)) return false;
  http.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);
  http.setRedirectLimit(5);
  return true;
}

bool lastRefusalWasHeap() { return s_lastRefusalHeap; }

uint32_t tlsStartDelayMs() {
  kickSntpIfNeeded();  // start the clock now, so it is set by the time the gate opens
  uint32_t anchorMs = 0;
  const bool haveConnect = fry_wifi::connectAnchorMs(&anchorMs);
  return fry::tlsConnectWaitMs(millis(), anchorMs, haveConnect);
}

// Drops the active trust-set selection. The anchors are const data in flash, so nothing is freed and no heap changes; the
// next beginHttpsUrl() selects its set again. Called from the loop level at the same points as before (end of the report
// tick, start of an OTA check, after the manifest session).
void releaseTrustAnchors() {
  if (!gTrust.list) return;
  gTrust.list = nullptr;
  gTrust.set = fry::TrustSet::None;
  Serial.printf_P(PSTR("tls: trust released free=%u blk=%u\n"), static_cast<unsigned>(ESP.getFreeHeap()),
                  static_cast<unsigned>(fry::queryMaxFreeBlock()));
}

bool beginHttpsUrl(HTTPClient& http, WiFiClientSecure& sec, const String& url, bool mflnProbeWorthwhile, bool smallReply) {
  return beginHttpsUrl(http, sec, url.c_str(), mflnProbeWorthwhile, smallReply);
}

bool beginHttpsUrl(HTTPClient& http, WiFiClientSecure& sec, const String& url, bool mflnProbeWorthwhile) {
  return beginHttpsUrl(http, sec, url, mflnProbeWorthwhile, /*smallReply=*/false);
}

}  // namespace fry_http
