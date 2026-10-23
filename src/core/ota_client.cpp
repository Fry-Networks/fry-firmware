#include "ota_client.h"

#include <ArduinoJson.h>
#if defined(ARDUINO_ARCH_ESP8266)
#include <Updater.h>  // ESP8266 core header is named Updater.h, not Update.h
#include <eboot_command.h>  // eboot_command_clear()

#include <memory>
#include <new>

#include "ota_sha_match.h"
#include "ota_stage_guard.h"
#else
#include <Update.h>
#endif

#include <cstring>

#include "config.h"
#include "flash_print.h"
#include "fry_config.h"
#include "heap_gate.h"
#include "heap_gate_wait.h"
#include "semver.h"
#include "http_tls.h"
#include "key_policy.h"
#include "miner_key.h"
#include "ota_boot_counter.h"
#include "ota_first_check.h"
#include "ota_health.h"
#include "ota_heap_budget.h"
#include "ota_manifest_read.h"
#include "ota_retry.h"
#include "ota_rollout_json.h"
#include "ota_session.h"
#include "ota_settle.h"
#include "ota_timewait.h"
#include "sha256.h"
#include "tls_sizing.h"
#include "trigger_hooks.h"
#include "wifi_station.h"

#if !defined(ARDUINO_ARCH_ESP8266)
#include <esp_ota_ops.h>
#endif

#ifndef FRY_FIRMWARE_VERSION
#define FRY_FIRMWARE_VERSION "0.0.0-dev"
#endif
#ifndef FRY_BUILD_ENV
#define FRY_BUILD_ENV "unknown"
#endif
#ifndef OTA_MANIFEST_URL
#define OTA_MANIFEST_URL ""
#endif

// The test channel (C-5) is compiled only into the *_test envs: its own manifest URL, its own
// "channel" value, and a short verify deadline so a rollback shows up within minutes on the bench.
#if defined(FRY_OTA_TEST_CHANNEL)
#ifndef OTA_MANIFEST_URL_TEST
#error "FRY_OTA_TEST_CHANNEL needs OTA_MANIFEST_URL_TEST"
#endif
#define FRY_OTA_DEFAULT_MANIFEST OTA_MANIFEST_URL_TEST
#define FRY_OTA_CHANNEL "test"
#define FRY_OTA_VERIFY_DEADLINE_MS fry::kOtaVerifyDeadlineTestMs
#else
#define FRY_OTA_DEFAULT_MANIFEST OTA_MANIFEST_URL
#define FRY_OTA_CHANNEL "prod"
#define FRY_OTA_VERIFY_DEADLINE_MS fry::kOtaVerifyDeadlineProdMs
#endif

#if defined(ARDUINO_ARCH_ESP8266)
// The ESP8266 runs loop() on a 4096 B stack (core cont.h CONT_STACKSIZE) and everything below it - the TLS
// connect chain and a level-1 interrupt frame (XTOS reserves 256 B, ~350 B with the WiFi handler) - has to fit
// in what checkNow() leaves. downloadAndApply() is called once, so the compiler inlines it, and its locals
// (second HTTPClient + WiFiClientSecure + WiFiClient, Sha256, the read buffer) then sit in checkNow()'s frame for
// the whole manifest GET: 1920 B. With ~2272 B used when the GET starts, the connect overran the stack by ~430 B
// on the bench board, overwrote cont_t's pc_suspend/sp_suspend (so nothing could yield any more: no send, no
// ACK, no timer for 15 s), and the soft WDT fired. Keep the download out of checkNow()'s frame.
// Not applied on the ESP32 (RTOS task stacks): its image must not change.
#define FRY_OTA_ESP8266_NOINLINE __attribute__((noinline))
#else
#define FRY_OTA_ESP8266_NOINLINE
#endif

namespace fry_ota {

namespace {

fry::HeartbeatTracker s_heartbeat;
// "ota: rollout field malformed - ignored" is logged once per boot, not at every 6-hour check.
bool s_loggedRolloutMalformed = false;
// Round 2 (PROTOCOL.md 11.8): the image is marked valid only once hardwareapi answered AND it ran
// through the first PoC/lease cycle - a crash in the VPN start, telemetry or the first PoC must
// still roll it back.
const uint32_t kMarkValidSettleMs = POC_INTERVAL_MS + 60000UL;
// This boot runs an image that still has to prove itself: PENDING_VERIFY in otadata (ESP32 family)
// and/or fry_ota.pending naming this version (the NVS boot counter, both chips). Cached so the
// per-loop guard never touches the store.
bool s_confirmPending = false;
bool s_markAttempted = false;  // loopGuard's one attempt at the settle mark; answers retry after it
bool s_firstCheckAfterRollback = false;  // a strike was counted this boot (skip that version once)
bool s_loggedKeyless = false;
#if !defined(ARDUINO_ARCH_ESP8266)
bool s_pendingVerify = false;   // the running image is PENDING_VERIFY in otadata
bool s_rolledBack = false;      // the other slot holds an image the bootloader rolled back from
bool s_rollbackFailed = false;  // nothing to roll back to: stay, and keep reporting "pending"
bool s_markFailLogged = false;
uint32_t s_verifyMs = 0;        // time with the station associated + an IP, since boot
unsigned long s_lastGuardMs = 0;
#else
const bool s_rolledBack = false;  // one slot: nothing to roll back to
#endif
#if defined(FRY_TEST_FAULT) && FRY_TEST_FAULT == 3
unsigned long s_faultCrashAtMs = 0;
#endif

unsigned long s_lastCheckMs = 0;
#if defined(ARDUINO_ARCH_ESP8266)
// The last checkNow() was refused by a heap gate before any connection opened (lib/fry_core/ota_retry.h).
bool s_heapRefused = false;
uint8_t s_heapRetries = 0;
// The last checkNow()'s manifest body did not arrive whole (lib/fry_core/ota_manifest_read.h): asked again soon, in a run of its own.
bool s_readFailed = false;
uint8_t s_readRetries = 0;
#endif
// PROTOCOL.md section 6 wants a check "on boot and every 6 h". tick() is only reached
// once WiFi is up, but with s_lastCheckMs seeded at 0 the elapsed-time gate is false at
// boot (millis() is still tiny), so the first check silently slipped to OTA_CHECK_MS
// after boot. This flag forces exactly one check on the first tick after WiFi comes up.
bool s_firstCheckDone = false;

// Boot-counter rollback: boot into whichever OTA slot is NOT currently running. The second line
// behind the bootloader's own app rollback (see ota_client.h), for boards whose bootloader - from
// their first flash - lacks it. fry_ota.pending is left naming this version and fry_ota.rbk is
// set, so the previous image's init() counts the strike: it is the only writer of the strikes.
void manualRollback() {
#if defined(ARDUINO_ARCH_ESP8266)
  FRY_PRINTLN("ota: boot-fail limit reached - ROLLBACK IMPOSSIBLE on ESP8266 (one slot)");
  fry_config::clearOtaPending();
#else
  const esp_partition_t* running = esp_ota_get_running_partition();
  const esp_partition_t* other = esp_ota_get_next_update_partition(nullptr);
  if (other && running && other->address != running->address) {
    FRY_PRINTLN("ota: boot-fail limit reached - booting the other OTA slot");
    fry_config::setOtaRolledBack(true);
    esp_ota_set_boot_partition(other);
  } else {
    FRY_PRINTLN("ota: boot-fail limit reached but no other OTA slot found - staying");
    fry_config::clearOtaPending();
  }
#endif
  fry_config::clearOtaBootFails();
  delay(200);
  ESP.restart();
}

// Marks the running image valid once decideMarkValid() says so; a failure is retried on the next
// hardwareapi answer (noteHeartbeat) and the image keeps reporting "pending" meanwhile.
void tryMarkValid(const char* why) {
  if (!s_confirmPending) return;
  if (!fry::decideMarkValid(true, s_heartbeat.anyResponse(), millis(), kMarkValidSettleMs)) return;
#if !defined(ARDUINO_ARCH_ESP8266)
  if (s_pendingVerify) {
    const esp_err_t err = esp_ota_mark_app_valid_cancel_rollback();
    if (err != ESP_OK) {
      if (!s_markFailLogged) {
        s_markFailLogged = true;
        FRY_PRINTF("ota: marking %s valid FAILED (err=%d) - retried on the next hardwareapi answer\n",
                      FRY_FIRMWARE_VERSION, static_cast<int>(err));
      }
      return;
    }
    s_pendingVerify = false;
  }
#endif
  confirmGood();  // fry_ota.pending + the boot counter
  s_confirmPending = false;
  s_firstCheckDone = false;  // the manifest check a pending image skips runs on the next tick
  FRY_PRINTF("ota: image %s marked valid after %lus (hardwareapi answered, last http=%d; %s)\n",
                FRY_FIRMWARE_VERSION, millis() / 1000UL, s_heartbeat.lastHttp(), why ? why : "?");
}

bool otaBeginUrl(HTTPClient& http, WiFiClientSecure& sec, WiFiClient& plain, const String& url
#if defined(ARDUINO_ARCH_ESP8266)
                 ,
                 bool smallReply  // every TLS record of this request is small: the manifest, not the image
#endif
) {
  if (url.startsWith("https://")) {
    // GitHub - the compiled OTA_MANIFEST_URL host, and the *.githubusercontent.com targets its
    // release redirects hand out - does not honour MFLN. On ESP8266, probing it costs a ~32 KB
    // contiguous allocation purely to be told no, and that spike is what made every HTTPS
    // manifest fetch return -1. Tell beginHttpsUrl not to bother. A lab override pointed at an
    // MFLN-honouring host still gets the probe, and therefore still gets the cheap 512/512 path.
    const bool githubHost =
        url.indexOf("github.com") >= 0 || url.indexOf("githubusercontent.com") >= 0;
#if defined(ARDUINO_ARCH_ESP8266)
    // checkNow() keeps the manifest HTTPClient + WiFiClientSecure in scope while downloadAndApply()
    // opens its own, and HTTPClient::end() only stops the TLS session (freeing BearSSL's ~21 KB of
    // context and I/O buffers) when keep-alive reuse is off. Its default is on and GitHub keeps the
    // connection, so two sessions were open at once on a ~80 KB heap. See lib/fry_core/ota_session.h.
    if (!fry_http::beginHttpsUrl(http, sec, url, !githubHost, smallReply)) return false;
    http.setReuse(fry::otaAsksForKeepAlive(/*isEsp8266=*/true, /*isHttps=*/true));
    return true;
#else
    return fry_http::beginHttpsUrl(http, sec, url, !githubHost);
#endif
  }
  if (!http.begin(plain, url)) return false;
  http.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);
  http.setRedirectLimit(5);
  return true;
}

#if defined(ARDUINO_ARCH_ESP8266)
// Second cut at the same 4 KB loop stack (the first, FRY_OTA_ESP8266_NOINLINE + the heap read buffer, left ~350 B
// free below a manifest GET on the bench): checkNow() and downloadAndApply() are on the stack, one above the other,
// while the TLS connect runs below them, and what they hold across it is the cost. HTTPClient + WiFiClientSecure +
// WiFiClient are 204 B, fry::Sha256 + digest + hex ~200 B more; they live in one heap block per function (same
// lifetime as the stack objects had: destroyed when the function returns), and the manifest decision, which needs
// a JsonDocument and two key/digest buffers but no connection, runs in its own frame after the GET.
// Frames (gcc -fstack-usage, tools/check_esp8266_stack_budget.py): checkNow 560 -> 128 B, downloadAndApply 512 ->
// 112 B, evaluateManifest 208 B (sequential with the GET, not nested in it).
struct ManifestClients {
  HTTPClient http;
  WiFiClientSecure sec;
  WiFiClient plain;
};

struct DownloadWork {
  HTTPClient http;
  WiFiClientSecure sec;
  WiFiClient plain;
  fry::Sha256 sha;
  uint8_t digest[32];
  char hex[65];
};

// beginHttpsUrl() judges the heap after these exist against the gate's floors less kOtaClientsBytes + the BearSSL thunk
// (lib/fry_core/tls_sizing.h, tlsFloorsAtBegin): the block must be at least as big as the larger of the two.
static_assert(sizeof(DownloadWork) + 16 <= fry::kOtaClientsBytes, "DownloadWork outgrew kOtaClientsBytes");
static_assert(sizeof(ManifestClients) + 16 <= fry::kOtaClientsBytes, "ManifestClients outgrew kOtaClientsBytes");
// The manifest gate in platformio.ini is typed by hand; the measured table is the source of truth.
static_assert(HEAP_GATE_OTA_MANIFEST_BLOCK == fry::ota_heap::kManifestGateBlock,
              "HEAP_GATE_OTA_MANIFEST_BLOCK (platformio.ini) drifted from ota_heap_budget.h");
static_assert(HEAP_GATE_OTA_MANIFEST == fry::ota_heap::kManifestGateFree,
              "HEAP_GATE_OTA_MANIFEST (platformio.ini) drifted from ota_heap_budget.h");
static_assert(HEAP_GATE_OTA_DOWNLOAD_BLOCK == fry::ota_heap::kDownloadGateBlock,
              "HEAP_GATE_OTA_DOWNLOAD_BLOCK (platformio.ini) drifted from ota_heap_budget.h");
static_assert(HEAP_GATE_OTA_DOWNLOAD == fry::ota_heap::kDownloadGateFree,
              "HEAP_GATE_OTA_DOWNLOAD (platformio.ini) drifted from ota_heap_budget.h");
static_assert(HEAP_GATE_OTA_STREAM == fry::ota_heap::kStreamGateFree,
              "HEAP_GATE_OTA_STREAM (platformio.ini) drifted from ota_heap_budget.h");

// What the manifest decided: the download's arguments.
struct OtaPlan {
  // Capacities taken by checkNow() BEFORE the manifest session opens (reserveEarly): see there.
  static constexpr size_t kUrlCap = 128;     // release-asset URLs are about 100 characters
  static constexpr size_t kShaCap = 64;      // a sha256 in hex
  static constexpr size_t kVersionCap = 24;  // a SemVer with a pre-release tag
  String url;
  String sha;
  String version;
  void reserveEarly() {
    url.reserve(kUrlCap);
    sha.reserve(kShaCap);
    version.reserve(kVersionCap);
  }
};
#endif

#if defined(ARDUINO_ARCH_ESP8266)
// The largest free block when checkNow() started its manifest check (after the plan's Strings were reserved): what the download waits for.
static uint32_t s_blkAtCheckStart = 0;
// The largest block an earlier check started on, this boot (0 = none yet): what the next check waits for before it measures (settleBeforeCheck).
static uint32_t s_blkSettledBase = 0;

// Between the manifest and the download: the manifest connection's pcb (192 B), the pbuf of its last TLS record (112 B) and that record's
// tcp_seg (24 B) are freed by lwIP once the peer answers the close, a few milliseconds to a second after the clients are gone. The download's
// constructors must not run before that: they would run on a heap those blocks split, and where they land decides where the 432 B work block
// and the 6208 B BearSSL thunk go (lib/fry_core/ota_settle.h, bench X2: the download's block 29072 -> 23000 -> 22648 -> 15008 over seven checks).
// Bounded, and silent when there was nothing to wait for. The messages stay under 64 B: Serial.printf of a longer one allocates.
// It runs first thing in downloadAndApply(), after checkNow() released the manifest's clients, body and url (test_ota_release pins that block).
FRY_OTA_ESP8266_NOINLINE static void settleAfterManifest(uint32_t blkBefore) {
  const unsigned long t0 = millis();
  uint32_t blk = fry::queryMaxFreeBlock();
  while (fry::decideHeapSettle(blk, blkBefore, fry::kOtaSettleSlackBytes, static_cast<uint32_t>(millis() - t0),
                               fry::kOtaSettleMaxMs) == fry::SettleHold::Hold) {
    delay(fry::kOtaSettlePollMs);
    blk = fry::queryMaxFreeBlock();
  }
  const unsigned long waited = millis() - t0;
  if (waited == 0) return;
  const bool back = blk + fry::kOtaSettleSlackBytes >= blkBefore;
  Serial.printf_P(back ? PSTR("ota: settled %lu ms, blk %u (start %u)\n") : PSTR("ota: not settled %lu ms, blk %u (start %u)\n"), waited,
                  static_cast<unsigned>(blk), static_cast<unsigned>(blkBefore));
}

// Before the check: the report tick that ran just before it leaves a 24 B block, or a 192 B pcb with its 112 B pbuf, in the middle of the free region
// for up to a few seconds. A check that starts on that heap measures a block that is not the settled one, so settleAfterManifest's reference is
// wrong and the manifest gate samples a split heap (x3-tip bench: cycle C download-begin blk 26280 instead of 32808, cycle G manifest skipped at
// blk 29776 against 29808). Wait, bounded, for the block to be back where earlier checks started (lib/fry_core/ota_settle.h), then measure.
// Silent when there was nothing to wait for. The messages stay under 64 B: Serial.printf of a longer one allocates.
FRY_OTA_ESP8266_NOINLINE static void settleBeforeCheck() {
  const unsigned long t0 = millis();
  unsigned long changedAt = t0;
  uint32_t blk = fry::queryMaxFreeBlock();
  uint32_t last = blk;
  uint32_t held = 0;
  uint32_t stable = 0;
  while (fry::decideCheckStartSettle(blk, s_blkSettledBase, fry::kOtaSettleSlackBytes, held, stable, fry::kOtaSettleMaxMs) ==
         fry::SettleHold::Hold) {
    delay(fry::kOtaSettlePollMs);
    blk = fry::queryMaxFreeBlock();
    const unsigned long now = millis();
    if (blk != last) {
      last = blk;
      changedAt = now;
    }
    held = static_cast<uint32_t>(now - t0);
    stable = static_cast<uint32_t>(now - changedAt);
  }
  const uint32_t base = s_blkSettledBase;
  const bool back = base == 0 || blk + fry::kOtaSettleSlackBytes >= base;
  s_blkSettledBase = fry::nextCheckStartBaseline(base, blk, held >= fry::kOtaSettleMaxMs);
  if (held == 0) return;
  Serial.printf_P(back ? PSTR("ota: start settled %lu ms, blk %u (base %u)\n") : PSTR("ota: start not settled %lu ms, blk %u (base %u)\n"),
                  static_cast<unsigned long>(held), static_cast<unsigned>(blk), static_cast<unsigned>(base));
}
#endif

FRY_OTA_ESP8266_NOINLINE bool downloadAndApply(const String& url, const String& shaExpect,
                                               const String& newVersion) {
#if defined(ARDUINO_ARCH_ESP8266)
  settleAfterManifest(s_blkAtCheckStart);
  const std::unique_ptr<DownloadWork> work(new (std::nothrow) DownloadWork());
  if (!work) {
    FRY_PRINTLN("ota: no memory for the download client");
    return false;
  }
  HTTPClient& http = work->http;
  WiFiClientSecure& sec = work->sec;
  WiFiClient& plain = work->plain;
#else
  HTTPClient http;
  WiFiClientSecure sec;
  WiFiClient plain;
#endif
#if defined(ARDUINO_ARCH_ESP8266)
  // The image streams 16 KB records: the big receive buffer, never the manifest's medium one.
  if (!otaBeginUrl(http, sec, plain, url, /*smallReply=*/false)) {
#else
  if (!otaBeginUrl(http, sec, plain, url)) {
#endif
    FRY_PRINTLN("ota: begin failed");
#if defined(ARDUINO_ARCH_ESP8266)
    if (url.startsWith("https://")) s_heapRefused = true;  // as for the manifest: only Refuse can fail it
#endif
    return false;
  }
  http.setTimeout(20000);

  int code = http.GET();
  if (code != 200) {
    FRY_PRINTF("ota: HTTP %d\n", code);
    http.end();
    return false;
  }
  int len = http.getSize();
  if (len <= 0) {
    FRY_PRINTLN("ota: no Content-Length");
    http.end();
    return false;
  }
  // Gate before streaming the image in. The large CONTIGUOUS requirement exists only for the
  // https path, where BearSSL wants a 16 KB receive buffer in one block — see
  // HEAP_GATE_OTA_BLOCK in config.h for the field evidence that made total-free alone wrong.
  // A plain-http download has no such buffer, so demanding it there would refuse a perfectly
  // safe update: measured on COM11 at blk=34176 the http lab OTA was rejected by the
  // unconditional gate even though it needs none of that headroom. Bounded wait either way,
  // so a transient fragmentation dip becomes a short retry rather than a failed update.
  const bool isHttps = url.startsWith("https://");
#if defined(ARDUINO_ARCH_ESP8266)
  // This gate runs after http.GET(): BearSSL's contexts and its 16 KB input buffer are already allocated, so asking for a
  // 36864 B contiguous block (or 20000 B free) here measured the heap the session itself had just consumed, and could
  // never pass. The session's own need was gated before the connect (beginHttpsUrl, HEAP_GATE_OTA_DOWNLOAD*); what is
  // left is the 1 KB download buffer and the Updater's buffer, both new(nothrow).
  const uint32_t minBlock = 0;
  const uint32_t minFree = isHttps ? HEAP_GATE_OTA_STREAM : HEAP_GATE_OTA;
#else
  constexpr bool kBearsslSingleBuffer = false;  // ESP32 family uses mbedtls
  const uint32_t minBlock =
      fry::otaMinContiguousBlock(isHttps, kBearsslSingleBuffer, HEAP_GATE_OTA_BLOCK);
  const uint32_t minFree = HEAP_GATE_OTA;
#endif
  if (!fry::waitForHeapGate(minFree, minBlock)) {
    FRY_PRINTF("ota: heap gate failed (%s)\n",
                  minBlock ? "total free or largest contiguous block" : "total free");
    http.end();
    return false;
  }
  if (!Update.begin(len)) {
    FRY_PRINTF("ota: Update.begin failed (bin %dB too big for slot?)\n", len);
    http.end();
    return false;
  }

#if defined(ARDUINO_ARCH_ESP8266)
  fry::Sha256& sha = work->sha;
  // The Updater has no abort() and end(false) STAGES a complete stream, so the last byte stays out of it until the digest matched.
  fry::HeldTailWriter<UpdaterClass> upd(Update, static_cast<size_t>(len));
#else
  fry::Sha256 sha;
#endif
  WiFiClient* stream = http.getStreamPtr();
  constexpr size_t kBufBytes = 1024;
#if defined(ARDUINO_ARCH_ESP8266)
  // On the heap, not the 4 KB loop stack: this frame is on the stack (below checkNow()) while the TLS
  // session opens, and 1 KB of it is what took the connect past the end of the stack.
  std::unique_ptr<uint8_t[]> bufHeap(new (std::nothrow) uint8_t[kBufBytes]);
  if (!bufHeap) {
    FRY_PRINTLN("ota: no memory for the download buffer");
    upd.discard();
    http.end();
    return false;
  }
  uint8_t* const buf = bufHeap.get();
#else
  uint8_t buf[kBufBytes];
#endif
  size_t done = 0;
  unsigned long lastData = millis();
  unsigned long lastLog = 0;
  while (done < static_cast<size_t>(len)) {
    size_t avail = stream->available();
    if (avail) {
      int r = stream->readBytes(buf, avail > kBufBytes ? kBufBytes : avail);
      if (r <= 0) break;
      sha.update(buf, r);
#if defined(ARDUINO_ARCH_ESP8266)
      if (!upd.write(buf, r)) {
#else
      if (Update.write(buf, r) != static_cast<size_t>(r)) {
#endif
        FRY_PRINTLN("ota: write failed");
#if defined(ARDUINO_ARCH_ESP8266)
        upd.discard();
#else
        Update.abort();
#endif
        http.end();
        return false;
      }
      done += r;
      lastData = millis();
      if (millis() - lastLog > 3000) {
        FRY_PRINTF("ota: downloading %u/%d KB\n", static_cast<unsigned>(done / 1024), len / 1024);
        lastLog = millis();
      }
    } else {
      if (!stream->connected()) break;
      if (millis() - lastData > 20000) {
        FRY_PRINTLN("ota: stall 20s");
        break;
      }
      delay(1);
    }
    yield();
  }
  http.end();

  if (done != static_cast<size_t>(len)) {
    FRY_PRINTF("ota: incomplete download %u/%d\n", static_cast<unsigned>(done), len);
#if defined(ARDUINO_ARCH_ESP8266)
    upd.discard();
#else
    Update.abort();
#endif
    return false;
  }

#if defined(ARDUINO_ARCH_ESP8266)
  uint8_t(&digest)[32] = work->digest;
  char(&hex)[65] = work->hex;
#else
  uint8_t digest[32];
  char hex[65];
#endif
  sha.finish(digest);
  fry::bytesToHexUpper(digest, 32, hex, sizeof(hex));
#if defined(ARDUINO_ARCH_ESP8266)
  // The digest compare allocates nothing: two Strings whose copies both fail are both empty, and empty Strings are equal, which would accept ANY image
  // when the stream has used up the heap (lib/fry_core/ota_sha_match.h). An empty or invalid manifest digest has length 0 and never matches.
  fry::asciiLowerInPlace(hex);
  const bool shaMismatch = !fry::sha256HexMatches(hex, shaExpect.c_str(), shaExpect.length());
  if (shaMismatch) {
    FRY_PRINTF("ota: sha256 mismatch (got %.16s want %.16s) - rejected\n", hex, shaExpect.c_str());
    // The last byte is still held, so this drops an unfinished update and nothing is staged (lib/fry_core/ota_stage_guard.h). Clearing the
    // eboot command as well is what eboot does itself after it has run one: a command left in RTC memory by anything else cannot boot this image.
    upd.discard();
    eboot_command_clear();
    return false;
  }
#else
  String got = hex;
  got.toLowerCase();
  String want = shaExpect;
  want.toLowerCase();
  if (got != want) {
    FRY_PRINTF("ota: sha256 mismatch (got %.16s want %.16s) - rejected\n", got.c_str(), want.c_str());
    Update.abort();
    return false;
  }
#endif

#if defined(ARDUINO_ARCH_ESP8266)
  if (!upd.commit()) {
#else
  if (!Update.end(true)) {
#endif
    FRY_PRINTLN("ota: Update.end failed");
    return false;
  }

  fry_config::setOtaPending(newVersion.c_str());
  FRY_PRINTF("ota: applied %s sha=ok\n", newVersion.c_str());
  delay(500);
  ESP.restart();
  return true;  // unreachable — kept for a clean return type after ESP.restart()
}

}  // namespace

void init() {
#if !defined(ARDUINO_ARCH_ESP8266)
  s_rolledBack = esp_ota_get_last_invalid_partition() != nullptr;
  esp_ota_img_states_t state;
  s_pendingVerify = esp_ota_get_state_partition(esp_ota_get_running_partition(), &state) == ESP_OK &&
                    state == ESP_OTA_IMG_PENDING_VERIFY;
  if (s_pendingVerify) {
    s_confirmPending = true;
    FRY_PRINTF("ota: image %s is pending verification - valid once hardwareapi answered and it "
                  "ran %lus, rolled back after %lus of Wi-Fi without an answer\n",
                  FRY_FIRMWARE_VERSION, static_cast<unsigned long>(kMarkValidSettleMs / 1000),
                  static_cast<unsigned long>(FRY_OTA_VERIFY_DEADLINE_MS / 1000));
  }
#endif
  // One-boot markers for the strike bookkeeping below; consumed whichever image reads them.
  const bool plannedRestart = fry_config::getOtaPlannedRestart();
  if (plannedRestart) fry_config::setOtaPlannedRestart(false);
  const bool counterRolledBack = fry_config::getOtaRolledBack();
  if (counterRolledBack) fry_config::setOtaRolledBack(false);

  String pending = fry_config::getOtaPending();
  if (pending.length() == 0) return;

  if (pending == FRY_FIRMWARE_VERSION) {
    s_confirmPending = true;
    uint8_t fails = fry_config::getOtaBootFails();
    fry::OtaBootCounter counter(fails);
    counter.increment();
    fry_config::setOtaBootFails(counter.count());
    if (counter.shouldRollBack(OTA_BOOT_FAIL_LIMIT)) {
      manualRollback();  // does not return
    }
    FRY_PRINTF("ota: first boot %s - awaiting confirmation (%u/%u attempts)\n",
                  FRY_FIRMWARE_VERSION, counter.count(), OTA_BOOT_FAIL_LIMIT);
  } else {
    if (fry::shouldRecordBadVersion(pending.c_str(), FRY_FIRMWARE_VERSION,
                                    s_rolledBack || counterRolledBack)) {
      // The image we installed did not survive and we are back on this one. The single writer of
      // the strikes (PROTOCOL.md 11.8): one per rollback, none for a planned restart.
      const String badver = fry_config::getOtaBadVer();
      bool changed = false;
      const uint8_t strikes = fry::nextStrikeCount(badver.c_str(), fry_config::getOtaBadN(),
                                                   pending.c_str(), plannedRestart, &changed);
      if (changed) {
        fry_config::setOtaStrikes(pending.c_str(), strikes);
        s_firstCheckAfterRollback = true;
        FRY_PRINTF("ota: %s was rolled back - running %s, strike %u/%u for %s%s\n", pending.c_str(),
                      FRY_FIRMWARE_VERSION, strikes, fry::kOtaPermanentStrikes, pending.c_str(),
                      strikes >= fry::kOtaPermanentStrikes ? " - it will not be installed again"
                                                           : " - retried after the next 6 h check");
      } else if (plannedRestart) {
        FRY_PRINTF("ota: %s was rolled back by a planned restart - not counted\n", pending.c_str());
      }
    }
    FRY_PRINTF("ota: boot %s with pending=%s - flag cleared\n", FRY_FIRMWARE_VERSION, pending.c_str());
    fry_config::clearOtaPending();
    fry_config::clearOtaBootFails();
  }
}

void noteHeartbeat(int http, const char* what) {
#if defined(FRY_TEST_FAULT) && FRY_TEST_FAULT == 2
  (void)http;
  (void)what;
  return;  // test fault: this image never proves itself, so loopGuard() must roll it back
#else
  const bool first = s_heartbeat.note(http, millis());
#if defined(FRY_TEST_FAULT) && FRY_TEST_FAULT == 3
  if (first) {
    s_faultCrashAtMs = millis() + 60000UL;  // inside the settle window: must roll back
    if (s_faultCrashAtMs == 0) s_faultCrashAtMs = 1;
  }
#else
  (void)first;
#endif
  if (http > 0) tryMarkValid(what);  // every answer while pending retries a failed mark
#endif
}

void notePlannedRestart() {
  if (s_confirmPending) fry_config::setOtaPlannedRestart(true);
}

void loopGuard() {
  const unsigned long now = millis();
#if defined(FRY_TEST_FAULT) && FRY_TEST_FAULT == 3
  if (s_faultCrashAtMs && static_cast<long>(now - s_faultCrashAtMs) >= 0) {
    FRY_PRINTLN("[fault] FRY_TEST_FAULT=3 - crashing 60 s after the first heartbeat");
    Serial.flush();
    abort();
  }
#endif
  // The settle window can end between answers: one attempt here, later ones ride on answers.
  if (s_confirmPending && !s_markAttempted &&
      fry::decideMarkValid(true, s_heartbeat.anyResponse(), now, kMarkValidSettleMs)) {
    s_markAttempted = true;
    tryMarkValid("settle window");
  }
#if !defined(ARDUINO_ARCH_ESP8266)
  // Only time with the station associated and holding an IP counts toward the deadline: an
  // outage right after the update is not the image's fault (round 2 F2).
  s_verifyMs = fry::accrueVerifyMs(s_verifyMs, static_cast<uint32_t>(now - s_lastGuardMs),
                                   fry_wifi::isConnected());
  s_lastGuardMs = now;
  if (s_rollbackFailed ||
      fry::decideRollbackGuard(s_pendingVerify, s_heartbeat.anyResponse(), s_verifyMs,
                               FRY_OTA_VERIFY_DEADLINE_MS) != fry::GuardAction::Rollback) {
    return;
  }
  FRY_PRINTF("ota: no hardwareapi answer after %lus of Wi-Fi on pending image %s - rolling back\n",
                static_cast<unsigned long>(s_verifyMs / 1000), FRY_FIRMWARE_VERSION);
  Serial.flush();
  esp_ota_mark_app_invalid_rollback_and_reboot();
  // Only reached when there is nothing to roll back to. Stay, keep reporting "pending", and let a
  // later answer mark the image valid (tryMarkValid) so a forward fix can still arrive.
  s_rollbackFailed = true;
  FRY_PRINTF("ota: rollback impossible (no other valid image) - staying on pending %s\n",
                FRY_FIRMWARE_VERSION);
#endif
}

int32_t heartbeatAgeS() { return s_heartbeat.ageS(millis()); }

const char* imageStateName() {
#if defined(ARDUINO_ARCH_ESP8266)
  return fry::otaImageStateName(fry::otaImageState(s_confirmPending, false));
#else
  return fry::otaImageStateName(fry::otaImageState(s_pendingVerify, s_rolledBack));
#endif
}

void confirmGood() {
  if (fry_config::getOtaPending().length() == 0) return;
  fry_config::clearOtaPending();
  fry_config::clearOtaBootFails();
  FRY_PRINTF("ota: %s confirmed\n", FRY_FIRMWARE_VERSION);
}

#if defined(ARDUINO_ARCH_ESP8266)
FRY_OTA_ESP8266_NOINLINE static bool evaluateManifest(const String& body, OtaPlan& plan);

// What fry::readManifestBody() (lib/fry_core/ota_manifest_read.h) needs of the connection and of the String it fills.
struct ManifestConn {
  WiFiClient& c;
  bool connected() { return c.connected(); }
  int available() { return c.available(); }
  int read(uint8_t* b, size_t n) { return c.read(b, n); }
  uint32_t nowMs() { return millis(); }
  void idle() { delay(1); }
};

// A String that stops at the manifest cap: the sink for the sized read, and the Print HTTPClient::writeToPrint() fills for a body
// of unknown length.
class ManifestSink : public Print {
 public:
  explicit ManifestSink(String& s) : s_(s) {}
  size_t write(uint8_t b) override { return write(&b, 1); }
  size_t write(const uint8_t* p, size_t n) override {
    if (s_.length() + n > fry::kManifestMaxBytes) return 0;
    return s_.concat(reinterpret_cast<const char*>(p), static_cast<unsigned int>(n)) ? n : 0;
  }
  bool append(const uint8_t* p, size_t n) { return write(p, n) == n; }

 private:
  String& s_;
};

// The manifest body after a 200: read exactly Content-Length bytes by our own loop; a body of unknown length goes through
// HTTPClient's bounded stream copy with its result checked. Prints its own line when the body did not arrive whole.
// A frame of its own (the GET is over, no connection opens under it), like evaluateManifest().
FRY_OTA_ESP8266_NOINLINE static fry::ManifestRead readManifest(HTTPClient& http, WiFiClientSecure& sec, String& body) {
  const int size = http.getSize();
  fry::ManifestRead r = fry::ManifestRead::Ok;
  int err = 0;
  switch (fry::classifyManifestSize(size)) {
    case fry::ManifestSize::TooBig:
      r = fry::ManifestRead::TooBig;
      break;
    case fry::ManifestSize::Sized: {
      WiFiClient* stream = http.getStreamPtr();
      if (!stream) {
        r = fry::ManifestRead::Closed;
      } else if (!body.reserve(static_cast<unsigned int>(size) + 1)) {
        r = fry::ManifestRead::NoRoom;
      } else {
        ManifestConn conn{*stream};
        ManifestSink sink(body);
        r = fry::readManifestBody(conn, static_cast<size_t>(size), fry::kManifestReadTimeoutMs, sink);
      }
      break;
    }
    case fry::ManifestSize::Unsized: {
      ManifestSink sink(body);
      err = http.writeToPrint(&sink);
      if (err <= 0) r = fry::ManifestRead::Closed;
      break;
    }
  }
  if (r != fry::ManifestRead::Ok) {
    // got/of say how much arrived, err is HTTPClient's own code (unsized only), ssl is BearSSL's last error (0 = none).
    FRY_PRINTF("ota: manifest read failed (%s) got=%u of %d err=%d ssl=%d blk=%u\n", fry::manifestReadName(r),
                  static_cast<unsigned>(body.length()), size, err, sec.getLastSSLError(),
                  static_cast<unsigned>(fry::queryMaxFreeBlock()));
  }
  return r;
}
#endif

bool checkNow() {
#if defined(ARDUINO_ARCH_ESP8266)
  s_heapRefused = false;
#endif
#if defined(ARDUINO_ARCH_ESP8266)
  s_readFailed = false;
#endif
#if !defined(ARDUINO_ARCH_ESP8266)
  // esp_ota_begin() refuses while the running image is unconfirmed, and the other slot is the
  // rollback target: do not download over it before this image has proved itself.
  if (s_pendingVerify) {
    FRY_PRINTLN("ota: manifest check skipped - running image still pending verification");
    return false;
  }
#endif
  // Round 2 F4: a keyless USER_SUPPLIED board makes no hardwareapi call at all, so a new image
  // could never verify - it would only roll back. Update once the owner has written the key.
  {
    char key[40] = {0};
    fry_identity::ensureMinerKey(key, sizeof(key));
    if (!fry::keyAllowsJoin(fry::kBuildKeyModel, key[0] != 0)) {
      if (!s_loggedKeyless) {
        s_loggedKeyless = true;
        FRY_PRINTLN("ota: manifest check skipped - no miner key yet");
      }
      return false;
    }
  }
  String manifestUrl = fry_config::getOtaUrl();
  if (manifestUrl.length() == 0) manifestUrl = FRY_OTA_DEFAULT_MANIFEST;
  if (manifestUrl.length() == 0) return false;

#if defined(ARDUINO_ARCH_ESP8266)
  // The report tick before this check may have left lwIP blocks in the middle of the free region: wait for the heap to settle before the gate
  // samples it and before the block the download will wait for is measured.
  settleBeforeCheck();
#endif

#if defined(FRY_BOARD_ESP8266)
  // Do not even open an HTTPS session for the manifest unless it is affordable: the gate is the
  // MEASURED need of the 8192/512 session plus a margin (lib/fry_core/ota_heap_budget.h), sampled before
  // the clients and BearSSL's stack thunk exist. The rest of this comment predates that and is about the
  // 16384/512 session the check used to open. The release manifest lives on GitHub, which does not honour MFLN, so on a
  // fragmented heap the 512/512 fallback cannot carry its handshake and BearSSL fails hard
  // rather than returning an error. Skipping the check costs one deferred update; not
  // skipping it cost a crash-and-reboot on COM11. Plain-HTTP manifests (the lab server) are
  // unaffected and still checked, which is how OTA is exercised on this chip.
  if (manifestUrl.startsWith("https://") &&
      !fry::waitForHeapGate(HEAP_GATE_OTA_MANIFEST, HEAP_GATE_OTA_MANIFEST_BLOCK, 1)) {
    // Print the numbers, not just the verdict. "insufficient" alone cost real diagnostic time:
    // a board carrying a stale plain-http lab override never reaches this branch at all, and its
    // unrelated "manifest fetch HTTP -1" (lab server unreachable) was read for two runs as
    // evidence of a TLS/heap failure on the GitHub path that was in fact never attempted.
    // With the shortfall visible, the two situations can never be confused again.
    FRY_PRINTF("ota: skipped https manifest check - need blk>=%u free>=%u, have blk=%u free=%u\n",
                  static_cast<unsigned>(HEAP_GATE_OTA_MANIFEST_BLOCK), static_cast<unsigned>(HEAP_GATE_OTA_MANIFEST),
                  static_cast<unsigned>(fry::queryMaxFreeBlock()),
                  static_cast<unsigned>(ESP.getFreeHeap()));
    s_heapRefused = true;
    return false;
  }
#endif

#if defined(ARDUINO_ARCH_ESP8266)
  // The plan's Strings are the one thing that outlives the manifest session (clients.reset() below). umm_malloc is best-fit and carves the low
  // end of the block it picks, so Strings born while the session is live sit above its blocks and split the free region the download
  // needs (heap map at dl-begin: 104 B + 88 B cut the largest block from 28280 to 14768). Take their capacity first: below the session.
  OtaPlan plan;
  plan.reserveEarly();
  // Where the check starts: the download's constructors wait for the largest block to be back at this (settleAfterManifest).
  s_blkAtCheckStart = fry::queryMaxFreeBlock();
  std::unique_ptr<ManifestClients> clients(new (std::nothrow) ManifestClients());
  if (!clients) {
    FRY_PRINTLN("ota: no memory for the manifest client");
    return false;
  }
  HTTPClient& http = clients->http;
  WiFiClientSecure& sec = clients->sec;
  WiFiClient& plain = clients->plain;
#else
  HTTPClient http;
  WiFiClientSecure sec;
  WiFiClient plain;
#endif
#if defined(ARDUINO_ARCH_ESP8266)
  // A ~2 KB JSON behind a 4146 B Certificate record: 8192/512 instead of 16384/512 (lib/fry_core/tls_sizing.h).
  if (!otaBeginUrl(http, sec, plain, manifestUrl, /*smallReply=*/true)) {
#else
  if (!otaBeginUrl(http, sec, plain, manifestUrl)) {
#endif
    FRY_PRINTLN("ota: manifest fetch begin failed");
#if defined(ARDUINO_ARCH_ESP8266)
    // On ESP8266 an https begin() can only fail by beginHttpsUrl()'s Refuse (HTTPClient::begin cannot fail for these URLs).
    if (manifestUrl.startsWith("https://")) s_heapRefused = true;
#endif
    return false;
  }
  int code = http.GET();
  if (code != 200) {
    // Log the largest contiguous block alongside the code. HTTPClient collapses connect-refused,
    // iobuf-OOM and TLS-handshake-failure all into -1, and the 30 s [health] line samples far too
    // coarsely to catch the allocation peak, so without blk here a -1 is undiagnosable.
    FRY_PRINTF("ota: manifest fetch HTTP %d (blk=%u)\n", code,
                  static_cast<unsigned>(fry::queryMaxFreeBlock()));
    http.end();
    return false;
  }
#if defined(ARDUINO_ARCH_ESP8266)
  // Not getString(): it hands back "" when the body is lost (readManifest()).
  String body;
  const fry::ManifestRead rd = readManifest(http, sec, body);
  if (rd != fry::ManifestRead::Ok) {
    if (fry::manifestReadRetrySoon(rd)) s_readFailed = true;
    http.end();
    return false;
  }
#else
  String body = http.getString();
#endif
  http.end();

#if defined(ARDUINO_ARCH_ESP8266)
  // The rest of the decision runs in evaluateManifest(), a frame of its own that is gone again before the download
  // opens its connection (see ManifestClients above). The ESP32 keeps one function.
  if (!evaluateManifest(body, plan)) return false;
  // The manifest check is over: give back what it held before the download opens its own session.
  body = String();
  manifestUrl = String();
  clients.reset();
  return downloadAndApply(plan.url, plan.sha, plan.version);
}

FRY_OTA_ESP8266_NOINLINE static bool evaluateManifest(const String& body, OtaPlan& plan) {
#endif
  JsonDocument doc;
  if (deserializeJson(doc, body)) {
    FRY_PRINTLN("ota: manifest parse failed");
    return false;
  }

  const char* latest = doc["firmware_version"] | ""; FRY_OLOSTEP_SET_KILL(doc)
  const char* channel = doc["channel"] | "";
  JsonObject build = doc["builds"][FRY_BUILD_ENV];
  const char* url = build["url"] | "";
  const char* sha = build["sha256"] | "";
  // Only ever move FORWARD, by SemVer precedence (0.4.1-rc.1 < 0.4.1). This was strcmp(...) != 0,
  // which updated in either direction, so a device running a newer build than the published
  // manifest downgraded itself (observed on the bench: cur=0.1.1 latest=0.1.0 action=update).
  // Deliberate rollback is slot-based, not manifest-driven. A manifest for the other channel, the
  // version this board is holding strikes for (skipped on the first check after a rollback, for
  // good at 3 - PROTOCOL.md 11.8), or a manifest without this env's build (a chip left out on
  // purpose) never updates.
  String badver = fry_config::getOtaBadVer();
  uint8_t badn = badver.length() ? fry_config::getOtaBadN() : 0;
  if (fry::strikesReset(latest, badver.c_str())) {
    fry_config::setOtaStrikes("", 0);
    FRY_PRINTF("ota: manifest names %s - strikes for %s cleared\n", latest, badver.c_str());
    badver = "";
    badn = 0;
  }
  const bool skip = fry::skipBadVersion(latest, badver.c_str(), badn, s_firstCheckAfterRollback);
  s_firstCheckAfterRollback = false;
  // Staged rollout (lib/fry_core/ota_rollout.h): an optional manifest "rollout" object. Absent or
  // malformed means no gate (0.4.7 behaviour); only a well-formed one that excludes this board
  // closes it. Decided from SHA-256 of the miner key; the key and the hash are never logged. A
  // board without a key yet cannot be bucketed and is not gated.
  bool inRollout = true;
  uint32_t rolloutBucketNo = 0;
  {
    char rolloutKey[40] = {0};
    fry_identity::ensureMinerKey(rolloutKey, sizeof(rolloutKey));
    if (rolloutKey[0] != 0) {
      uint8_t digest[32];
      fry::Sha256::hash(reinterpret_cast<const uint8_t*>(rolloutKey), strlen(rolloutKey), digest);
      const fry::RolloutVerdict rv = fry::evaluateRollout(doc, digest);
      inRollout = fry::rolloutAllows(rv);
      if (rv == fry::RolloutVerdict::Malformed && !s_loggedRolloutMalformed) {
        s_loggedRolloutMalformed = true;
        FRY_PRINTLN("ota: rollout field malformed - ignored");
      }
      rolloutBucketNo = fry::rolloutBucket(digest);
    }
    memset(rolloutKey, 0, sizeof(rolloutKey));
  }
  const fry::OtaDecision decision = fry::decideOtaUpdate(
      channel, FRY_OTA_CHANNEL, latest, FRY_FIRMWARE_VERSION, skip ? badver.c_str() : "", url, sha,
      inRollout);
  if (decision == fry::OtaDecision::NotInRollout) {
    FRY_PRINTF("ota: rollout skip bucket=%u\n", static_cast<unsigned>(rolloutBucketNo));
  }
  const bool willUpdate = decision == fry::OtaDecision::Update;
  FRY_PRINTF("ota: manifest check cur=%s latest=%s action=%s\n", FRY_FIRMWARE_VERSION,
                strlen(latest) ? latest : "?", willUpdate ? "update" : "none");
  if (!willUpdate) {
    if (decision != fry::OtaDecision::NotNewer) {
      FRY_PRINTF("ota: not updating - %s (manifest channel=%s, ours=%s, strikes=%u)\n",
                    fry::otaDecisionName(decision), strlen(channel) ? channel : "prod", FRY_OTA_CHANNEL,
                    static_cast<unsigned>(badn));
    }
    return false;
  }

#if defined(ARDUINO_ARCH_ESP8266)
  plan.url = url;
  plan.sha = sha;
  plan.version = latest;
  return true;
#else
  return downloadAndApply(url, sha, latest);
#endif
}

#if defined(ARDUINO_ARCH_ESP8266)
// Hold a due check while lwIP still has closed connections in TIME_WAIT, or this side's pcbs in a closing state (FIN_WAIT_1/2,
// CLOSING, LAST_ACK: the same pcb a moment before TIME_WAIT), for at most fry::kOtaTimeWaitMaxHoldMs (lib/fry_core/ota_timewait.h: two
// such pcbs cost the heap 7784 B of contiguous block until they expire ~120 s after the TLS calls that left them). Never blocks: true
// means "skip this loop pass", and the check stays due, so the decision is taken again on the next pass.
static bool holdForTimeWait(unsigned long now) {
  static bool holding = false;
  static unsigned long since = 0;
  const uint32_t tw = fry::countTimeWaitPcbs();
  const uint32_t closing = fry::countClosingPcbs();
  const uint32_t heldMs = holding ? static_cast<uint32_t>(now - since) : 0;
  if (fry::decideTimeWaitHold(tw + closing, heldMs, fry::kOtaTimeWaitMaxHoldMs) == fry::TwHold::Hold) {
    if (!holding) {
      holding = true;
      since = now;
      Serial.printf_P(PSTR("ota: check held, %u TIME_WAIT + %u closing pcb(s), at most %lu s\n"),
                      static_cast<unsigned>(tw), static_cast<unsigned>(closing),
                      static_cast<unsigned long>(fry::kOtaTimeWaitMaxHoldMs / 1000UL));
    }
    return true;
  }
  if (holding) {
    holding = false;
    Serial.printf_P(PSTR("ota: check released after %lu ms (tw=%u cl=%u%s)\n"),
                    static_cast<unsigned long>(heldMs), static_cast<unsigned>(tw), static_cast<unsigned>(closing),
                    tw + closing ? ", bound reached" : "");
  }
  return false;
}
#endif

#if defined(ARDUINO_ARCH_ESP8266)
// After a check: the normal wait, or the bounded shorter one when a heap gate refused it or its manifest body did not arrive whole
// (lib/fry_core/ota_retry.h). Each has its own run of retries; a check is at most one of the two.
static void afterCheck(unsigned long now) {
  uint32_t wait = fry::otaNextCheckDelayMs(s_heapRefused, s_heapRetries, OTA_CHECK_MS);
  const uint32_t readWait = fry::otaNextCheckDelayMs(s_readFailed, s_readRetries, OTA_CHECK_MS);
  if (readWait < wait) wait = readWait;
  s_lastCheckMs = now - (OTA_CHECK_MS - wait);  // the next check fires `wait` after `now`
}
#endif

void tick() {
  unsigned long now = millis();
  if (!s_firstCheckDone) {
#if defined(ARDUINO_ARCH_ESP8266)
    // Until the first check s_lastCheckMs is unused (0): it holds the time of the first tick (tick() is only reached once Wi-Fi is up).
    if (s_lastCheckMs == 0) s_lastCheckMs = now;
    // Not while the boot's asynchronous 504 B allocation (7.8 s after the connect) can still land inside the check.
    if (fry::otaFirstCheckWaitMs(static_cast<uint32_t>(now), static_cast<uint32_t>(s_lastCheckMs)) != 0) return;
    if (holdForTimeWait(now)) return;
#endif
    s_firstCheckDone = true;
    s_lastCheckMs = now;
    checkNow();
#if defined(ARDUINO_ARCH_ESP8266)
    afterCheck(now);
#endif
    return;
  }
  if (now - s_lastCheckMs < OTA_CHECK_MS) return;
#if defined(ARDUINO_ARCH_ESP8266)
  if (holdForTimeWait(now)) return;
#endif
  s_lastCheckMs = now;
  checkNow();
#if defined(ARDUINO_ARCH_ESP8266)
  afterCheck(now);
#endif
}

}  // namespace fry_ota

extern "C" void fry_trigger_ota_now() { fry_ota::checkNow(); }
