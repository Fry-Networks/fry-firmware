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
#include "ota_boot_flow.h"
#include "ota_confirm.h"
#include "ota_first_check.h"
#include "ota_health.h"
#include "ota_heap_budget.h"
#include "ota_manifest_read.h"
#include "ota_redirect.h"
#include "ota_retry.h"
#include "ota_rollback_json.h"
#include "ota_rollout_json.h"
#include "ota_session.h"
#include "ota_settle.h"
#include "ota_hold_release.h"
#include "ota_timewait.h"
#include "ota_version_guard.h"
#include "sha256.h"
#include "tls_sizing.h"
#include "trigger_hooks.h"
#include "wifi_station.h"

#if !defined(ARDUINO_ARCH_ESP8266)
#include <esp_ota_ops.h>
#include <esp_system.h>  // esp_reset_reason()
#include <esp_core_dump.h>
#include <esp_partition.h>
#include <stdlib.h>
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
// Early confirm and probation (lib/fry_core/ota_confirm.h).
bool s_startupDone = false;     // the tunnel bring-up attempt is over (main.cpp: noteStartupDone)
unsigned long s_startupDoneMs = 0;  // when
uint8_t s_loopPasses = 0;       // loopGuard() passes since then
bool s_earlyAttempted = false;  // loopGuard's one early confirm attempt; answers retry after it
bool s_earlyOk = false;         // core health was proven: tryMarkValid() skips the settle window
bool s_inProbation = false;     // this version's install-attempt record is still open
uint8_t s_probFails = 0;        // fry_ota.bootfails as read at init, kept current
bool s_tunnelBringUp = false;   // the tunnel bring-up was attempted (vpn_wireguard.cpp)
bool s_tunnelFetch = false;     // the tunnel provisioning fetch completed one attempt
bool s_pocOk = false;           // a PoC or lease request was answered 2xx this boot
bool s_healthGaveUp = false;    // the health note could not be written; not retried every pass
fry::AttemptRecord s_rec;       // this version's install-attempt record as stored
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

// Selects the OTA slot that is NOT running for the next boot. fry_ota.pending is left naming this version
// and fry_ota.rbk is set, so the previous image's init() counts the strike: it is the only writer of the
// strikes. Returns false (and leaves nothing set) when there is no slot to go back to or it fails its check.
bool selectOtherSlot() {
#if defined(ARDUINO_ARCH_ESP8266)
  FRY_PRINTLN("ota: boot-fail limit reached - ROLLBACK IMPOSSIBLE on ESP8266 (one slot)");
  fry_config::clearOtaPending();
  return false;
#else
  const esp_partition_t* running = esp_ota_get_running_partition();
  const esp_partition_t* other = esp_ota_get_next_update_partition(nullptr);
  if (other && running && other->address != running->address) {
    FRY_PRINTLN("ota: boot-fail limit reached - booting the other OTA slot");
    fry_config::setOtaRolledBack(true);
    if (esp_ota_set_boot_partition(other) != ESP_OK) {  // the slot failed its image check: stay
      fry_config::setOtaRolledBack(false);
      fry_config::clearOtaPending();
      return false;
    }
    return true;
  }
  FRY_PRINTLN("ota: boot-fail limit reached but no other OTA slot found - staying");
  fry_config::clearOtaPending();
  return false;
#endif
}

// Boot-counter rollback: boot into whichever OTA slot is NOT currently running. The second line
// behind the bootloader's own app rollback (see ota_client.h), for boards whose bootloader - from
// their first flash - lacks it.
void manualRollback() {
  selectOtherSlot();
  fry_config::clearOtaBootFails();
  delay(200);
  ESP.restart();
}

#if !defined(ARDUINO_ARCH_ESP8266)
// The previous OTA slot can be booted: it is a different slot, its OTA state is not a failed or never-booted one, and
// it carries an app descriptor. esp_ota_set_boot_partition() runs the full image check once more when it is used.
bool otherSlotIntact() {
  const esp_partition_t* running = esp_ota_get_running_partition();
  const esp_partition_t* other = esp_ota_get_next_update_partition(nullptr);
  if (!running || !other || other->address == running->address) return false;
  esp_ota_img_states_t st;
  if (esp_ota_get_state_partition(other, &st) == ESP_OK &&
      (st == ESP_OTA_IMG_INVALID || st == ESP_OTA_IMG_ABORTED || st == ESP_OTA_IMG_NEW ||
       st == ESP_OTA_IMG_PENDING_VERIFY)) {
    return false;
  }
  esp_app_desc_t desc;
  return esp_ota_get_partition_description(other, &desc) == ESP_OK;
}

// Evidence that THIS build crashed earlier: the core dump partition holds a dump whose ELF sha256 is the
// running image's. Panics and the interrupt/task watchdogs leave one; a power cut, an EN or USB reset, a
// restart and a brownout do not. Unavailable when core dumps to flash are compiled out or there is no partition.
fry::CrashEvidence thisBuildCrashed() {
#if defined(CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH) && defined(CONFIG_ESP_COREDUMP_DATA_FORMAT_ELF)
  if (!esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_COREDUMP, nullptr)) {
    return fry::CrashEvidence::Unavailable;
  }
  if (esp_core_dump_image_check() != ESP_OK) return fry::CrashEvidence::No;  // no dump, or an unreadable one
  esp_core_dump_summary_t* sum = static_cast<esp_core_dump_summary_t*>(calloc(1, sizeof(esp_core_dump_summary_t)));
  if (!sum) return fry::CrashEvidence::Unavailable;
  bool same = false;
  char mine[APP_ELF_SHA256_SZ] = {0};
  if (esp_core_dump_get_summary(sum) == ESP_OK && esp_ota_get_app_elf_sha256(mine, sizeof(mine)) > 0) {
    same = strncmp(reinterpret_cast<const char*>(sum->app_elf_sha256), mine, CONFIG_APP_RETRIEVE_LEN_ELF_SHA) == 0;
  }
  free(sum);
  return same ? fry::CrashEvidence::Yes : fry::CrashEvidence::No;
#else
  return fry::CrashEvidence::Unavailable;
#endif
}

void copyString(const String& s, char* out, size_t cap) {
  if (cap == 0) return;
  strncpy(out, s.c_str(), cap - 1);
  out[cap - 1] = 0;
}

// The ports of lib/fry_core/ota_boot_flow.h on the real NVS, esp_ota_* and the core dump.
class RealBootPorts : public fry::OtaBootPorts {
 public:
  void getAttempts(char* out, size_t cap) override { copyString(fry_config::getOtaAttempts(), out, cap); }
  bool setAttempts(const char* record) override { return fry_config::setOtaAttempts(record); }
  void clearAttempts() override { fry_config::clearOtaAttempts(); }
  uint8_t getBootFails() override { return fry_config::getOtaBootFails(); }
  bool setBootFails(uint8_t v) override { return fry_config::setOtaBootFailsChecked(v); }
  void getBadVer(char* out, size_t cap) override { copyString(fry_config::getOtaBadVer(), out, cap); }
  uint8_t getBadN() override { return fry_config::getOtaBadN(); }
  void getUrl(char* out, size_t cap) override { copyString(fry_config::getOtaUrl(), out, cap); }
  void setUrl(const char* url) override { fry_config::setOtaUrl(url); }
  void getQuarantined(char* out, size_t cap) override { copyString(fry_config::getOtaQuarantined(), out, cap); }
  void setQuarantined(const char* version) override { fry_config::setOtaQuarantined(version); }
  void setPending(const char* version) override { fry_config::setOtaPending(version); }
  bool pendingBoot() override { return s_pendingVerify || fry_config::getOtaPending() == FRY_FIRMWARE_VERSION; }
  uint32_t resetReason() override { return static_cast<uint32_t>(esp_reset_reason()); }
  bool otherSlotIntact() override { return ::fry_ota::otherSlotIntact(); }
  fry::CrashEvidence crashEvidence() override { return thisBuildCrashed(); }
  bool selectOtherSlot() override { return ::fry_ota::selectOtherSlot(); }
  void finishRollback() override {
    fry_config::clearOtaBootFails();
    delay(200);
    ESP.restart();
  }
  void log(const char* line) override { Serial.println(line); }
};
#endif

// Marks the running image valid once decideMarkValid() says so; a failure is retried on the next
// hardwareapi answer (noteHeartbeat) and the image keeps reporting "pending" meanwhile.
void tryMarkValid(const char* why) {
  if (!s_confirmPending) return;
#if !defined(ARDUINO_ARCH_ESP8266)
  const bool earlyOk = s_earlyOk;  // core health proven (loopGuard) or the last permitted install attempt
#else
  const bool earlyOk = false;
#endif
  if (!earlyOk && !fry::decideMarkValid(true, s_heartbeat.anyResponse(), millis(), kMarkValidSettleMs)) return;
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
    // Redirects are followed by hand (getFollowingHops): each hop needs its own trust anchor set and its own heap check.
    http.setFollowRedirects(HTTPC_DISABLE_FOLLOW_REDIRECTS);
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
// 96 B, evaluateManifest 320 B (sequential with the GET, not nested in it).
struct ManifestClients {
  HTTPClient http;
  WiFiClientSecure sec;
  WiFiClient plain;
};

struct DownloadWork {
  HTTPClient http;
  WiFiClientSecure sec;
  WiFiClient plain;
};

// The digest state is not part of DownloadWork: it is only needed once the body streams, and in the work block it was live (216 B) at the
// download's first floor sample. Taken just before streaming, freed when downloadAndApply() returns.
struct DigestWork {
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
// GET with every redirect followed here instead of by the HTTP client. The client would keep one TLS client and one trust
// anchor set for every hop, but the hosts of a release download are anchored by different roots and holding both costs heap
// the download does not have. So each hop is decided first (lib/fry_core/ota_redirect.h: at most kMaxRedirectHops, https
// only, a host that has trust anchors), the session is stopped, and the next hop is begun through beginHttpsUrl, which
// replaces the anchors, validates the new host, and applies the same heap floors as the first hop. Nothing falls back to an
// insecure connection: a refused hop ends the request.
//
// Between two hops the heap must be given back in one piece, or the next session's big buffers have no block to land in. Two
// allocations made while the first session was live sit in the middle of the region its buffers free: the Location String the
// client keeps (a signed URL is about 900 B, grown as the header is read) and the last received segment, which stop() leaves in
// the connection's queue (stop() closes the pcb but only the last reference to the connection frees what it never read).
// So, in this order: read what is left (bounded), copy the Location to the stack (a Location over kHopLocationMax ends the
// request), stop, rebuild the client so its old Strings are freed, then begin the next hop from the stack copy. No heap block is
// made for the redirect, so none sits in the freed region at the next hop's heap sample.
constexpr uint16_t kHopDrainBytes = 2048;  // most unread bytes thrown away per hop
constexpr uint32_t kHopDrainMs = 250;      // longest the drain may take; the loop is never blocked past this
constexpr uint16_t kManifestTimeoutMs = HTTPCLIENT_DEFAULT_TCP_TIMEOUT;
constexpr uint16_t kDownloadTimeoutMs = 20000;

// The settings every OTA client carries after its begin: the read timeout, redirects off (beginHttpsUrl turns them on), and
// keep-alive as otaBeginUrl chose it. One place, so a rebuilt client gets exactly what the first one had.
FRY_OTA_ESP8266_NOINLINE static void applyOtaClientSettings(HTTPClient& http, uint16_t timeoutMs) {
  http.setTimeout(timeoutMs);
  http.setFollowRedirects(HTTPC_DISABLE_FOLLOW_REDIRECTS);
  // Not spelled as in otaBeginUrl: test_ota_session pins that call site as the only one.
  const bool keepAlive = fry::otaAsksForKeepAlive(/*isEsp8266=*/true, /*isHttps=*/true);
  http.setReuse(keepAlive);
}

// HTTPClient::end() and clear() only set the length of its Strings to zero (ESP8266HTTPClient.cpp:55-62, 198-202): the
// Location, URI and header buffers stay allocated. Destroying and rebuilding the object in place frees them and drops the
// connection clone. Nothing holds a pointer or reference into the old Strings: the callers keep only the HTTPClient& itself,
// which stays valid, and the Location was copied before.
FRY_OTA_ESP8266_NOINLINE static void rebuildHttpClient(HTTPClient& http) {
  http.~HTTPClient();
  new (&http) HTTPClient();
}

FRY_OTA_ESP8266_NOINLINE static void drainUnread(WiFiClientSecure& sec) {
  const unsigned long t0 = millis();
  uint16_t n = 0;
  while (n < kHopDrainBytes && millis() - t0 < kHopDrainMs && sec.available() > 0) {
    sec.read();
    n++;
  }
}

// After a followed redirect hop the previous connection must not leave anything inside the region the next hop's floor sample measures.
// Wait, bounded (reusing fry::decideHeapSettle), for the largest block to be back at the baseline taken before the first hop began.
// When the bound expires, log one line and go on: the floor check in beginHttpsUrl then decides, fail closed. Returns the ms waited.
FRY_OTA_ESP8266_NOINLINE static unsigned long settleAfterHop(uint32_t blkBaseline) {
  const unsigned long t0 = millis();
  uint32_t blk = fry::queryMaxFreeBlock();
  // Also wait for the previous session's closing pcb: it sits below the large block, so the block criterion alone passes at once.
  while (fry::decideHeapSettle(blk, blkBaseline, fry::kOtaSettleSlackBytes, static_cast<uint32_t>(millis() - t0),
                               fry::kOtaSettleMaxMs) == fry::SettleHold::Hold ||
         fry::decideClosingSettle(fry::countClosingPcbs(), static_cast<uint32_t>(millis() - t0), fry::kOtaSettleMaxMs) ==
             fry::SettleHold::Hold) {
    delay(fry::kOtaSettlePollMs);
    blk = fry::queryMaxFreeBlock();
  }
  const unsigned long waited = millis() - t0;
  if (blk + fry::kOtaSettleSlackBytes < blkBaseline)
    Serial.printf_P(PSTR("ota: hop not settled %lu ms, blk %u (start %u)\n"), waited, static_cast<unsigned>(blk),
                    static_cast<unsigned>(blkBaseline));
  return waited;
}

// A signed release-assets URL is about 900 B; this holds one with room to spare. A longer Location is refused.
constexpr size_t kHopLocationMax = 1280;

// One redirect hop, in the order that leaves the heap whole: read what is left (bounded), copy the Location to this frame's
// stack, stop the session, rebuild the client (which frees the Location String it held), and begin the next hop from the stack
// copy. Nothing about the redirect is on the heap when beginHttpsUrl takes its heap sample. The buffer lives in this frame only,
// so it is gone before the next GET() runs the TLS handshake on the same stack. False ends the request (fail closed).
FRY_OTA_ESP8266_NOINLINE static bool beginNextHop(HTTPClient& http, WiFiClientSecure& sec, bool manifest, bool& refused,
                                                  uint16_t timeoutMs, uint32_t blkBaseline) {
  drainUnread(sec);
  char loc[kHopLocationMax + 1];
  const String& got = http.getLocation();
  const size_t n = got.length();
  if (n > kHopLocationMax) {
    Serial.printf_P(PSTR("ota: redirect refused (location too long)\n"));
    return false;
  }
  memcpy(loc, got.c_str(), n + 1);
  // The redirect is decided and its body drained: stop() closes the connection and frees the TLS state. What the closed connection
  // still holds is released by that stop and the client rebuild below, and the bounded settle waits until the largest block has
  // recovered, before the next hop's floor check.
  sec.stop();
  rebuildHttpClient(http);
  (void)settleAfterHop(blkBaseline);
  if (!fry_http::beginHttpsUrl(http, sec, static_cast<const char*>(loc), /*mflnProbeWorthwhile=*/false, manifest)) {
    if (fry_http::lastRefusalWasHeap()) refused = true;  // a clock, host or anchor failure takes the normal failure path
    return false;
  }
  applyOtaClientSettings(http, timeoutMs);
  return true;
}

FRY_OTA_ESP8266_NOINLINE static int getFollowingHops(HTTPClient& http, WiFiClientSecure& sec, bool isHttps, bool manifest, bool& refused,
                                                      uint16_t timeoutMs) {
  if (!isHttps) return http.GET();
  uint8_t hops = 0;
  const uint32_t blkBaseline = fry::queryMaxFreeBlock();  // before the first GET(): what each followed hop settles back to
  for (;;) {
    const int code = http.GET();
    const fry::RedirectDecision d = fry::decideRedirect(code, hops, http.getLocation().c_str());
    if (d == fry::RedirectDecision::NotRedirect) return code;
    if (d != fry::RedirectDecision::Follow) {
      Serial.printf_P(PSTR("ota: redirect refused (%d)\n"), static_cast<int>(d));
      return -1;
    }
    hops++;
    if (!beginNextHop(http, sec, manifest, refused, timeoutMs, blkBaseline)) return -1;
  }
}

FRY_OTA_ESP8266_NOINLINE static void settleAfterManifest(uint32_t blkBefore) {
  const unsigned long t0 = millis();
  uint32_t blk = fry::queryMaxFreeBlock();
  // Also wait for the previous session's closing pcb: it sits below the large block, so the block criterion alone passes at once.
  while (fry::decideHeapSettle(blk, blkBefore, fry::kOtaSettleSlackBytes, static_cast<uint32_t>(millis() - t0),
                               fry::kOtaSettleMaxMs) == fry::SettleHold::Hold ||
         fry::decideClosingSettle(fry::countClosingPcbs(), static_cast<uint32_t>(millis() - t0), fry::kOtaSettleMaxMs) ==
             fry::SettleHold::Hold) {
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
  // The manifest's clients are gone (checkNow() reset them): its last anchor set must not be resident while the download waits
  // for its heap and then builds the anchors of its own first hop.
  fry_http::releaseTrustAnchors();
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
    if (url.startsWith("https://") && fry_http::lastRefusalWasHeap()) s_heapRefused = true;  // as for the manifest: only the heap refusal
#endif
    return false;
  }
  http.setTimeout(20000);

#if defined(ARDUINO_ARCH_ESP8266)
  const bool isHttpsUrl = url.startsWith("https://");
  int code = getFollowingHops(http, sec, isHttpsUrl, /*manifest=*/false, s_heapRefused, kDownloadTimeoutMs);
#else
  int code = http.GET();
#endif
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
  const std::unique_ptr<DigestWork> digestWork(new (std::nothrow) DigestWork());
  if (!bufHeap || !digestWork) {
    FRY_PRINTLN("ota: no memory for the download buffer");
    upd.discard();
    http.end();
    return false;
  }
  uint8_t* const buf = bufHeap.get();
  fry::Sha256& sha = digestWork->sha;
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
  uint8_t(&digest)[32] = digestWork->digest;
  char(&hex)[65] = digestWork->hex;
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

#if !defined(ARDUINO_ARCH_ESP8266)
  // Install attempts and probation (lib/fry_core/ota_confirm.h, ota_boot_flow.h): the record is an NVS key the
  // previous image does not know, so it survives a rollback. Decided before the pending check below.
  {
    RealBootPorts ports;
    fry::BootFlowConfig cfg;
    cfg.version = FRY_FIRMWARE_VERSION;
    cfg.manifestUrl = OTA_MANIFEST_URL;
    cfg.failLimit = OTA_BOOT_FAIL_LIMIT;
    const fry::BootFlowResult fr = fry::runBootFlow(ports, cfg);  // a rollback restarts and does not return
    s_inProbation = fr.inProbation;
    s_probFails = fr.failCount;
    s_rec = fr.record;
    if (fr.outcome == fry::FlowOutcome::ConfirmNow) {
      s_confirmPending = true;
      s_earlyOk = true;
      tryMarkValid("last install attempt");
    }
  }
#endif

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
                                                           : " - retried at the next update check");
      } else if (plannedRestart) {
        FRY_PRINTF("ota: %s was rolled back by a planned restart - not counted\n", pending.c_str());
      }
    }
#if defined(ARDUINO_ARCH_ESP8266)
    // No bootloader rollback here: a different image than the manifest declared (pending) with no
    // rollback or planned-restart marker is a mislabelled image. One strike, like a failed install.
    // The boot after an upgrade whose image really is the pending version never gets here (pending ==
    // running), and a different bad version simply restarts the count at strike 1 (badver != pending).
    if (fry::shouldRejectManifestVersion(pending.c_str(), FRY_FIRMWARE_VERSION,
                                         s_rolledBack || counterRolledBack, plannedRestart)) {
      const String badver = fry_config::getOtaBadVer();
      bool changed = false;
      const uint8_t strikes = fry::nextStrikeCount(badver.c_str(), fry_config::getOtaBadN(),
                                                   pending.c_str(), false, &changed);
      if (changed) {
        fry_config::setOtaStrikes(pending.c_str(), strikes);
        s_firstCheckAfterRollback = true;
        FRY_PRINTF("ota: version mismatch manifest=%s image=%s - strike %u/%u%s\n", pending.c_str(),
                      FRY_FIRMWARE_VERSION, strikes, fry::kOtaPermanentStrikes,
                      strikes >= fry::kOtaPermanentStrikes ? " - it will not be installed again" : "");
      }
    }
#endif
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
#if !defined(ARDUINO_ARCH_ESP8266)
  if (http >= 200 && http < 300 && what && (strcmp(what, "poc") == 0 || strcmp(what, "lease") == 0)) s_pocOk = true;
#endif
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

#if !defined(ARDUINO_ARCH_ESP8266)
void noteStartupDone() {
  s_startupDone = true;
  s_startupDoneMs = millis();
}
void noteTunnelBringUpAttempted() { s_tunnelBringUp = true; }
void noteTunnelFetchAttempted() { s_tunnelFetch = true; }
#endif

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
#if !defined(ARDUINO_ARCH_ESP8266)
  // Core health (lib/fry_core/ota_confirm.h): confirm a pending image as soon as Wi-Fi, a 2xx answer, the end of the
  // tunnel bring-up attempt and a short uptime prove it works; the settle window below stays the fallback. After the
  // confirm the same health ends the probation: forgive crash boots after 120 s, drop the record after 30 min.
  if (s_startupDone && s_loopPasses < 255) s_loopPasses++;
  if (s_confirmPending || s_inProbation) {
    fry::CoreHealth h;
    h.staUp = fry_wifi::isConnected();
    h.apiOk2xx = s_heartbeat.ageS(now) >= 0;  // ageS() is -1 until a 2xx arrived this boot
    h.startupDone = s_startupDone;
    h.tunnelSettled = fry::tunnelSettled(fry_config::hasVpnConfig(), s_tunnelBringUp, s_tunnelFetch,
                                        s_startupDone ? static_cast<uint32_t>(now - s_startupDoneMs) : 0);
    h.loopPasses = s_loopPasses;
    h.freeHeap = ESP.getFreeHeap();
    h.uptimeMs = now;
    if (!s_healthGaveUp && s_rec.n > 0 && !s_rec.healthy && h.staUp && h.apiOk2xx) {
      // Remember that an attempt got as far as the API: a later attempt without this note is a silent failure.
      RealBootPorts ports;
      fry::BootFlowConfig cfg;
      cfg.version = FRY_FIRMWARE_VERSION;
      cfg.manifestUrl = OTA_MANIFEST_URL;
      cfg.failLimit = OTA_BOOT_FAIL_LIMIT;
      if (!fry::recordHealthReached(ports, cfg, &s_rec)) s_healthGaveUp = true;
    }
    if (s_confirmPending && !s_earlyAttempted && fry::decideEarlyConfirm(true, h, HEAP_GATE_OTA)) {
      s_earlyAttempted = true;
      s_earlyOk = true;
      tryMarkValid("core health");
    } else if (!s_confirmPending && s_inProbation) {
      const fry::ProbationStep step =
          fry::decideProbationProgress(true, fry::coreHealthy(h, HEAP_GATE_OTA), now, s_probFails, s_pocOk);
      if (step == fry::ProbationStep::ClearFails) {
        s_probFails = 0;
        fry_config::clearOtaBootFails();
        FRY_PRINTF("ota: probation crash count cleared - healthy for %lus\n", now / 1000UL);
      } else if (step == fry::ProbationStep::End) {
        s_inProbation = false;
        s_probFails = 0;
        s_rec = fry::AttemptRecord();
        fry_config::clearOtaBootFails();
        fry_config::clearOtaAttempts();
        FRY_PRINTF("ota: probation over for %s - healthy for %lus\n", FRY_FIRMWARE_VERSION, now / 1000UL);
      }
    }
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
  fry_http::releaseTrustAnchors();  // no TLS client exists yet; a resident set would sit in the free region being measured
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
    if (manifestUrl.startsWith("https://") && fry_http::lastRefusalWasHeap()) s_heapRefused = true;
#endif
    return false;
  }
#if defined(ARDUINO_ARCH_ESP8266)
  int code = getFollowingHops(http, sec, manifestUrl.startsWith("https://"), /*manifest=*/true, s_heapRefused, kManifestTimeoutMs);
#else
  int code = http.GET();
#endif
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
  const bool firstCheck = s_firstCheckAfterRollback;
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
  bool willUpdate = decision == fry::OtaDecision::Update;
  // Manifest-directed rollback (PROTOCOL.md 11.11): only where no forward update exists, only for an explicit
  // builds.<env>.rollback that lists this running version, and never rollout-gated. The bad version is recorded
  // with permanent strikes BEFORE the download, so a manifest that still names it as latest cannot pull the board
  // forward again (strikesReset ran above and keeps a record that names the same version).
  if (decision == fry::OtaDecision::NotNewer) {
    fry::RollbackEntry rb;
    if (fry::readRollbackEntry(build["rollback"], FRY_FIRMWARE_VERSION, &rb) &&
        fry::decideOtaRollback(channel, FRY_OTA_CHANNEL, FRY_FIRMWARE_VERSION, true, rb.version, badver.c_str(),
                               badn, firstCheck, rb.url, rb.sha256) == fry::OtaDecision::Rollback) {
      fry_config::setOtaStrikes(FRY_FIRMWARE_VERSION, fry::kOtaPermanentStrikes);
      FRY_PRINTF("ota: manifest directs rollback %s -> %s\n", FRY_FIRMWARE_VERSION, rb.version);
      latest = rb.version;
      url = rb.url;
      sha = rb.sha256;
      willUpdate = true;
    }
  }
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
    // The hold only waits for a heap the next TLS begin accepts. Free and block both at the download gate (pre-constructor sample, ota_hold_release.h): stop waiting.
    const uint32_t freeNow = ESP.getFreeHeap();
    const uint32_t blkNow = fry::queryMaxFreeBlock();
    if (fry::decideHoldRelease(tw + closing, heldMs, fry::kOtaTimeWaitMaxHoldMs, freeNow, blkNow) == fry::TwHold::Proceed) {
      if (holding) {
        holding = false;
        Serial.printf_P(PSTR("ota: check released early after %lu ms (free=%u blk=%u, tw=%u cl=%u)\n"),
                        static_cast<unsigned long>(heldMs), static_cast<unsigned>(freeNow), static_cast<unsigned>(blkNow),
                        static_cast<unsigned>(tw), static_cast<unsigned>(closing));
      }
      return false;
    }
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
    // Nor before the boot registration (started when the TLS gate opens, counted from the connect) has had its slot.
    uint32_t connectAnchor = 0;
    const bool haveConnect = fry_wifi::connectAnchorMs(&connectAnchor);
    if (fry::otaFirstCheckAfterConnectWaitMs(static_cast<uint32_t>(now), connectAnchor, haveConnect) != 0) return;
    if (fry_http::tlsStartDelayMs() != 0) return;  // boot TLS gate: only delays the start; the hold decision below is unchanged
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

extern "C" void fry_trigger_ota_now() {
#if defined(ARDUINO_ARCH_ESP8266)
  // Boot TLS gate: a check asked for from outside the schedule (the serial command) waits for the boot window too. A deferral: no
  // session, and no retry or strike state is touched. The scheduled checks go through tick(), which is gated itself.
  if (fry_http::tlsStartDelayMs() != 0) {
    FRY_PRINTLN("ota: manifest check deferred until the boot window ends");
    return;
  }
#endif
  fry_ota::checkNow();
}
