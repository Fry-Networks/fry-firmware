// ESP8266 OTA client (IV5, 0.3.4). This is src/core/ota_client.cpp @0.3.3 plus three
// ESP8266-only changes, kept in a separate file so the shared one - and with it every
// ESP32/S3/C3 image - stays byte-for-byte what 0.3.3 shipped (env:esp8266's build_src_filter
// swaps this file in for it):
//   1. the build entry's own "version" wins over the manifest's top-level firmware_version (the
//      shared manifest's top level is the ESP32/C3 version; comparing against it would re-apply
//      this same image every OTA_CHECK_MS),
//   2. B4: the entry must name this board/layout (board_id, flash_size) and its exact size
//      before a byte is written - one app slot, no rollback (lib/fry_core/ota_target.h),
//   3. the relay link is paused - and every byte of it freed (relay_link.cpp) - around each check,
//      so the GitHub path finds the same heap a 0.3.3 board has; the free/blk it found is logged.
#include "../core/ota_client.h"

#include <ArduinoJson.h>
#if defined(ARDUINO_ARCH_ESP8266)
#include <Updater.h>  // ESP8266 core header is named Updater.h, not Update.h
#include <eboot_command.h>
#else
#include <Update.h>
#endif

#include <cstring>
#include <memory>
#include <new>

#include "config.h"
#include "../core/fry_config.h"
#include "heap_gate.h"
#include "../core/heap_gate_wait.h"
#include "semver.h"
#include "../core/http_tls.h"
#include "ota_boot_counter.h"
#include "sha256.h"
#include "../core/trigger_hooks.h"

#if !defined(ARDUINO_ARCH_ESP8266)
#include <esp_ota_ops.h>
#endif

#include "ota_mfln.h"
#include "ota_target.h"
#include "relay_link.h"

#ifndef FRY_OTA_BOARD_ID
#define FRY_OTA_BOARD_ID "unknown"
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

namespace fry_ota {

namespace {

unsigned long s_lastCheckMs = 0;
// PROTOCOL.md section 6 wants a check "on boot and every 6 h". tick() is only reached
// once WiFi is up, but with s_lastCheckMs seeded at 0 the elapsed-time gate is false at
// boot (millis() is still tiny), so the first check silently slipped to OTA_CHECK_MS
// after boot. This flag forces exactly one check on the first tick after WiFi comes up.
bool s_firstCheckDone = false;

// B4: the manifest entry's declared image size, checked against Content-Length before a byte is
// written (one slot, no rollback on this chip).
uint32_t s_expectSize = 0;

// The loop() (CONT) stack is 4 KB and the BearSSL handshake runs on top of whatever checkNow() and
// downloadAndApply() already hold. The HTTP/TLS clients (and the download buffer below) therefore
// live on the heap, never in those frames: measured with the diag build, the OTA connect started
// with 276 bytes of CONT stack free and a soft WDT followed. The heap gates are sampled BEFORE
// any of this is allocated and are not re-sampled.
struct OtaConn {
  HTTPClient http;
  WiFiClientSecure sec;
  WiFiClient plain;
};
constexpr size_t kDownloadBufSize = 1024;

// The relay link's TLS session would otherwise sit in the heap the GitHub path needs.
struct RelayLinkPause {
  RelayLinkPause() { fry_relay::pause(); }
  ~RelayLinkPause() { fry_relay::resume(); }
};

// Manual rollback: boot into whichever OTA slot is NOT currently running. This does not depend
// on esp_ota_mark_app_valid_cancel_rollback()/Update.rollBack() at all, since those rely on the
// hardware rollback machinery this bootloader was built without.
void manualRollback() {
#if defined(ARDUINO_ARCH_ESP8266)
  Serial.println("ota: boot-fail limit reached - ROLLBACK IMPOSSIBLE on ESP8266 (one slot)");
#else
  const esp_partition_t* running = esp_ota_get_running_partition();
  const esp_partition_t* other = esp_ota_get_next_update_partition(nullptr);
  if (other && running && other->address != running->address) {
    Serial.println("ota: boot-fail limit reached - booting the other OTA slot");
    esp_ota_set_boot_partition(other);
  } else {
    Serial.println("ota: boot-fail limit reached but no other OTA slot found - staying");
  }
#endif
  fry_config::clearOtaPending();
  fry_config::clearOtaBootFails();
  delay(200);
  ESP.restart();
}

// Mandatory on every OTA TLS connection (manifest and image), sampled right before the connect.
// The rx/tx shown for a non-MFLN host are the planned 16384/512; beginHttpsUrl may still fall back
// to 512/512 and says so on its own "tls:" line.
void logOtaTls(const String& url, const fry::OtaTlsPlan& plan) {
  char host[96];
  if (!fry::otaUrlHost(url.c_str(), host, sizeof(host))) strcpy(host, "?");
  Serial.printf_P(PSTR("ota-tls: host=%s mfln=%s bufs=%u/%u%s blk=%u free=%u\n"), host,
                  plan.mfln ? "yes" : "no", static_cast<unsigned>(plan.rx),
                  static_cast<unsigned>(plan.tx), plan.mfln ? "" : "(planned)", static_cast<unsigned>(fry::queryMaxFreeBlock()),
                  static_cast<unsigned>(ESP.getFreeHeap()));
}

void logOtaTlsNegotiated(WiFiClientSecure& sec, const fry::OtaTlsPlan& plan) {
#if defined(ARDUINO_ARCH_ESP8266)
  if (plan.https) Serial.printf_P(PSTR("ota-tls: negotiated mfln=%d\n"), sec.getMFLNStatus() ? 1 : 0);
#else
  (void)sec;
  (void)plan;
#endif
}

bool otaBeginUrl(HTTPClient& http, WiFiClientSecure& sec, WiFiClient& plain, const String& url,
                 const fry::OtaTlsPlan& plan) {
  if (url.startsWith("https://")) {
    logOtaTls(url, plan);
    if (plan.mfln) {
      // hardwareapi echoes max_fragment_length: a 512/512 BearSSL session, no contiguous block
      // needed. Redirects are NOT followed (fry::otaFollowRedirects): the target would not be
      // re-classified, and 512/512 BearSSL against a non-MFLN host spins in _run_until until the
      // soft WDT fires. hardwareapi serves both files directly, so a 3xx comes back as
      // "HTTP <code>" and the caller skips to the next scheduled check.
      sec.setInsecure();  // same documented limitation as beginHttpsUrl (http_tls.cpp)
      sec.setBufferSizes(plan.rx, plan.tx);
      if (!http.begin(sec, url)) return false;
      http.setFollowRedirects(fry::otaFollowRedirects(plan) ? HTTPC_FORCE_FOLLOW_REDIRECTS
                                                            : HTTPC_DISABLE_FOLLOW_REDIRECTS);
      return true;
    }
    // GitHub - the compiled OTA_MANIFEST_URL host, and the *.githubusercontent.com targets its
    // release redirects hand out - does not honour MFLN. On ESP8266, probing it costs a ~32 KB
    // contiguous allocation purely to be told no, and that spike is what made every HTTPS
    // manifest fetch return -1. Tell beginHttpsUrl not to bother. A lab override pointed at an
    // MFLN-honouring host still gets the probe, and therefore still gets the cheap 512/512 path.
    const bool githubHost =
        url.indexOf("github.com") >= 0 || url.indexOf("githubusercontent.com") >= 0;
    return fry_http::beginHttpsUrl(http, sec, url, !githubHost);
  }
  if (!http.begin(plain, url)) return false;
  http.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);
  http.setRedirectLimit(5);
  return true;
}

// Update.end(false) on a COMPLETE download still stages it (Updater.cpp end(): only hasError() or an
// unfinished download rejects; it then writes the eboot ACTION_COPY_RAW command), so a bad-hash image
// would be copied by the very next restart. Called after bytes reached Update on every path that
// does not apply: end the update, then cancel whatever staging that left behind.
void abortUpdate(size_t done, int len, bool shaOk, bool endOk) {
#if defined(ARDUINO_ARCH_ESP8266)
  Update.end(false);
  if (!fry::otaMustClearStaged(static_cast<uint32_t>(done), static_cast<uint32_t>(len), shaOk, endOk)) return;
  eboot_command_clear();
  Serial.println("ota: staged image cleared (eboot cmd)");
#else
  (void)done;
  (void)len;
  (void)shaOk;
  (void)endOk;
  Update.abort();
#endif
}

// Every failure (connect/handshake, HTTP, parse, gate) waits for the next scheduled check: no
// restart, no immediate retry. tick() stamps s_lastCheckMs before checkNow(), so returning is enough.
void logSkip(fry::OtaFailKind kind, const char* why) {
  if (fry::otaFailureAction(kind) == fry::OtaFailAction::SkipToNextCheck)
    Serial.printf_P(PSTR("ota: skipped until next check (%s)\n"), why);
}

bool downloadAndApply(const String& url, const String& shaExpect, const String& newVersion) {
  const fry::OtaTlsPlan plan = fry::otaTlsPlan(url.c_str(), HEAP_GATE_OTA_BLOCK);
  // Small-buffer path: sample the gate ONCE, before any client is constructed (a gate re-sampled
  // after the TLS client allocated measures the wrong heap). No contiguous-block requirement.
  if (plan.mfln && !fry::waitForHeapGate(HEAP_GATE_OTA, plan.minBlock)) {
    Serial.printf("ota: heap gate failed (total free)\n");
    logSkip(fry::OtaFailKind::GateFailed, "heap gate");
    return false;
  }
  std::unique_ptr<OtaConn> conn(new (std::nothrow) OtaConn);
  if (!conn) {
    Serial.println("ota: out of memory for the connection");
    logSkip(fry::OtaFailKind::GateFailed, "no memory");
    return false;
  }
  HTTPClient& http = conn->http;
  WiFiClientSecure& sec = conn->sec;
  WiFiClient& plain = conn->plain;
  if (!otaBeginUrl(http, sec, plain, url, plan)) {
    Serial.println("ota: begin failed");
    return false;
  }
  http.setTimeout(20000);

  int code = http.GET();
  logOtaTlsNegotiated(sec, plan);
  if (code != 200) {
    Serial.printf("ota: HTTP %d\n", code);
    http.end();
    logSkip(code < 0 ? fry::OtaFailKind::ConnectOrHandshake : fry::OtaFailKind::HttpError,
            code < 0 ? "image connect/handshake failed" : "image HTTP error");
    return false;
  }
  int len = http.getSize();
  if (len <= 0) {
    Serial.println("ota: no Content-Length");
    http.end();
    return false;
  }
  if (fry::checkOtaSize(s_expectSize, len) != fry::OtaTargetVerdict::Ok) {
    Serial.printf_P(PSTR("ota: refused size (want %u have %d)\n"), static_cast<unsigned>(s_expectSize), len);
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
  if (!plan.mfln) {
    const bool isHttps = url.startsWith("https://");
#if defined(ARDUINO_ARCH_ESP8266)
    constexpr bool kBearsslSingleBuffer = true;
#else
    constexpr bool kBearsslSingleBuffer = false;  // ESP32 family uses mbedtls
#endif
    const uint32_t minBlock =
        fry::otaMinContiguousBlock(isHttps, kBearsslSingleBuffer, HEAP_GATE_OTA_BLOCK);
    if (!fry::waitForHeapGate(HEAP_GATE_OTA, minBlock)) {
      Serial.printf("ota: heap gate failed (%s)\n",
                    minBlock ? "total free or largest contiguous block" : "total free");
      http.end();
      logSkip(fry::OtaFailKind::GateFailed, "heap gate");
      return false;
    }
  }
  std::unique_ptr<uint8_t[]> bufHeap(new (std::nothrow) uint8_t[kDownloadBufSize]);
  if (!bufHeap) {
    Serial.println("ota: out of memory for the download buffer");
    http.end();
    logSkip(fry::OtaFailKind::GateFailed, "no memory");
    return false;
  }
  if (!Update.begin(len)) {
    Serial.printf("ota: Update.begin failed (bin %dB too big for slot?)\n", len);
    http.end();
    return false;
  }
  Serial.printf("ota: download start %d bytes\n", len);

  fry::Sha256 sha;
  WiFiClient* stream = http.getStreamPtr();
  uint8_t* const buf = bufHeap.get();
  size_t done = 0;
  unsigned long lastData = millis();
  unsigned long lastLog = 0;
  while (done < static_cast<size_t>(len)) {
    size_t avail = stream->available();
    if (avail) {
      int r = stream->readBytes(buf, avail > kDownloadBufSize ? kDownloadBufSize : avail);
      if (r <= 0) break;
      sha.update(buf, r);
      if (Update.write(buf, r) != static_cast<size_t>(r)) {
        Serial.println("ota: write failed");
        abortUpdate(done, len, false, false);
        http.end();
        return false;
      }
      done += r;
      lastData = millis();
      if (millis() - lastLog > 3000) {
        Serial.printf("ota: downloading %u/%d KB\n", static_cast<unsigned>(done / 1024), len / 1024);
        lastLog = millis();
      }
    } else {
      if (!stream->connected()) break;
      if (millis() - lastData > 20000) {
        Serial.println("ota: stall 20s");
        break;
      }
      delay(1);
    }
    yield();
  }
  http.end();

  if (done != static_cast<size_t>(len)) {
    Serial.printf("ota: incomplete download %u/%d\n", static_cast<unsigned>(done), len);
    abortUpdate(done, len, false, false);
    return false;
  }

  Serial.printf("ota: download done %u bytes\n", static_cast<unsigned>(done));

  uint8_t digest[32];
  sha.finish(digest);
  char hex[65];
  fry::bytesToHexUpper(digest, 32, hex, sizeof(hex));
  String got = hex;
  got.toLowerCase();
  String want = shaExpect;
  want.toLowerCase();
  if (got != want) {
    Serial.printf("ota: sha256 mismatch (got %.16s want %.16s) - rejected\n", got.c_str(), want.c_str());
    abortUpdate(done, len, false, true);
    return false;
  }

  if (!Update.end(true)) {
    Serial.println("ota: Update.end failed");
    abortUpdate(done, len, true, false);
    return false;
  }

  fry_config::setOtaPending(newVersion.c_str());
  Serial.printf("ota: applied %s sha=ok\n", newVersion.c_str());
  delay(500);
  ESP.restart();
  return true;  // unreachable — kept for a clean return type after ESP.restart()
}

}  // namespace

void init() {
  String pending = fry_config::getOtaPending();
  if (pending.length() == 0) return;

  if (pending == FRY_FIRMWARE_VERSION) {
    uint8_t fails = fry_config::getOtaBootFails();
    fry::OtaBootCounter counter(fails);
    counter.increment();
    fry_config::setOtaBootFails(counter.count());
    if (counter.shouldRollBack(OTA_BOOT_FAIL_LIMIT)) {
      manualRollback();  // does not return
    }
    Serial.printf("ota: first boot %s - awaiting confirmation (%u/%u attempts)\n",
                  FRY_FIRMWARE_VERSION, counter.count(), OTA_BOOT_FAIL_LIMIT);
  } else {
    Serial.printf("ota: boot %s with pending=%s - flag cleared\n", FRY_FIRMWARE_VERSION, pending.c_str());
    fry_config::clearOtaPending();
    fry_config::clearOtaBootFails();
  }
}

void confirmGood() {
  if (fry_config::getOtaPending().length() == 0) return;
  fry_config::clearOtaPending();
  fry_config::clearOtaBootFails();
  Serial.printf("ota: %s confirmed\n", FRY_FIRMWARE_VERSION);
}

// The 0.4.x entry points shared code calls (hardwareapi_client.cpp, main.cpp, status_snapshot.cpp)
// but this 0.3.3-line client predates. One slot and no bootloader rollback on this chip, so they
// reduce to: a 2xx hardwareapi answer proves the image good (what registration did before), the
// heartbeat age is tracked, and there is no pending-verify state to guard.
namespace {
bool s_haveHeartbeat = false;
unsigned long s_lastHeartbeatMs = 0;
}  // namespace

// ESP8266 has ONE app slot and no bootloader rollback, so there is nothing to roll back to and
// nothing is ever "pending verify". This only marks state: it records the 2xx heartbeat time and
// clears the NVS pending flag / boot-fail counter (the manual boot-counter guard in init()).
void noteHeartbeat(int http, const char* what) {
  (void)what;
  if (http < 200 || http >= 300) return;
  s_haveHeartbeat = true;
  s_lastHeartbeatMs = millis();
  confirmGood();  // a no-op once the pending flag is gone
}

void notePlannedRestart() {}  // no-op: no rollback exists to be told about a planned restart

void loopGuard() {}  // no-op: no PENDING_VERIFY image and no automatic rollback on this chip

int32_t heartbeatAgeS() {
  if (!s_haveHeartbeat) return -1;
  return static_cast<int32_t>((millis() - s_lastHeartbeatMs) / 1000UL);
}

const char* imageStateName() { return "valid"; }  // never pending or rolled_back on one slot

bool checkNow() {
  String manifestUrl = fry_config::getOtaUrl();
  if (manifestUrl.length() == 0) manifestUrl = OTA_MANIFEST_URL;
  if (manifestUrl.length() == 0) return false;

  RelayLinkPause relayPause;
  // Sampled once, before any client exists. Only a host that is not known to honour MFLN needs the
  // big contiguous block; hardwareapi (small-buffer path) needs just the total-free gate.
  const fry::OtaTlsPlan plan = fry::otaTlsPlan(manifestUrl.c_str(), HEAP_GATE_OTA_BLOCK);
#if defined(FRY_BOARD_ESP8266)
  // Do not even open an HTTPS session for the manifest unless the BearSSL path chosen for its host
  // is affordable. A GitHub manifest does not honour MFLN, so on a fragmented heap the 512/512
  // fallback cannot carry its handshake and BearSSL fails hard rather than returning an error.
  // Skipping the check costs one deferred update; not skipping it cost a crash-and-reboot on COM11.
  // Plain-HTTP manifests (the lab server) are unaffected and still checked.
  if (plan.https && !fry::waitForHeapGate(HEAP_GATE_OTA, plan.minBlock, 1)) {
    // Print the numbers, not just the verdict. "insufficient" alone cost real diagnostic time:
    // a board carrying a stale plain-http lab override never reaches this branch at all, and its
    // unrelated "manifest fetch HTTP -1" (lab server unreachable) was read for two runs as
    // evidence of a TLS/heap failure on the GitHub path that was in fact never attempted.
    // With the shortfall visible, the two situations can never be confused again.
    Serial.printf("ota: skipped https manifest check - need blk>=%u free>=%u, have blk=%u free=%u\n",
                  static_cast<unsigned>(plan.minBlock), static_cast<unsigned>(HEAP_GATE_OTA),
                  static_cast<unsigned>(fry::queryMaxFreeBlock()),
                  static_cast<unsigned>(ESP.getFreeHeap()));
    logSkip(fry::OtaFailKind::GateFailed, "heap gate");
    return false;
  }
  // T2 F1: the relay link is freed above (RelayLinkPause), so this is the heap the manifest path
  // really gets - logged so the bench can prove the gate numbers.
  Serial.printf_P(PSTR("ota: heap at manifest check free=%u blk=%u (relay link freed)\n"),
                static_cast<unsigned>(ESP.getFreeHeap()),
                static_cast<unsigned>(fry::queryMaxFreeBlock()));
#endif

  // Everything the download needs is copied out so the manifest body, the JSON document and the
  // manifest's TLS client are all freed before the image connection is opened.
  String imgUrl, imgSha, latestStr;
  {
    String body;
    {
      std::unique_ptr<OtaConn> conn(new (std::nothrow) OtaConn);
      if (!conn) {
        Serial.println("ota: out of memory for the connection");
        logSkip(fry::OtaFailKind::GateFailed, "no memory");
        return false;
      }
      HTTPClient& http = conn->http;
      WiFiClientSecure& sec = conn->sec;
      WiFiClient& plain = conn->plain;
      if (!otaBeginUrl(http, sec, plain, manifestUrl, plan)) {
        Serial.println("ota: manifest fetch begin failed");
        return false;
      }
      int code = http.GET();
      logOtaTlsNegotiated(sec, plan);
      if (code != 200) {
        // Log the largest contiguous block alongside the code. HTTPClient collapses connect-refused,
        // iobuf-OOM and TLS-handshake-failure all into -1, and the 30 s [health] line samples far too
        // coarsely to catch the allocation peak, so without blk here a -1 is undiagnosable.
        Serial.printf("ota: manifest fetch HTTP %d (blk=%u)\n", code,
                      static_cast<unsigned>(fry::queryMaxFreeBlock()));
        http.end();
        logSkip(code < 0 ? fry::OtaFailKind::ConnectOrHandshake : fry::OtaFailKind::HttpError,
                code < 0 ? "manifest connect/handshake failed" : "manifest HTTP error");
        return false;
      }
      body = http.getString();
      http.end();
    }

    JsonDocument doc;
    if (deserializeJson(doc, body)) {
      Serial.println("ota: manifest parse failed");
      logSkip(fry::OtaFailKind::ManifestParse, "manifest parse");
      return false;
    }

    JsonObject build = doc["builds"][FRY_BUILD_ENV];
    // Only ever move FORWARD, comparing numerically; the entry's own version wins over the shared
    // top level (the ESP32/C3 version), and B4 refuses an entry not built for this board/layout -
    // all before anything is downloaded. Order and rules: fry::decideOtaApply (native tested).
    fry::OtaManifestEntry entry;
    entry.topVersion = doc["firmware_version"] | "";
    entry.buildVersion = build["version"] | "";
    entry.url = build["url"] | "";
    entry.sha256 = build["sha256"] | "";
    entry.target.boardId = build["board_id"] | "";
    entry.target.flashSize = build["flash_size"] | 0u;
    fry::OtaDeviceFlash device;
    device.boardId = FRY_OTA_BOARD_ID;
    device.flashReal = ESP.getFlashChipRealSize();
    device.flashHeader = ESP.getFlashChipSize();
    device.isEsp8285 = esp_is_8285();
    const fry::OtaDecision decision = fry::decideOtaApply(entry, device, FRY_FIRMWARE_VERSION);
    const char* latest = decision.version;
    Serial.printf("ota: manifest check cur=%s latest=%s action=%s\n", FRY_FIRMWARE_VERSION,
                  strlen(latest) ? latest : "?",
                  decision.action == fry::OtaAction::Update   ? "update"
                  : decision.action == fry::OtaAction::Refuse ? "refuse"
                                                              : "none");
    if (decision.action == fry::OtaAction::Refuse) {
      Serial.printf_P(PSTR("ota: refused %s (want board=%s flash=%u, have board=%s real=%u hdr=%u)\n"),
                    fry::otaTargetReason(decision.verdict), entry.target.boardId,
                    static_cast<unsigned>(entry.target.flashSize), device.boardId,
                    static_cast<unsigned>(device.flashReal), static_cast<unsigned>(device.flashHeader));
      return false;
    }
    if (decision.action != fry::OtaAction::Update) return false;
    s_expectSize = build["size"] | 0u;
    imgUrl = entry.url;
    imgSha = entry.sha256;
    latestStr = latest;
  }

  return downloadAndApply(imgUrl, imgSha, latestStr);
}

void tick() {
  unsigned long now = millis();
  if (!s_firstCheckDone) {
    s_firstCheckDone = true;
    s_lastCheckMs = now;
    checkNow();
    return;
  }
  if (now - s_lastCheckMs < OTA_CHECK_MS) return;
  s_lastCheckMs = now;
  checkNow();
}

}  // namespace fry_ota

extern "C" void fry_trigger_ota_now() { fry_ota::checkNow(); }
