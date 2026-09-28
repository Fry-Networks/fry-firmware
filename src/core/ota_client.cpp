#include "ota_client.h"

#include <ArduinoJson.h>
#if defined(ARDUINO_ARCH_ESP8266)
#include <Updater.h>  // ESP8266 core header is named Updater.h, not Update.h
#else
#include <Update.h>
#endif

#include <cstring>

#include "config.h"
#include "fry_config.h"
#include "heap_gate.h"
#include "heap_gate_wait.h"
#include "semver.h"
#include "http_tls.h"
#include "ota_boot_counter.h"
#include "ota_health.h"
#include "sha256.h"
#include "trigger_hooks.h"

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

namespace fry_ota {

namespace {

fry::HeartbeatTracker s_heartbeat;
#if !defined(ARDUINO_ARCH_ESP8266)
bool s_pendingVerify = false;  // the running image is PENDING_VERIFY in otadata
bool s_rolledBack = false;     // the other slot holds an image the bootloader rolled back from
#else
const bool s_rolledBack = false;  // one slot: nothing to roll back to
#endif
#if defined(FRY_TEST_FAULT) && FRY_TEST_FAULT == 3
unsigned long s_faultCrashAtMs = 0;
#endif

unsigned long s_lastCheckMs = 0;
// PROTOCOL.md section 6 wants a check "on boot and every 6 h". tick() is only reached
// once WiFi is up, but with s_lastCheckMs seeded at 0 the elapsed-time gate is false at
// boot (millis() is still tiny), so the first check silently slipped to OTA_CHECK_MS
// after boot. This flag forces exactly one check on the first tick after WiFi comes up.
bool s_firstCheckDone = false;

// Manual rollback: boot into whichever OTA slot is NOT currently running. This does not depend
// on esp_ota_mark_app_valid_cancel_rollback()/Update.rollBack() at all, since those rely on the
// hardware rollback machinery this bootloader was built without.
void manualRollback() {
  fry_config::setOtaBadVer(FRY_FIRMWARE_VERSION);  // do not come back to this one
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

bool otaBeginUrl(HTTPClient& http, WiFiClientSecure& sec, WiFiClient& plain, const String& url) {
  if (url.startsWith("https://")) {
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

bool downloadAndApply(const String& url, const String& shaExpect, const String& newVersion) {
  HTTPClient http;
  WiFiClientSecure sec;
  WiFiClient plain;
  if (!otaBeginUrl(http, sec, plain, url)) {
    Serial.println("ota: begin failed");
    return false;
  }
  http.setTimeout(20000);

  int code = http.GET();
  if (code != 200) {
    Serial.printf("ota: HTTP %d\n", code);
    http.end();
    return false;
  }
  int len = http.getSize();
  if (len <= 0) {
    Serial.println("ota: no Content-Length");
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
    return false;
  }
  if (!Update.begin(len)) {
    Serial.printf("ota: Update.begin failed (bin %dB too big for slot?)\n", len);
    http.end();
    return false;
  }

  fry::Sha256 sha;
  WiFiClient* stream = http.getStreamPtr();
  uint8_t buf[1024];
  size_t done = 0;
  unsigned long lastData = millis();
  unsigned long lastLog = 0;
  while (done < static_cast<size_t>(len)) {
    size_t avail = stream->available();
    if (avail) {
      int r = stream->readBytes(buf, avail > sizeof(buf) ? sizeof(buf) : avail);
      if (r <= 0) break;
      sha.update(buf, r);
      if (Update.write(buf, r) != static_cast<size_t>(r)) {
        Serial.println("ota: write failed");
#if defined(ARDUINO_ARCH_ESP8266)
        Update.end(false);
#else
        Update.abort();
#endif
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
#if defined(ARDUINO_ARCH_ESP8266)
    Update.end(false);
#else
    Update.abort();
#endif
    return false;
  }

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
#if defined(ARDUINO_ARCH_ESP8266)
    Update.end(false);
#else
    Update.abort();
#endif
    return false;
  }

  if (!Update.end(true)) {
    Serial.println("ota: Update.end failed");
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
#if !defined(ARDUINO_ARCH_ESP8266)
  s_rolledBack = esp_ota_get_last_invalid_partition() != nullptr;
  esp_ota_img_states_t state;
  s_pendingVerify = esp_ota_get_state_partition(esp_ota_get_running_partition(), &state) == ESP_OK &&
                    state == ESP_OTA_IMG_PENDING_VERIFY;
  if (s_pendingVerify) {
    Serial.printf("ota: image %s is pending verification - valid on the first hardwareapi answer, "
                  "rolled back after %lus without one\n",
                  FRY_FIRMWARE_VERSION, static_cast<unsigned long>(FRY_OTA_VERIFY_DEADLINE_MS / 1000));
  }
#endif
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
    if (fry::shouldRecordBadVersion(pending.c_str(), FRY_FIRMWARE_VERSION, s_rolledBack)) {
      // The image we installed did not survive and the bootloader brought us back here.
      fry_config::setOtaBadVer(pending.c_str());
      Serial.printf("ota: %s was rolled back - running %s, %s will not be installed again\n",
                    pending.c_str(), FRY_FIRMWARE_VERSION, pending.c_str());
    }
    Serial.printf("ota: boot %s with pending=%s - flag cleared\n", FRY_FIRMWARE_VERSION, pending.c_str());
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
  if (!s_heartbeat.note(http, millis())) return;
  // First hardwareapi answer this boot, whatever its status: the network path works.
  confirmGood();
#if !defined(ARDUINO_ARCH_ESP8266)
  if (s_pendingVerify) {
    const esp_err_t err = esp_ota_mark_app_valid_cancel_rollback();
    if (err == ESP_OK) s_pendingVerify = false;
    Serial.printf("ota: image %s marked valid (first hardwareapi answer: %s http=%d)%s\n",
                  FRY_FIRMWARE_VERSION, what ? what : "?", http, err == ESP_OK ? "" : " - FAILED");
  }
#endif
#if defined(FRY_TEST_FAULT) && FRY_TEST_FAULT == 3
  s_faultCrashAtMs = millis() + 60000UL;
  if (s_faultCrashAtMs == 0) s_faultCrashAtMs = 1;
#endif
#endif
}

void loopGuard() {
#if defined(FRY_TEST_FAULT) && FRY_TEST_FAULT == 3
  if (s_faultCrashAtMs && static_cast<long>(millis() - s_faultCrashAtMs) >= 0) {
    Serial.println("[fault] FRY_TEST_FAULT=3 - crashing 60 s after the first heartbeat");
    Serial.flush();
    abort();
  }
#endif
#if !defined(ARDUINO_ARCH_ESP8266)
  if (fry::decideRollbackGuard(s_pendingVerify, s_heartbeat.anyResponse(), millis(),
                               FRY_OTA_VERIFY_DEADLINE_MS) != fry::GuardAction::Rollback) {
    return;
  }
  Serial.printf("ota: no hardwareapi answer %lus after booting pending image %s - rolling back\n",
                static_cast<unsigned long>(FRY_OTA_VERIFY_DEADLINE_MS / 1000), FRY_FIRMWARE_VERSION);
  fry_config::setOtaBadVer(FRY_FIRMWARE_VERSION);
  Serial.flush();
  esp_ota_mark_app_invalid_rollback_and_reboot();
  s_pendingVerify = false;  // only reached if there was nothing to roll back to
#endif
}

int32_t heartbeatAgeS() { return s_heartbeat.ageS(millis()); }

const char* imageStateName() {
#if defined(ARDUINO_ARCH_ESP8266)
  const bool pending = fry_config::getOtaPending() == FRY_FIRMWARE_VERSION;
  return fry::otaImageStateName(fry::otaImageState(pending, false));
#else
  return fry::otaImageStateName(fry::otaImageState(s_pendingVerify, s_rolledBack));
#endif
}

void confirmGood() {
  if (fry_config::getOtaPending().length() == 0) return;
  fry_config::clearOtaPending();
  fry_config::clearOtaBootFails();
  Serial.printf("ota: %s confirmed\n", FRY_FIRMWARE_VERSION);
}

bool checkNow() {
#if !defined(ARDUINO_ARCH_ESP8266)
  // esp_ota_begin() refuses while the running image is unconfirmed, and the other slot is the
  // rollback target: do not download over it before this image has proved itself.
  if (s_pendingVerify) {
    Serial.println("ota: manifest check skipped - running image still pending verification");
    return false;
  }
#endif
  String manifestUrl = fry_config::getOtaUrl();
  if (manifestUrl.length() == 0) manifestUrl = FRY_OTA_DEFAULT_MANIFEST;
  if (manifestUrl.length() == 0) return false;

#if defined(FRY_BOARD_ESP8266)
  // Do not even open an HTTPS session for the manifest unless the big BearSSL path is
  // affordable. The release manifest lives on GitHub, which does not honour MFLN, so on a
  // fragmented heap the 512/512 fallback cannot carry its handshake and BearSSL fails hard
  // rather than returning an error. Skipping the check costs one deferred update; not
  // skipping it cost a crash-and-reboot on COM11. Plain-HTTP manifests (the lab server) are
  // unaffected and still checked, which is how OTA is exercised on this chip.
  if (manifestUrl.startsWith("https://") &&
      !fry::waitForHeapGate(HEAP_GATE_OTA, HEAP_GATE_OTA_BLOCK, 1)) {
    // Print the numbers, not just the verdict. "insufficient" alone cost real diagnostic time:
    // a board carrying a stale plain-http lab override never reaches this branch at all, and its
    // unrelated "manifest fetch HTTP -1" (lab server unreachable) was read for two runs as
    // evidence of a TLS/heap failure on the GitHub path that was in fact never attempted.
    // With the shortfall visible, the two situations can never be confused again.
    Serial.printf("ota: skipped https manifest check - need blk>=%u free>=%u, have blk=%u free=%u\n",
                  static_cast<unsigned>(HEAP_GATE_OTA_BLOCK), static_cast<unsigned>(HEAP_GATE_OTA),
                  static_cast<unsigned>(fry::queryMaxFreeBlock()),
                  static_cast<unsigned>(ESP.getFreeHeap()));
    return false;
  }
#endif

  HTTPClient http;
  WiFiClientSecure sec;
  WiFiClient plain;
  if (!otaBeginUrl(http, sec, plain, manifestUrl)) {
    Serial.println("ota: manifest fetch begin failed");
    return false;
  }
  int code = http.GET();
  if (code != 200) {
    // Log the largest contiguous block alongside the code. HTTPClient collapses connect-refused,
    // iobuf-OOM and TLS-handshake-failure all into -1, and the 30 s [health] line samples far too
    // coarsely to catch the allocation peak, so without blk here a -1 is undiagnosable.
    Serial.printf("ota: manifest fetch HTTP %d (blk=%u)\n", code,
                  static_cast<unsigned>(fry::queryMaxFreeBlock()));
    http.end();
    return false;
  }
  String body = http.getString();
  http.end();

  JsonDocument doc;
  if (deserializeJson(doc, body)) {
    Serial.println("ota: manifest parse failed");
    return false;
  }

  const char* latest = doc["firmware_version"] | "";
  const char* channel = doc["channel"] | "";
  JsonObject build = doc["builds"][FRY_BUILD_ENV];
  const char* url = build["url"] | "";
  const char* sha = build["sha256"] | "";
  // Only ever move FORWARD, by SemVer precedence (0.4.1-rc.1 < 0.4.1). This was strcmp(...) != 0,
  // which updated in either direction, so a device running a newer build than the published
  // manifest downgraded itself (observed on the bench: cur=0.1.1 latest=0.1.0 action=update).
  // Deliberate rollback is slot-based, not manifest-driven. A manifest for the other channel, the
  // version this board already rolled back from, or a manifest without this env's build (a chip
  // left out on purpose) never updates.
  const String badver = fry_config::getOtaBadVer();
  const fry::OtaDecision decision = fry::decideOtaUpdate(channel, FRY_OTA_CHANNEL, latest,
                                                         FRY_FIRMWARE_VERSION, badver.c_str(), url, sha);
  const bool willUpdate = decision == fry::OtaDecision::Update;
  Serial.printf("ota: manifest check cur=%s latest=%s action=%s\n", FRY_FIRMWARE_VERSION,
                strlen(latest) ? latest : "?", willUpdate ? "update" : "none");
  if (!willUpdate) {
    if (decision != fry::OtaDecision::NotNewer) {
      Serial.printf("ota: not updating - %s (manifest channel=%s, ours=%s)\n",
                    fry::otaDecisionName(decision), strlen(channel) ? channel : "prod", FRY_OTA_CHANNEL);
    }
    return false;
  }

  return downloadAndApply(url, sha, latest);
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
