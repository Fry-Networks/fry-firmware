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
#include "key_policy.h"
#include "miner_key.h"
#include "ota_boot_counter.h"
#include "ota_health.h"
#include "sha256.h"
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

namespace fry_ota {

namespace {

fry::HeartbeatTracker s_heartbeat;
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
  Serial.println("ota: boot-fail limit reached - ROLLBACK IMPOSSIBLE on ESP8266 (one slot)");
  fry_config::clearOtaPending();
#else
  const esp_partition_t* running = esp_ota_get_running_partition();
  const esp_partition_t* other = esp_ota_get_next_update_partition(nullptr);
  if (other && running && other->address != running->address) {
    Serial.println("ota: boot-fail limit reached - booting the other OTA slot");
    fry_config::setOtaRolledBack(true);
    esp_ota_set_boot_partition(other);
  } else {
    Serial.println("ota: boot-fail limit reached but no other OTA slot found - staying");
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
        Serial.printf("ota: marking %s valid FAILED (err=%d) - retried on the next hardwareapi answer\n",
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
  Serial.printf("ota: image %s marked valid after %lus (hardwareapi answered, last http=%d; %s)\n",
                FRY_FIRMWARE_VERSION, millis() / 1000UL, s_heartbeat.lastHttp(), why ? why : "?");
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
    s_confirmPending = true;
    Serial.printf("ota: image %s is pending verification - valid once hardwareapi answered and it "
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
    Serial.printf("ota: first boot %s - awaiting confirmation (%u/%u attempts)\n",
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
        Serial.printf("ota: %s was rolled back - running %s, strike %u/%u for %s%s\n", pending.c_str(),
                      FRY_FIRMWARE_VERSION, strikes, fry::kOtaPermanentStrikes, pending.c_str(),
                      strikes >= fry::kOtaPermanentStrikes ? " - it will not be installed again"
                                                           : " - retried after the next 6 h check");
      } else if (plannedRestart) {
        Serial.printf("ota: %s was rolled back by a planned restart - not counted\n", pending.c_str());
      }
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
    Serial.println("[fault] FRY_TEST_FAULT=3 - crashing 60 s after the first heartbeat");
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
  Serial.printf("ota: no hardwareapi answer after %lus of Wi-Fi on pending image %s - rolling back\n",
                static_cast<unsigned long>(s_verifyMs / 1000), FRY_FIRMWARE_VERSION);
  Serial.flush();
  esp_ota_mark_app_invalid_rollback_and_reboot();
  // Only reached when there is nothing to roll back to. Stay, keep reporting "pending", and let a
  // later answer mark the image valid (tryMarkValid) so a forward fix can still arrive.
  s_rollbackFailed = true;
  Serial.printf("ota: rollback impossible (no other valid image) - staying on pending %s\n",
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
  // Round 2 F4: a keyless USER_SUPPLIED board makes no hardwareapi call at all, so a new image
  // could never verify - it would only roll back. Update once the owner has written the key.
  {
    char key[40] = {0};
    fry_identity::ensureMinerKey(key, sizeof(key));
    if (!fry::keyAllowsJoin(fry::kBuildKeyModel, key[0] != 0)) {
      if (!s_loggedKeyless) {
        s_loggedKeyless = true;
        Serial.println("ota: manifest check skipped - no miner key yet");
      }
      return false;
    }
  }
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
  // version this board is holding strikes for (skipped on the first check after a rollback, for
  // good at 3 - PROTOCOL.md 11.8), or a manifest without this env's build (a chip left out on
  // purpose) never updates.
  String badver = fry_config::getOtaBadVer();
  uint8_t badn = badver.length() ? fry_config::getOtaBadN() : 0;
  if (fry::strikesReset(latest, badver.c_str())) {
    fry_config::setOtaStrikes("", 0);
    Serial.printf("ota: manifest names %s - strikes for %s cleared\n", latest, badver.c_str());
    badver = "";
    badn = 0;
  }
  const bool skip = fry::skipBadVersion(latest, badver.c_str(), badn, s_firstCheckAfterRollback);
  s_firstCheckAfterRollback = false;
  const fry::OtaDecision decision = fry::decideOtaUpdate(
      channel, FRY_OTA_CHANNEL, latest, FRY_FIRMWARE_VERSION, skip ? badver.c_str() : "", url, sha);
  const bool willUpdate = decision == fry::OtaDecision::Update;
  Serial.printf("ota: manifest check cur=%s latest=%s action=%s\n", FRY_FIRMWARE_VERSION,
                strlen(latest) ? latest : "?", willUpdate ? "update" : "none");
  if (!willUpdate) {
    if (decision != fry::OtaDecision::NotNewer) {
      Serial.printf("ota: not updating - %s (manifest channel=%s, ours=%s, strikes=%u)\n",
                    fry::otaDecisionName(decision), strlen(channel) ? channel : "prod", FRY_OTA_CHANNEL,
                    static_cast<unsigned>(badn));
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
