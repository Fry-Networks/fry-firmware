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
#include "http_tls.h"
#include "ota_boot_counter.h"
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

namespace fry_ota {

namespace {

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
    return fry_http::beginHttpsUrl(http, sec, url);
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
  if (ESP.getFreeHeap() < HEAP_GATE_OTA) {
    Serial.println("ota: heap gate failed");
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

bool checkNow() {
  String manifestUrl = fry_config::getOtaUrl();
  if (manifestUrl.length() == 0) manifestUrl = OTA_MANIFEST_URL;
  if (manifestUrl.length() == 0) return false;

  HTTPClient http;
  WiFiClientSecure sec;
  WiFiClient plain;
  if (!otaBeginUrl(http, sec, plain, manifestUrl)) {
    Serial.println("ota: manifest fetch begin failed");
    return false;
  }
  int code = http.GET();
  if (code != 200) {
    Serial.printf("ota: manifest fetch HTTP %d\n", code);
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
  JsonObject build = doc["builds"][FRY_BUILD_ENV];
  const char* url = build["url"] | "";
  const char* sha = build["sha256"] | "";
  bool willUpdate = (strlen(latest) > 0) && strcmp(latest, FRY_FIRMWARE_VERSION) != 0 &&
                    strlen(url) > 0 && strlen(sha) > 0;
  Serial.printf("ota: manifest check cur=%s latest=%s action=%s\n", FRY_FIRMWARE_VERSION,
                strlen(latest) ? latest : "?", willUpdate ? "update" : "none");
  if (!willUpdate) return false;

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
