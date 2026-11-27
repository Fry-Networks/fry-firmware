// Built only by the Pico / BK7231N envs (platformio.boards.ini defines FRY_BOARDS_PORT); the ESP envs compile all of src/.
#if defined(FRY_BOARDS_PORT)
// OTA client of the Pico and BK7231N boards behind src/core/ota_client.h (PROTOCOL.md sections 6 and 11.5).
//
//   manifest  GET OTA_MANIFEST_URL (or fry_ota/url), https only, redirects followed by hand (<= 5 hops, every hop's host must have a
//             trust set: lib/fry_core/ota_redirect.h + tls_trust.h). builds[FRY_BUILD_ENV] = {url, sha256}; the decision of whether
//             and what to install is lib/fry_core/ota_board_policy.h (pure, tested under native_boards).
//   image     streamed through Update (Pico: arduino-pico Updater, staged as firmware.bin in LittleFS and flashed by the boot-ROM
//             helper on the next reboot; BK7231N: LibreTiny Update, a UF2 stream written block by block into the download partition
//             and activated by the Beken bootloader). The SHA-256 is computed over the stream and compared BEFORE the image is
//             committed: the last 512 bytes are held back, so a mismatch ends the update incomplete (nothing is staged or activated).
//
// Single slot, like the ESP8266: there is no bootloader rollback. fry_ota/pending + the boot counter (lib/fry_core/ota_board_policy.h
// bootLimitReached) only report an image that never reached hardwareapi; the next release is the recovery.
#include "../core/ota_client.h"

#include <ArduinoJson.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>

#if defined(FRY_BOARD_PICO)
#include <LittleFS.h>
#include <Updater.h>
#else
#include <Update.h>
#endif

#include <cstring>

#include "../core/flash_print.h"
#include "../core/fry_config.h"
#include "../core/trigger_hooks.h"
#include "../core/wifi_station.h"
#include "config.h"
#include "fry_board_hal.h"
#include "ota_board_policy.h"
#include "ota_redirect.h"
#include "ota_sha_match.h"
#include "sha256.h"
#include "tls_client.h"
#include "tls_trust.h"

#ifndef FRY_FIRMWARE_VERSION
#define FRY_FIRMWARE_VERSION "0.0.0-dev"
#endif
#ifndef FRY_BUILD_ENV
#define FRY_BUILD_ENV "unknown"
#endif

namespace fry_ota {

namespace {

const unsigned long kFirstCheckMs = 90UL * 1000UL;   // after boot, once the registration had its chance
const unsigned long kSettleMs = 60UL * 1000UL;       // an answer from hardwareapi this long ago confirms the image
const uint32_t kManifestMax = 16384;
const size_t kHoldBytes = 512;                       // one UF2 block; also the Pico tail
const uint32_t kBkImageMax = 4u * 1024u * 1024u;

bool s_confirmPending = false;
bool s_haveAnswer = false;
unsigned long s_firstAnswerMs = 0;
bool s_haveOk = false;
unsigned long s_lastOkMs = 0;
unsigned long s_nextCheckMs = kFirstCheckMs;
bool s_checking = false;

void removeStaged() {
#if defined(FRY_BOARD_PICO)
  if (LittleFS.begin()) LittleFS.remove("firmware.bin");
#endif
}

void maybeConfirm() {
  if (!s_confirmPending || !s_haveAnswer) return;
  if (millis() - s_firstAnswerMs < kSettleMs) return;
  confirmGood();
  FRY_PRINTF("ota: image %s confirmed after hardwareapi answered\n", FRY_FIRMWARE_VERSION);
}

// GET with the redirects followed by hand. Every hop must be https and its host must have a trust set (a release asset is two
// hops and changes host). Returns the final status with `http` still open on it, or a negative value on a refusal / transport error.
int getFollowing(HTTPClient& http, WiFiClientSecure& sec, String& url) {
  const char* collect[] = {"Location"};
  for (uint8_t hops = 0;; hops++) {
    if (!url.startsWith("https://")) return -1000;
    http.end();
    sec.stop();
    if (!fry_boards::prepareSecure(sec, url.c_str())) return -1001;
    http.setFollowRedirects(HTTPC_DISABLE_FOLLOW_REDIRECTS);
    http.setReuse(false);
    http.setTimeout(20000);
    http.collectHeaders(collect, 1);
    if (!http.begin(sec, url)) return -1002;
    const int code = http.GET();
    if (!fry::isRedirectStatus(code)) return code;
    String loc = http.header("Location");
    const fry::RedirectDecision d = fry::decideRedirect(code, hops, loc.c_str());
    if (d != fry::RedirectDecision::Follow) {
      FRY_PRINTF("ota: redirect refused (%d)\n", static_cast<int>(d));
      return -1003;
    }
    char host[64];
    if (!fry_boards::hostOfUrl(loc.c_str(), host, sizeof(host)) || fry::trustSetForHost(host) == fry::TrustSet::None) {
      FRY_PRINTLN("ota: redirect to a host without trust anchors refused");
      return -1004;
    }
    url = loc;
  }
}

// Streams the image into Update, holding the last kHoldBytes back until the digest matched.
bool downloadAndApply(const String& startUrl, const char* shaExpect, const char* version, fry::boards::ImageKind kind) {
  HTTPClient http;
  WiFiClientSecure sec;
  String url = startUrl;
  const int code = getFollowing(http, sec, url);
  if (code != 200) {
    FRY_PRINTF("ota: image HTTP %d\n", code);
    http.end();
    return false;
  }
  const int len = http.getSize();
  if (len <= 0) {
    FRY_PRINTLN("ota: no Content-Length");
    http.end();
    return false;
  }
  const uint32_t ulen = static_cast<uint32_t>(len);
  if (kind == fry::boards::ImageKind::BkUf2) {
    if (ulen % 512 != 0 || ulen > kBkImageMax) {  // a UF2 file is a whole number of 512-byte blocks
      FRY_PRINTF("ota: UF2 size %d not acceptable\n", len);
      http.end();
      return false;
    }
  } else if (ulen > fry::board::flashInfo().otaFreeBytes) {
    FRY_PRINTF("ota: image %d B does not fit the %u B staging space\n", len, static_cast<unsigned>(fry::board::flashInfo().otaFreeBytes));
    http.end();
    return false;
  }
  if (ulen <= kHoldBytes) {
    FRY_PRINTLN("ota: image too small");
    http.end();
    return false;
  }

  removeStaged();
  if (!Update.begin(ulen)) {
    FRY_PRINTLN("ota: Update.begin failed");
    http.end();
    return false;
  }

  WiFiClient* stream = http.getStreamPtr();
  fry::Sha256 sha;
  uint8_t* buf = static_cast<uint8_t*>(malloc(1024 + kHoldBytes));
  uint8_t* hold = buf + 1024;
  if (!buf) {
    FRY_PRINTLN("ota: no memory for the download buffer");
    Update.end();
    http.end();
    return false;
  }
  size_t holdLen = 0, done = 0, written = 0;
  uint8_t head[256];
  size_t headLen = 0;
  bool headerChecked = false;
  bool ok = true;
  unsigned long lastData = millis(), lastLog = 0;
  while (done < ulen) {
    const size_t avail = stream->available();
    if (!avail) {
      if (!stream->connected() || millis() - lastData > 20000) break;
      delay(1);
      continue;
    }
    const size_t want = avail > 1024 ? 1024 : avail;
    const int r = stream->readBytes(buf, want > ulen - done ? ulen - done : want);
    if (r <= 0) break;
    lastData = millis();
    // The first 256 bytes are checked before anything reaches Update (writes only start once 512 bytes are held).
    if (headLen < sizeof(head)) {
      const size_t room = sizeof(head) - headLen;
      const size_t c = static_cast<size_t>(r) < room ? static_cast<size_t>(r) : room;
      memcpy(head + headLen, buf, c);
      headLen += c;
    }
    if (!headerChecked && headLen == sizeof(head)) {
      headerChecked = true;
      if (!fry::boards::imageHeaderPlausible(kind, head, headLen)) {
        FRY_PRINTLN("ota: stream does not look like a firmware image - rejected");
        ok = false;
        break;
      }
    }
    sha.update(buf, static_cast<size_t>(r));
    done += static_cast<size_t>(r);
    // Everything but the newest kHoldBytes goes to Update; the rest waits in `hold`.
    size_t off = 0;
    while (off < static_cast<size_t>(r)) {
      if (holdLen == kHoldBytes) {
        if (Update.write(hold, kHoldBytes) != kHoldBytes) {
          ok = false;
          break;
        }
        written += kHoldBytes;
        holdLen = 0;
      }
      const size_t take = (static_cast<size_t>(r) - off) < (kHoldBytes - holdLen) ? (static_cast<size_t>(r) - off) : (kHoldBytes - holdLen);
      memcpy(hold + holdLen, buf + off, take);
      holdLen += take;
      off += take;
    }
    if (!ok) {
      FRY_PRINTLN("ota: write failed");
      break;
    }
    if (millis() - lastLog > 3000) {
      lastLog = millis();
      FRY_PRINTF("ota: downloading %u/%u KB\n", static_cast<unsigned>(done / 1024), static_cast<unsigned>(ulen / 1024));
    }
    yield();
  }
  http.end();

  if (!ok || done != ulen || written + holdLen != ulen) {
    if (ok) FRY_PRINTF("ota: incomplete download %u/%u\n", static_cast<unsigned>(done), static_cast<unsigned>(ulen));
    Update.end();  // incomplete: nothing is staged or activated
    removeStaged();
    free(buf);
    return false;
  }

  uint8_t digest[32];
  char hex[65];
  sha.finish(digest);
  fry::bytesToHexUpper(digest, 32, hex, sizeof(hex));
  fry::asciiLowerInPlace(hex);
  if (!fry::sha256HexMatches(hex, shaExpect, strlen(shaExpect))) {
    FRY_PRINTF("ota: sha256 mismatch (got %.16s want %.16s) - rejected\n", hex, shaExpect);
    Update.end();  // the tail is still held: the update ends incomplete, nothing is staged or activated
    removeStaged();
    free(buf);
    return false;
  }

  // Digest verified: the held tail completes the stream, and only then does Update stage/activate the image.
  const bool tailOk = Update.write(hold, holdLen) == holdLen;
  free(buf);
  if (!tailOk || !Update.end(true)) {
    FRY_PRINTLN("ota: Update.end failed");
    removeStaged();
    return false;
  }
  fry_config::setOtaPending(version);
  fry_config::setOtaBootFails(0);
  FRY_PRINTF("ota: applied %s sha=ok\n", version);
  Serial.flush();
  delay(500);
  fry::board::restart();
  return true;
}

}  // namespace

void init() {
  const String pending = fry_config::getOtaPending();
  if (pending.length() == 0) return;
  if (pending == FRY_FIRMWARE_VERSION) {
    s_confirmPending = true;
    uint8_t fails = fry_config::getOtaBootFails();
    if (fails < 255) fails++;
    fry_config::setOtaBootFails(fails);
    if (fry::boards::bootLimitReached(fails, OTA_BOOT_FAIL_LIMIT)) {
      // Single slot: there is nothing to roll back to. Stop counting and let the next release replace this image.
      FRY_PRINTF("ota: image %s has not reached hardwareapi in %u boots; no previous image to return to\n", FRY_FIRMWARE_VERSION,
                 static_cast<unsigned>(fails));
      confirmGood();
      return;
    }
    FRY_PRINTF("ota: first boot %s - awaiting confirmation (%u/%u attempts)\n", FRY_FIRMWARE_VERSION, static_cast<unsigned>(fails),
               static_cast<unsigned>(OTA_BOOT_FAIL_LIMIT));
  } else {
    // The image that is running is not the one that was staged: staging did not take. Drop the marker so checks resume.
    FRY_PRINTF("ota: staged %s did not take, still running %s\n", pending.c_str(), FRY_FIRMWARE_VERSION);
    fry_config::clearOtaPending();
    fry_config::clearOtaBootFails();
  }
}

void confirmGood() {
  fry_config::clearOtaPending();
  fry_config::clearOtaBootFails();
  fry_config::setOtaPlannedRestart(false);
  s_confirmPending = false;
  removeStaged();
}

void noteHeartbeat(int http, const char* what) {
  if (http <= 0) return;  // a transport error proves nothing
  if (!s_haveAnswer) {
    s_haveAnswer = true;
    s_firstAnswerMs = millis();
  }
  if (http >= 200 && http < 300) {
    s_haveOk = true;
    s_lastOkMs = millis();
  }
  maybeConfirm();
}

void noteStartupDone() {}
void noteTunnelBringUpAttempted() {}
void noteTunnelFetchAttempted() {}

void notePlannedRestart() { fry_config::setOtaPlannedRestart(true); }

void loopGuard() { maybeConfirm(); }

int32_t heartbeatAgeS() { return s_haveOk ? static_cast<int32_t>((millis() - s_lastOkMs) / 1000UL) : -1; }

const char* imageStateName() { return s_confirmPending ? "pending" : "valid"; }

bool checkNow() {
  if (s_checking || !fry_wifi::isConnected()) return false;
  s_checking = true;
  struct Reset {
    ~Reset() { s_checking = false; }
  } reset;

  const String pending = fry_config::getOtaPending();
  const String override = fry_config::getOtaUrl();
  String url = override.length() ? override : String(OTA_MANIFEST_URL);

  JsonDocument doc;
  {
    HTTPClient http;
    WiFiClientSecure sec;
    const int code = getFollowing(http, sec, url);
    if (code != 200) {
      FRY_PRINTF("ota: manifest HTTP %d\n", code);
      http.end();
      return false;
    }
    const int sz = http.getSize();
    if (sz <= 0 || static_cast<uint32_t>(sz) > kManifestMax) {
      FRY_PRINTF("ota: manifest size %d not acceptable\n", sz);
      http.end();
      return false;
    }
    // HTTPClient::getString() does not exist on LibreTiny: read the (size-checked) body off the stream.
    String body;
    body.reserve(static_cast<unsigned>(sz) + 1);
    WiFiClient* bs = http.getStreamPtr();
    for (unsigned long last = millis(); body.length() < static_cast<unsigned>(sz) && millis() - last < 15000;) {
      if (bs->available()) {
        body += static_cast<char>(bs->read());
        last = millis();
      } else if (!bs->connected()) {
        break;
      } else {
        delay(1);
      }
    }
    http.end();
    if (deserializeJson(doc, body)) {
      FRY_PRINTLN("ota: manifest is not JSON");
      return false;
    }
  }

  const char* version = doc["firmware_version"] | "";
  JsonVariantConst build = doc["builds"][FRY_BUILD_ENV];
  fry::boards::OtaInput in{};
  in.os = FRY_BUILD_ENV;
  in.runningVersion = FRY_FIRMWARE_VERSION;
  in.manifestVersion = version;
  in.channel = doc["channel"] | "";
  in.buildPresent = build.is<JsonObjectConst>();
  in.url = build["url"] | "";
  in.sha256 = build["sha256"] | "";
  in.imageBytes = 0;
  in.freeSlotBytes = fry::board::flashInfo().otaFreeBytes;
  in.pendingVersion = pending.c_str();
  const fry::boards::OtaDecision d = fry::boards::decideOta(in);
  if (d != fry::boards::OtaDecision::Apply) {
    FRY_PRINTF("ota: %s (running %s, manifest %s)\n", fry::boards::decisionText(d), FRY_FIRMWARE_VERSION, version);
    return false;
  }
  FRY_PRINTF("ota: update %s -> %s\n", FRY_FIRMWARE_VERSION, version);
  const String imageUrl = String(in.url);
  const String sha = String(in.sha256);
  const String ver = String(version);
  doc.clear();
  return downloadAndApply(imageUrl, sha.c_str(), ver.c_str(), fry::boards::imageKindForOs(FRY_BUILD_ENV));
}

void tick() {
  if (!fry_wifi::isConnected()) return;
  const unsigned long now = millis();
  if (now < s_nextCheckMs) return;
  s_nextCheckMs = now + OTA_CHECK_MS;
  checkNow();
}

}  // namespace fry_ota

extern "C" void fry_trigger_ota_now() { fry_ota::checkNow(); }
#endif  // FRY_BOARDS_PORT
