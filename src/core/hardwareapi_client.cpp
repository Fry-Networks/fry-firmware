#include "hardwareapi_client.h"

#include <ArduinoJson.h>

#include <cstring>
#include <ctime>
#if defined(ARDUINO_ARCH_ESP8266)
#include <memory>
#include <new>
#endif

#include "config.h"
#include "flash_print.h"
#include "fry_config.h"
#include "heartbeat_fields.h"
#include "http_tls.h"
#include "kv_store.h"
#include "miner_key.h"
#include "ota_client.h"
#include "provisioning_transport.h"
#include "reg_result.h"
#include "stale_token_heal.h"
#include "telemetry.h"
#include "trigger_hooks.h"
#include "wifi_station.h"
#if defined(FRY_HAS_WIREGUARD) && FRY_HAS_WIREGUARD
#include "vpn_relay.h"  // fry_vpn::relayLatency(): the ESP32 relay's connect-latency summary
#endif

#include <generated/fry_secrets.h>

#if !defined(ARDUINO_ARCH_ESP8266)
#include <esp_flash.h>
#include <esp_system.h>  // the ESP32 family reset reason
#endif

#ifndef FRY_FIRMWARE_VERSION
#define FRY_FIRMWARE_VERSION "0.0.0-dev"
#endif
#ifndef FRY_MINER_CODE
#define FRY_MINER_CODE "IOTVPN"
#endif
#ifndef FRY_BUILD_ENV
#define FRY_BUILD_ENV "unknown"
#endif

namespace fry_hwapi {

namespace {

// Flash facts for the heartbeat, read once and cached: the first call may touch flash (the sketch
// size walks the image header) and nothing here changes while the board runs. This is the only
// platform-specific part of the heartbeat body; the field set itself is lib/fry_core/heartbeat_fields.h.
//   ESP8266: ESP.getFlashChipRealSize() is the JEDEC-id size, ESP.getFlashChipSize() the image
//            header's (or the real one under FLASH_MAP_SUPPORT), ESP.getFreeSketchSpace() what
//            Updater.begin() will accept (Esp.cpp).
//   ESP32/C3: esp_flash_get_physical_size() reads the chip's own size (the pinned
//            arduino-esp32 ESP.getFlashChipSize() is derived from the same JEDEC id, so it is the
//            physical size there too); ESP.getFreeSketchSpace() is the next OTA partition's size.
fry::FlashInfo flashInfo() {
  static fry::FlashInfo cached{};
  static bool have = false;
  if (have) return cached;
  fry::FlashInfo fi{};
#if defined(ARDUINO_ARCH_ESP8266)
  fi.flashRealSize = ESP.getFlashChipRealSize();
#else
  uint32_t physical = 0;
  if (esp_flash_get_physical_size(nullptr, &physical) != ESP_OK) physical = 0;
  fi.flashRealSize = physical;
#endif
  fi.flashIdeSize = ESP.getFlashChipSize();
  fi.otaFreeBytes = ESP.getFreeSketchSpace();
  fi.sketchSize = ESP.getSketchSize();
  cached = fi;
  have = true;
  return cached;
}

#if defined(FRY_HEARTBEAT_HEAP) && defined(ARDUINO_ARCH_ESP8266)
__attribute__((noinline)) void addHeartbeatHeap(JsonDocument& doc) {
  // Own frame (noinline) so registerInstallation(), which sits on the deepest loop-stack path, does not grow. One umm_info pass gives
  // the three heap numbers coherently; the loop stack's high water is what the cont stack has never come back from since boot.
  uint32_t freeHeap = 0, maxBlock = 0;
  uint8_t frag = 0;
  ESP.getHeapStats(&freeHeap, &maxBlock, &frag);
  fry::addHeapFields(doc, {freeHeap, maxBlock, frag, ESP.getFreeContStack()});
}
#endif

#if defined(FRY_HAS_WIREGUARD) && FRY_HAS_WIREGUARD
__attribute__((noinline)) void addHeartbeatRelayLatency(JsonDocument& doc) {
  // Appended after the 13-member body exactly like addHeapFields above, and in its own frame for
  // the same reason: registerInstallation() sits on the deepest loop-stack path.
  const fry_vpn::RelayLatency l = fry_vpn::relayLatency();
  fry::addRelayLatencyFields(doc, {l.p50Ms, l.p95Ms, l.samples});
}
#endif

// Why the chip last reset, as the heartbeat's `reset_reason` (PROTOCOL.md 11.10). The SDK latches the value at boot and never
// changes it, and it is read once here and cached, so it costs two bytes of state and no SDK call after the first.
//   ESP8266: rst_info.reason via the core's reset-info pointer (0 power-on ... 6 external reset).
//   ESP32 family: esp_reset_reason_t (1 power-on, 3 software reset ...).
// The fry_hwapi::resetReason() definition below the anonymous namespace shares it with the boot banner in main.cpp.
__attribute__((noinline)) void addHeartbeatResetReason(JsonDocument& doc) {
  // Own frame (noinline), like the two helpers above: registerInstallation() sits on the deepest loop-stack path.
  fry::addResetReasonField(doc, resetReason());
}

// Updated unconditionally BEFORE every registration attempt (success or failure) so a rejected
// or failed call backs off to INSTALL_HEARTBEAT_MS just like a successful heartbeat does — the
// old design only updated this on success, which meant a persistent failure (e.g. the server
// rejecting our miner code with a 4xx) retried on literally every tick() call instead of backing
// off, since `!s_registered` alone was enough to trigger another attempt.
unsigned long s_lastRegisterAttemptMs = 0;
// Delay after the last attempt before the next one: the hourly heartbeat after a success or a 4xx,
// 60 s doubling to an hour while hardwareapi is unreachable (fry::nextRegisterDelayMs).
unsigned long s_nextRegisterDelayMs = INSTALL_HEARTBEAT_MS;
uint32_t s_regFailures = 0;
int s_lastRegHttp = 0;
bool s_loggedNoKey = false;
unsigned long s_lastPocMs = 0;
bool s_registered = false;
bool s_ntpSynced = false;
// Stale-token self-heal (lib/fry_core/stale_token_heal.h): at most one per boot. The 6 h bound
// across reboots is the persisted fry/healAt epoch.
bool s_staleTokenHealed = false;

const uint32_t kQuickRetryMs = 2000;

// The server's own words for a rejection ("detail" or "error" in the JSON body), bounded and with
// every key-shaped token masked (fry::sanitizeServerDetail). Never logs the body wholesale.
void readServerDetail(HTTPClient& http, const char* minerKey, char* out, size_t outLen) {
  out[0] = 0;
  // Not a JSON error body (or a chunked one of unknown length): do not buffer it. The rule is
  // fry::tooBigForServerDetail, pinned by test_server_detail_size (round 2 F10).
  if (fry::tooBigForServerDetail(http.getSize())) return;
  JsonDocument rdoc;
  if (deserializeJson(rdoc, http.getString())) return;
  const char* d = rdoc["detail"].is<const char*>() ? rdoc["detail"].as<const char*>()
                                                   : (rdoc["error"] | "");
  fry::sanitizeServerDetailLast4(d, minerKey, out, outLen);
}

// Authorization header per PROTOCOL.md section 5: the per-device token once issued, else the
// build-time bootstrap token, omitted entirely when both are empty. Never call this before the
// installation registration response has had a chance to persist a device_token.
void addAuthHeader(HTTPClient& http) {
  String token = fry_config::getDeviceToken();
  if (token.length() == 0) token = String(FRY_API_TOKEN);
  if (token.length() > 0) http.addHeader(FRY_TEXT("Authorization"), "Bearer " + token);
}

int computeSlot() {
  time_t now = time(nullptr);
  struct tm t;
  gmtime_r(&now, &t);
  int minutesSinceMidnight = t.tm_hour * 60 + t.tm_min;
  return (minutesSinceMidnight / 10) % 144;
}

}  // namespace

uint8_t resetReason() {
  static uint8_t cached = 0;
  static bool have = false;
  if (have) return cached;
#if defined(ARDUINO_ARCH_ESP8266)
  const uint32_t raw = ESP.getResetInfoPtr()->reason;
#else
  const uint32_t raw = static_cast<uint32_t>(esp_reset_reason());
#endif
  cached = raw > 255 ? 255 : static_cast<uint8_t>(raw);
  have = true;
  return cached;
}

bool ensureNtpSynced(uint32_t timeoutMs) {
  if (s_ntpSynced) return true;
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  unsigned long start = millis();
  while (millis() - start < timeoutMs) {
    // A plausible synced time is well past the epoch (year 2000 = 946684800).
    if (time(nullptr) > 946684800) {
      s_ntpSynced = true;
      return true;
    }
    delay(250);
  }
  return false;
}

#if defined(ARDUINO_ARCH_ESP8266)
// registerInstallation() sits on the deepest boot-time loop-stack path: loop() -> tick() -> here -> the TLS connect below it, a few
// hundred bytes from the end of the 4 KB cont stack (bench: 736..1152 B free at the end of the registration interval). What it holds
// across the connect lives in heap blocks, as ota_client.cpp's ManifestClients does: the four text buffers for the whole call, the two
// TLS clients for one attempt: the frame goes from 736 B to 352 B (-fstack-usage). The ESP32 keeps its stack locals.
namespace {
struct RegText {
  char minerKey[40];
  char installId[40];
  char deviceName[32];
  char detail[128];
};
struct RegClients {
  WiFiClientSecure sec;
  HTTPClient http;
};
}  // namespace
#endif

namespace {

// NVS state of the stale-token self-heal (lib/fry_core/stale_token_heal.h), in the fry namespace
// next to installId/deviceToken. Every key name here is 15 characters or fewer: NVS_KEY_NAME_MAX_SIZE
// is 16 including the NUL and nvs_set_str rejects anything longer, so a longer name would make the
// whole heal a silent no-op. The shadow pair is written BEFORE the live pair is cleared, so no path
// leaves the board with neither pair.
const char* const kShadowId = "shdwInstallId";
const char* const kShadowToken = "shdwDevToken";

// The shadow pair through one read-only handle ("" for a key that is absent).
void readTokenPairShadow(String& id, String& tok) {
  KvStore r;
  r.begin("fry", true);
  id = r.getString(kShadowId, "");
  tok = r.getString(kShadowToken, "");
  r.end();
}

// Proven by READ-BACK of both values: ESP32's putString returns 0 for a rejected key and the
// ESP8266 store ignores save() failure, so a write return alone proves nothing. An empty or
// unreadable shadow is a failed stash, and the caller must then clear nothing.
bool stashTokenPair() {
  String id = fry_config::getInstallId(), tok = fry_config::getDeviceToken();
  if (id.length() == 0 || tok.length() == 0) return false;
  KvStore w;
  if (!w.begin("fry", false)) return false;
  bool wrote = w.putString(kShadowId, id) > 0 && w.putString(kShadowToken, tok) > 0;
  w.end();
  String rid, rtok;
  readTokenPairShadow(rid, rtok);
  return wrote && rid.length() > 0 && rtok.length() > 0 &&
         fry::pairsMatchByteForByte(rid.c_str(), id.c_str()) &&
         fry::pairsMatchByteForByte(rtok.c_str(), tok.c_str());
}

// Only an erase when a shadow key actually exists: no hourly nvs_erase_key error spam.
void dropTokenPairShadow() {
  KvStore r;
  r.begin("fry", true);
  bool any = r.isKey(kShadowId) || r.isKey(kShadowToken);
  r.end();
  if (!any) return;
  KvStore w;
  w.begin("fry", false);
  w.remove(kShadowId);
  w.remove(kShadowToken);
  w.end();
}

// Puts the shadow pair back and drops the shadows only when BOTH live values are non-empty and
// byte-identical to the shadows; otherwise nothing is written and the shadows stay, so the board
// never holds neither pair.
bool restoreTokenPair() {
  String id, tok;
  readTokenPairShadow(id, tok);
  if (id.length() == 0 || tok.length() == 0) return false;  // an empty shadow is not a pair
  fry_config::setInstallId(id.c_str());
  fry_config::setDeviceToken(tok.c_str());
  if (!fry::pairsMatchByteForByte(id.c_str(), fry_config::getInstallId().c_str()) ||
      !fry::pairsMatchByteForByte(tok.c_str(), fry_config::getDeviceToken().c_str())) {
    return false;
  }
  dropTokenPairShadow();
  return true;
}

// A crash between the heal's clear and its retry leaves the live pair empty with the shadows in
// NVS: put the pair back BEFORE ensureInstallId() mints a new installation. With a live value still
// present the shadows are leftovers (a pre-heal pair whose heartbeat never came), so they go.
void recoverOrphanedTokenPair() {
  if (fry_config::getInstallId().length() > 0 || fry_config::getDeviceToken().length() > 0) {
    dropTokenPairShadow();
    return;
  }
  restoreTokenPair();
}

// The bounded heal. Only the stale-token signature can reach it, only on a NON-default apiBase (the
// compiled default's registration route is open, where a transient 404 must never reset a healthy
// installation), and only while this boot and the persisted 6 h window allow it, so it can never
// loop or storm. It shadows the identity pair, clears the live pair, registers ONCE with NO
// Authorization header at all (clearing the token would otherwise fall back to the build-time
// FRY_API_TOKEN), and restores the pair byte for byte when that attempt fails for ANY reason. A
// success keeps the shadows until putPoc() sees an accepted heartbeat.
bool healStaleTokenIfDue(HTTPClient& http, WiFiClientSecure& sec, const String& url,
                         const char* installId, const String& body, int code, bool tokenSent) {
  if (s_staleTokenHealed || !fry::isStaleTokenSignature(code, tokenSent)) return false;
  if (strcmp(fry_config::getApiBase().c_str(), HARDWAREAPI_BASE) == 0) return false;
  const time_t nowT = time(nullptr);
  const uint32_t epochNow = nowT == static_cast<time_t>(-1) ? 0 : static_cast<uint32_t>(nowT);
  KvStore h;
  h.begin("fry", true);
  const uint32_t lastHeal = h.getUInt("healAt", 0);
  h.end();
  if (!fry::healWindowOpen(s_staleTokenHealed, lastHeal, epochNow)) return false;
  // Stash (and prove it) BEFORE the window is burnt, so a failed stash costs no 6 h.
  if (!stashTokenPair()) return false;
  s_staleTokenHealed = true;  // one per boot, whatever the outcome below
  KvStore w;
  w.begin("fry", false);
  w.putUInt("healAt", epochNow);  // one per 6 h, across reboots
  w.end();
  fry_config::clearInstallation();
  char newId[40];
  fry_identity::ensureInstallId(newId, sizeof(newId));  // a fresh installation, registered token-less
  String healBody = body;
  healBody.replace(installId, newId);
  const String healUrl = url.substring(0, url.length() - strlen(installId)) + newId;
  int healCode = -1;
  String token;
  if (fry_http::beginHttpsUrl(http, sec, healUrl)) {
    const FryText contentType = FRY_TEXT("Content-Type");  // test_flash_text pins the 3 literal uses
    http.addHeader(contentType, FRY_TEXT("application/json"));
    healCode = http.POST(healBody);
    if (healCode >= 200 && healCode < 300) {
      JsonDocument rdoc;
      deserializeJson(rdoc, http.getString());
      token = String(rdoc["device_token"] | "");
    }
  }
  http.end();
  if (healCode < 200 || healCode >= 300) {
    if (!restoreTokenPair()) {  // the shadows stay: never a board with neither pair
      FRY_PRINTLN("api: stale-token retry failed and the pair could not be restored; shadows kept");
    }
    return false;
  }
  if (token.length() > 0) fry_config::setDeviceToken(token.c_str());
  if (!fry_config::getKeyOk()) fry_config::setKeyOk(true);  // the fresh registration confirmed it
  s_lastRegHttp = healCode;  // the last registration attempt this boot is now the healed one
  FRY_PRINTF("api: stale device token healed http=404 install=%s token=%s\n", newId,
             token.length() > 0 ? "present" : "none");
  return true;
}

}  // namespace

bool registerInstallation() {
#if defined(ARDUINO_ARCH_ESP8266)
  std::unique_ptr<RegText> text(new (std::nothrow) RegText());
  if (!text) {
    FRY_PRINTLN("api: no memory for the registration");
    return false;
  }
  char (&minerKey)[40] = text->minerKey;
#else
  char minerKey[40];
#endif
  fry_identity::ensureMinerKey(minerKey, sizeof(minerKey));
  if (minerKey[0] == 0) {
    // USER_SUPPLIED board without a key: there is nothing to register as. Not an API failure.
    if (!s_loggedNoKey) {
      s_loggedNoKey = true;
      FRY_PRINTLN("api: registration skipped - no miner key yet");
    }
    fry_provisioning::notifyKeyMissing();
    return false;
  }
#if defined(ARDUINO_ARCH_ESP8266)
  char (&installId)[40] = text->installId;
#else
  char installId[40];
#endif
  // A crash inside a self-heal can leave the live pair empty with the shadows in NVS: put the pair
  // back before ensureInstallId() would mint a new installation.
  recoverOrphanedTokenPair();
  fry_identity::ensureInstallId(installId, sizeof(installId));
#if defined(ARDUINO_ARCH_ESP8266)
  char (&deviceName)[32] = text->deviceName;
#else
  char deviceName[32];
#endif
  fry_identity::getDeviceName(deviceName, sizeof(deviceName));

  fry::InstallationFields fields{};
  fields.minerKey = minerKey;
  fields.installId = installId;
  fields.minerCode = FRY_MINER_CODE;
  fields.softwareVersion = FRY_FIRMWARE_VERSION;
  fields.pocVersion = "1.0.0";
  fields.hostname = deviceName;
  fields.os = FRY_BUILD_ENV;
  fields.deviceName = deviceName;
  fields.flash = flashInfo();
  JsonDocument doc;
  fry::buildInstallationDoc(doc, fields);
#if defined(FRY_HEARTBEAT_HEAP) && defined(ARDUINO_ARCH_ESP8266)
  addHeartbeatHeap(doc);
#endif
#if defined(FRY_HAS_WIREGUARD) && FRY_HAS_WIREGUARD
  addHeartbeatRelayLatency(doc);
#endif
  addHeartbeatResetReason(doc);
  String body;
  serializeJson(doc, body);

  String url = fry_config::getApiBase() + FRY_TEXT("/installations/") + minerKey + FRY_TEXT("/installations/") + installId;
  // Whether our stored device token (not the build-time bootstrap token) rides on this attempt:
  // the stale-token signature needs both halves.
  const bool deviceTokenSent = fry_config::getDeviceToken().length() > 0;

  // One attempt plus one quick retry for an outage only. Anything longer is tick()'s schedule, so
  // the loop (Improv, the reset button, the relay) is never held for more than one retry.
  int code = -1;
  fry::RegClass cls = fry::RegClass::Unreachable;
#if defined(ARDUINO_ARCH_ESP8266)
  char (&detail)[128] = text->detail;
#else
  char detail[128] = {0};
#endif
  for (int attempt = 0; attempt < 2; attempt++) {
#if defined(ARDUINO_ARCH_ESP8266)
    std::unique_ptr<RegClients> clients(new (std::nothrow) RegClients());
    if (!clients) {
      FRY_PRINTLN("api: no memory for the registration client");
      break;  // code -1, Unreachable: the failure bookkeeping below backs off as for an unreachable server
    }
    WiFiClientSecure& sec = clients->sec;
    HTTPClient& http = clients->http;
#else
    WiFiClientSecure sec;
    HTTPClient http;
#endif
    code = -1;
    if (fry_http::beginHttpsUrl(http, sec, url)) {
      addAuthHeader(http);
      http.addHeader(FRY_TEXT("Content-Type"), FRY_TEXT("application/json"));
      code = http.POST(body);
    }
    s_lastRegHttp = code;
    fry_ota::noteHeartbeat(code, "register");  // any HTTP answer proves this image can reach us
    cls = fry::classifyRegistration(code);

    if (cls == fry::RegClass::Ok) {
      JsonDocument rdoc;
      deserializeJson(rdoc, http.getString());
      const char* token = rdoc["device_token"] | "";
      if (strlen(token) > 0) fry_config::setDeviceToken(token);
      http.end();
      FRY_PRINTF("api: registered install=%s token=%s\n", installId,
                    strlen(token) > 0 ? "present" : "none");
      if (!fry_config::getKeyOk()) fry_config::setKeyOk(true);  // the key is now confirmed
      s_regFailures = 0;
      s_nextRegisterDelayMs = INSTALL_HEARTBEAT_MS;
      fry_provisioning::notifyApiOk();
      return true;
    }
    if (!fry::regClassRetryQuickly(cls)) {
      // A 4xx is the server's answer; asking again seconds later gets the same one. This does NOT
      // touch fry_config's device token - except for the one stale-token signature below: a 404
      // while OUR device token was sent means the token is stale (a WG1 apiBase then skips its
      // token-less first-registration route), and the hourly retry would never clear it.
      readServerDetail(http, minerKey, detail, sizeof(detail));
      http.end();
      if (healStaleTokenIfDue(http, sec, url, installId, body, code, deviceTokenSent)) {
        s_regFailures = 0;
        s_nextRegisterDelayMs = INSTALL_HEARTBEAT_MS;
        fry_provisioning::notifyApiOk();
        return true;
      }
      break;
    }
    http.end();
    if (attempt == 0) delay(kQuickRetryMs);
  }

  if (s_regFailures < 0xFFFFFFFFu) s_regFailures++;
  s_nextRegisterDelayMs = fry::nextRegisterDelayMs(cls, s_regFailures);
  const fry::ProvErr err = fry::regClassProvErr(cls);
  if (cls == fry::RegClass::Unreachable) {
    FRY_PRINTF("api: registration failed install=%s http=%d detail=%u (%s) next=%lus\n", installId,
                  code, static_cast<unsigned>(err), fry::regClassText(cls),
                  s_nextRegisterDelayMs / 1000UL);
  } else {
    FRY_PRINTF("api: register rejected http=%d detail=%u (%s) server=\"%s\" next=%lus\n", code,
                  static_cast<unsigned>(err), fry::regClassText(cls), detail,
                  s_nextRegisterDelayMs / 1000UL);
  }
  fry_provisioning::notifyApiFail(err);
  return false;
}

int lastRegisterHttp() { return s_lastRegHttp; }

bool renewLease() {
  char minerKey[40];
  fry_identity::ensureMinerKey(minerKey, sizeof(minerKey));
  if (minerKey[0] == 0) return false;  // no key, no installation to lease
  char installId[40];
  fry_identity::ensureInstallId(installId, sizeof(installId));

  JsonDocument doc;
  doc["lease_seconds"] = LEASE_SECONDS;
  String body;
  serializeJson(doc, body);

  String url = fry_config::getApiBase() + FRY_TEXT("/installations/") + minerKey + FRY_TEXT("/leases/") + installId;
  WiFiClientSecure sec;
  HTTPClient http;
  if (!fry_http::beginHttpsUrl(http, sec, url)) return false;
  addAuthHeader(http);
  http.addHeader(FRY_TEXT("Content-Type"), FRY_TEXT("application/json"));
  int code = http.sendRequest("PATCH", body);  // String overload — avoids a const/non-const
                                                // uint8_t* signature mismatch between cores
  http.end();
  fry_ota::noteHeartbeat(code, "lease");
  return code > 0 && code < 300;
}

int putPoc() {
  char minerKey[40];
  fry_identity::ensureMinerKey(minerKey, sizeof(minerKey));
  if (minerKey[0] == 0) return -1;  // nothing to report as - checked before the NTP wait

  if (!ensureNtpSynced()) return -1;  // NTP before the first PoC, per PROTOCOL.md section 5

  JsonDocument doc;
  JsonObject document = doc["document"].to<JsonObject>();
  document["slot_number"] = computeSlot();
  document["miner_type"] = FRY_MINER_CODE;
  document["timestamp"] = static_cast<uint32_t>(time(nullptr));
  document["uptime_s"] = millis() / 1000;
  document["heap_free"] = ESP.getFreeHeap();
  document["rssi"] = fry_wifi::isConnected() ? fry_wifi::rssi() : 0;
  String body;
  serializeJson(doc, body);

  String url = fry_config::getApiBase() + FRY_TEXT("/PoC/") + minerKey + FRY_TEXT("/hardware");
  WiFiClientSecure sec;
  HTTPClient http;
  if (!fry_http::beginHttpsUrl(http, sec, url)) return -1;
  addAuthHeader(http);
  http.addHeader(FRY_TEXT("Content-Type"), FRY_TEXT("application/json"));
  int code = http.PUT(body);
  http.end();
  // An accepted heartbeat after a heal this boot proves the pair the heal installed; only then may
  // the stale-token shadow pair go (boot recovery drops leftovers from a reboot-before-heartbeat).
  if (code >= 200 && code < 300 && s_staleTokenHealed) dropTokenPairShadow();
  fry_ota::noteHeartbeat(code, "poc");
  return code;
}

bool getVersions(String& outJson) {
  String url = fry_config::getApiBase() + FRY_TEXT("/versions/" FRY_MINER_CODE "?platform=" FRY_BUILD_ENV);
  WiFiClientSecure sec;
  HTTPClient http;
  if (!fry_http::beginHttpsUrl(http, sec, url)) return false;
  addAuthHeader(http);
  int code = http.GET();
  bool ok = code > 0 && code < 300;
  if (ok) {
    outJson = http.getString();
  } else if (code >= 400 && code < 500) {
    // Terminal, same as registration — e.g. a 422 because FRY_MINER_CODE isn't in the server's
    // accepted enum yet. Not retried here; the caller's own cadence decides when to try again.
    FRY_PRINTF("api: version check rejected http=%d - server does not accept this miner code yet\n",
                  code);
  }
  http.end();
  return ok;
}

void tick() {
  if (!fry_wifi::isConnected()) return;
  unsigned long now = millis();

  fry_ota::tick();  // drives OTA_CHECK_MS cadence; composed here since only one strong
                     // definition of fry_trigger_report_loop_tick can exist (see trigger_hooks.h)

  // Gated purely by elapsed time since the LAST ATTEMPT (success or failure) — never by
  // `!s_registered` alone. Registration is one optional subsystem, not a boot gate: WiFi, the
  // VPN/relay endpoint, the health loop and OTA all keep running whether or not this succeeds.
  // A rejected (4xx) attempt waits the same hour as a normal heartbeat; an unreachable server
  // (transport, 5xx, 429) is retried after 60 s, doubling to an hour (fry::nextRegisterDelayMs).
  // Either way it is retried indefinitely — so if the server later accepts this key, the device
  // recovers on its own without a reflash — but it never tight-loops.
  bool dueForAttempt =
      (s_lastRegisterAttemptMs == 0) || (now - s_lastRegisterAttemptMs) >= s_nextRegisterDelayMs;
  if (dueForAttempt) {
    s_lastRegisterAttemptMs = now;
    if (registerInstallation()) {
      s_registered = true;
    }
  }

  // Telemetry drives its own TELEMETRY_INTERVAL_MS and yields to the OTA heap gate; composed
  // here for the same reason fry_ota::tick() is — only one strong definition of
  // fry_trigger_report_loop_tick may exist (see trigger_hooks.h).
  fry_telemetry::tick();

  if ((now - s_lastPocMs) >= POC_INTERVAL_MS) {
    s_lastPocMs = now;
    int slot = computeSlot();
    int putCode = putPoc();
    bool leaseOk = renewLease();
    FRY_PRINTF("poc: slot=%d put=%d lease=%s\n", slot, putCode, leaseOk ? "true" : "false");
  }
}

#if defined(ARDUINO_ARCH_ESP8266)
// The boot-time registration (main.cpp attemptWifiConnect() -> fry_trigger_register_now()). tick() registers whenever
// s_lastRegisterAttemptMs is 0 and nothing recorded this call, so the first tick registered AGAIN about a second later: a second ~8 KB
// TLS session low in the 40 KB heap and a second TIME_WAIT pcb (test/test_hwapi_register_once). A success is recorded the way tick()
// records its own (registerInstallation() has already set s_nextRegisterDelayMs to the heartbeat). A failure, or a call that skipped
// for want of a miner key, is not: tick() retries at once, as before.
bool registerAtBoot() {
  const unsigned long started = millis();
  if (!registerInstallation()) return false;
  s_lastRegisterAttemptMs = started ? started : 1;
  s_registered = true;
  return true;
}
#endif

}  // namespace fry_hwapi

// Strong overrides of the weak defaults in trigger_stubs.cpp (see trigger_hooks.h).
extern "C" void fry_trigger_register_now() {
#if defined(ARDUINO_ARCH_ESP8266)
  fry_hwapi::registerAtBoot();
#else
  fry_hwapi::registerInstallation();
#endif
}
extern "C" void fry_trigger_poc_now() { fry_hwapi::putPoc(); }
extern "C" void fry_trigger_report_loop_tick() { fry_hwapi::tick(); }
