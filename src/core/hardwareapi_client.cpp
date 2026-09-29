#include "hardwareapi_client.h"

#include <ArduinoJson.h>

#include <cstring>
#include <ctime>

#include "config.h"
#include "fry_config.h"
#include "http_tls.h"
#include "miner_key.h"
#include "ota_client.h"
#include "provisioning_transport.h"
#include "reg_result.h"
#include "telemetry.h"
#include "trigger_hooks.h"
#include "wifi_station.h"

#include <generated/fry_secrets.h>

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

const uint32_t kQuickRetryMs = 2000;

// The server's own words for a rejection ("detail" or "error" in the JSON body), bounded and with
// every key-shaped token masked (fry::sanitizeServerDetail). Never logs the body wholesale.
void readServerDetail(HTTPClient& http, const char* minerKey, char* out, size_t outLen) {
  out[0] = 0;
  const int size = http.getSize();
  // Not a JSON error body; do not buffer it. -1 is a chunked body of unknown length: getString()
  // would buffer all of it, so it counts as too big too (round 2 F10).
  if (size < 0 || size > 2048) return;
  JsonDocument rdoc;
  if (deserializeJson(rdoc, http.getString())) return;
  const char* d = rdoc["detail"].is<const char*>() ? rdoc["detail"].as<const char*>()
                                                   : (rdoc["error"] | "");
  fry::sanitizeServerDetail(d, minerKey, out, outLen);
}

// Authorization header per PROTOCOL.md section 5: the per-device token once issued, else the
// build-time bootstrap token, omitted entirely when both are empty. Never call this before the
// installation registration response has had a chance to persist a device_token.
void addAuthHeader(HTTPClient& http) {
  String token = fry_config::getDeviceToken();
  if (token.length() == 0) token = String(FRY_API_TOKEN);
  if (token.length() > 0) http.addHeader("Authorization", "Bearer " + token);
}

int computeSlot() {
  time_t now = time(nullptr);
  struct tm t;
  gmtime_r(&now, &t);
  int minutesSinceMidnight = t.tm_hour * 60 + t.tm_min;
  return (minutesSinceMidnight / 10) % 144;
}

}  // namespace

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

bool registerInstallation() {
  char minerKey[40];
  fry_identity::ensureMinerKey(minerKey, sizeof(minerKey));
  if (minerKey[0] == 0) {
    // USER_SUPPLIED board without a key: there is nothing to register as. Not an API failure.
    if (!s_loggedNoKey) {
      s_loggedNoKey = true;
      Serial.println("api: registration skipped - no miner key yet");
    }
    fry_provisioning::notifyKeyMissing();
    return false;
  }
  char installId[40];
  fry_identity::ensureInstallId(installId, sizeof(installId));
  char deviceName[32];
  fry_identity::getDeviceName(deviceName, sizeof(deviceName));

  JsonDocument doc;
  doc["miner_key"] = minerKey;
  doc["install_id"] = installId;
  doc["minerCode"] = FRY_MINER_CODE;  // camelCase — every sibling key is snake_case (protocol)
  doc["software_version_installed"] = FRY_FIRMWARE_VERSION;
  doc["poc_version_installed"] = "1.0.0";
  doc["hostname"] = deviceName;
  doc["os"] = FRY_BUILD_ENV;
  doc["is_installed"] = true;
  doc["device_name"] = deviceName;
  String body;
  serializeJson(doc, body);

  String url = fry_config::getApiBase() + "/installations/" + minerKey + "/installations/" + installId;

  // One attempt plus one quick retry for an outage only. Anything longer is tick()'s schedule, so
  // the loop (Improv, the reset button, the relay) is never held for more than one retry.
  int code = -1;
  fry::RegClass cls = fry::RegClass::Unreachable;
  char detail[128] = {0};
  for (int attempt = 0; attempt < 2; attempt++) {
    WiFiClientSecure sec;
    HTTPClient http;
    code = -1;
    if (fry_http::beginHttpsUrl(http, sec, url)) {
      addAuthHeader(http);
      http.addHeader("Content-Type", "application/json");
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
      Serial.printf("api: registered install=%s token=%s\n", installId,
                    strlen(token) > 0 ? "present" : "none");
      if (!fry_config::getKeyOk()) fry_config::setKeyOk(true);  // the key is now confirmed
      s_regFailures = 0;
      s_nextRegisterDelayMs = INSTALL_HEARTBEAT_MS;
      fry_provisioning::notifyApiOk();
      return true;
    }
    if (!fry::regClassRetryQuickly(cls)) {
      // A 4xx is the server's answer; asking again seconds later gets the same one. This does NOT
      // touch fry_config's device token: a 4xx here is a policy rejection, not an expired
      // credential, and there is nothing to recover by clearing anything.
      readServerDetail(http, minerKey, detail, sizeof(detail));
      http.end();
      break;
    }
    http.end();
    if (attempt == 0) delay(kQuickRetryMs);
  }

  if (s_regFailures < 0xFFFFFFFFu) s_regFailures++;
  s_nextRegisterDelayMs = fry::nextRegisterDelayMs(cls, s_regFailures);
  const fry::ProvErr err = fry::regClassProvErr(cls);
  if (cls == fry::RegClass::Unreachable) {
    Serial.printf("api: registration failed install=%s http=%d detail=%u (%s) next=%lus\n", installId,
                  code, static_cast<unsigned>(err), fry::regClassText(cls),
                  s_nextRegisterDelayMs / 1000UL);
  } else {
    Serial.printf("api: register rejected http=%d detail=%u (%s) server=\"%s\" next=%lus\n", code,
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

  String url = fry_config::getApiBase() + "/installations/" + minerKey + "/leases/" + installId;
  WiFiClientSecure sec;
  HTTPClient http;
  if (!fry_http::beginHttpsUrl(http, sec, url)) return false;
  addAuthHeader(http);
  http.addHeader("Content-Type", "application/json");
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

  String url = fry_config::getApiBase() + "/PoC/" + minerKey + "/hardware";
  WiFiClientSecure sec;
  HTTPClient http;
  if (!fry_http::beginHttpsUrl(http, sec, url)) return -1;
  addAuthHeader(http);
  http.addHeader("Content-Type", "application/json");
  int code = http.PUT(body);
  http.end();
  fry_ota::noteHeartbeat(code, "poc");
  return code;
}

bool getVersions(String& outJson) {
  String url = fry_config::getApiBase() + "/versions/" FRY_MINER_CODE "?platform=" FRY_BUILD_ENV;
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
    Serial.printf("api: version check rejected http=%d - server does not accept this miner code yet\n",
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
    Serial.printf("poc: slot=%d put=%d lease=%s\n", slot, putCode, leaseOk ? "true" : "false");
  }
}

}  // namespace fry_hwapi

// Strong overrides of the weak defaults in trigger_stubs.cpp (see trigger_hooks.h).
extern "C" void fry_trigger_register_now() { fry_hwapi::registerInstallation(); }
extern "C" void fry_trigger_poc_now() { fry_hwapi::putPoc(); }
extern "C" void fry_trigger_report_loop_tick() { fry_hwapi::tick(); }
