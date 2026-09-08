#include "hardwareapi_client.h"

#include <ArduinoJson.h>

#include <cstring>
#include <ctime>

#include "config.h"
#include "fry_config.h"
#include "http_tls.h"
#include "miner_key.h"
#include "ota_client.h"
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

unsigned long s_lastHeartbeatMs = 0;
unsigned long s_lastPocMs = 0;
bool s_registered = false;
bool s_ntpSynced = false;

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
  const uint32_t backoffMs[3] = {2000, 4000, 8000};

  for (int attempt = 0; attempt <= 3; attempt++) {
    WiFiClientSecure sec;
    HTTPClient http;
    int code = -1;
    if (fry_http::beginHttpsUrl(http, sec, url)) {
      addAuthHeader(http);
      http.addHeader("Content-Type", "application/json");
      code = http.POST(body);
    }

    if (code > 0 && code < 300) {
      JsonDocument rdoc;
      deserializeJson(rdoc, http.getString());
      const char* token = rdoc["device_token"] | "";
      if (strlen(token) > 0) fry_config::setDeviceToken(token);
      http.end();
      Serial.printf("api: registered install=%s token=%s\n", installId,
                    strlen(token) > 0 ? "present" : "none");
      fry_ota::confirmGood();  // registration succeeding is this firmware's "proved itself good"
      return true;
    }
    http.end();

    if (code >= 400 && code < 500) return false;  // never retry on 4xx
    if (attempt < 3) delay(backoffMs[attempt]);    // transport error or 5xx — retry
  }

  Serial.printf("api: registration failed install=%s\n", installId);
  return false;
}

bool renewLease() {
  char minerKey[40];
  fry_identity::ensureMinerKey(minerKey, sizeof(minerKey));
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
  return code > 0 && code < 300;
}

int putPoc() {
  if (!ensureNtpSynced()) return -1;  // NTP before the first PoC, per PROTOCOL.md section 5

  char minerKey[40];
  fry_identity::ensureMinerKey(minerKey, sizeof(minerKey));

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
  if (ok) outJson = http.getString();
  http.end();
  return ok;
}

void tick() {
  if (!fry_wifi::isConnected()) return;
  unsigned long now = millis();

  fry_ota::tick();  // drives OTA_CHECK_MS cadence; composed here since only one strong
                     // definition of fry_trigger_report_loop_tick can exist (see trigger_hooks.h)

  if (!s_registered || (now - s_lastHeartbeatMs) >= INSTALL_HEARTBEAT_MS) {
    if (registerInstallation()) {
      s_registered = true;
      s_lastHeartbeatMs = now;
    }
  }

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
