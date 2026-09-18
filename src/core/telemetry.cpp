#include "telemetry.h"

#include <Arduino.h>
#include <string.h>
#include <time.h>

// http_tls.h is the per-chip TLS dispatch: it pulls ESP8266HTTPClient.h +
// WiFiClientSecureBearSSL.h on the 8266 and HTTPClient.h + WiFiClientSecure.h on the ESP32
// family. Including the ESP32 spellings directly here is a hard build break on ESP8266 --
// HTTPClient.h does not exist in that core at all.
#include "config.h"
#include "fry_config.h"
#include "hardwareapi_client.h"
#include "heap_gate.h"
#include "heap_gate_wait.h"
#include "http_tls.h"
#include "miner_key.h"
#include "telemetry_body.h"
#include "wifi_station.h"

#ifndef FRY_MINER_CODE
#define FRY_MINER_CODE "IOTVPN"
#endif
#ifndef FRY_CHIP
#define FRY_CHIP "UNKNOWN"
#endif
#ifndef FRY_FIRMWARE_VERSION
#define FRY_FIRMWARE_VERSION "0.0.0"
#endif

namespace fry_telemetry {
namespace {

unsigned long s_lastMs = 0;
bool s_loggedSkipNoToken = false;
bool s_loggedSkipHeap = false;
bool s_loggedSkipClock = false;
bool s_loggedSkipIdentity = false;
bool s_loggedFailure = false;

uint32_t stackHighWater() {
#if defined(ESP32) || defined(FRY_BOARD_ESP32) || defined(FRY_BOARD_ESP32S3) || \
    defined(FRY_BOARD_ESP32C3)
  return static_cast<uint32_t>(uxTaskGetStackHighWaterMark(nullptr));
#else
  // ESP8266 has no per-task stack accounting; report 0 rather than a misleading number.
  return 0;
#endif
}

// RFC3339 UTC. Returns false when the clock has not been set, in which case the server would
// receive an epoch-1970 timestamp and silently mis-date the sample.
bool nowIso8601(char* out, size_t outLen) {
  time_t now = time(nullptr);
  if (now < 1600000000) return false;  // clearly pre-NTP
  struct tm t;
  gmtime_r(&now, &t);
  return strftime(out, outLen, "%Y-%m-%dT%H:%M:%SZ", &t) > 0;
}

}  // namespace

void tick() {
  if (!fry_wifi::isConnected()) return;

  unsigned long now = millis();
  if (s_lastMs != 0 && (now - s_lastMs) < TELEMETRY_INTERVAL_MS) return;
  s_lastMs = now;

  String token = fry_config::getDeviceToken();
  if (token.length() == 0) {
    if (!s_loggedSkipNoToken) {
      Serial.println("telemetry: no device token yet - skipping until registration succeeds");
      s_loggedSkipNoToken = true;
    }
    return;
  }
  s_loggedSkipNoToken = false;

  // Identity before the heap gate: both are NVS reads, and an empty one must abort before any
  // allocation. ensureInstallId/ensureMinerKey are void, so the only failure signal is the
  // buffer staying empty -- and isJsonSafeToken("") is true, so an unchecked empty id would be
  // emitted as "install_id":"" and POSTed to a URL with an empty path segment.
  char installId[40] = {0};
  fry_identity::ensureInstallId(installId, sizeof(installId));
  char minerKey[40] = {0};
  fry_identity::ensureMinerKey(minerKey, sizeof(minerKey));
  if (strlen(installId) == 0 || strlen(minerKey) == 0) {
    if (!s_loggedSkipIdentity) {
      Serial.println("telemetry: install id or miner key is empty - skipping");
      s_loggedSkipIdentity = true;
    }
    return;
  }
  s_loggedSkipIdentity = false;

  // The path parameter is the miner key. The server's fallback device lookup resolves that
  // hexId against minerKey/canonicalId, so sending the key (not the install id) is what makes
  // an unresolvable install still attributable.
  String url = fry_config::getApiBase() + "/measurements/" + minerKey;

  // Yield to OTA. One attempt, no blocking wait: a bounded wait inside the loop has previously
  // starved it badly enough to trip the software watchdog.
  //
  // The CONTIGUOUS-block half of the gate is BearSSL-only, exactly as in ota_client.cpp. Asking
  // every chip for HEAP_GATE_OTA_BLOCK (36864) re-imports the bug heap_gate.h documents: a
  // T-Beam idling at 110,580 B contiguous still failed it mid-session, so no ESP32 board could
  // ever pass. On ESP32/C3 that would have made telemetry silently never post -- and because the
  // skip below is one-shot-latched, the serial log would have said so exactly once and then gone
  // quiet forever.
  const bool isHttps = url.startsWith("https://");
#if defined(ARDUINO_ARCH_ESP8266)
  constexpr bool kBearsslSingleBuffer = true;
#else
  constexpr bool kBearsslSingleBuffer = false;  // ESP32 family uses mbedtls
#endif
  const uint32_t minBlock =
      fry::otaMinContiguousBlock(isHttps, kBearsslSingleBuffer, HEAP_GATE_OTA_BLOCK);
  // Sample once and log THESE numbers: re-reading the heap to build the message prints values
  // the gate never saw, which makes a diagnostic line that cannot be trusted.
  const uint32_t freeNow = static_cast<uint32_t>(ESP.getFreeHeap());
  const uint32_t blkNow = static_cast<uint32_t>(fry::queryMaxFreeBlock());
  if (!fry::waitForHeapGate(HEAP_GATE_OTA, minBlock, 1)) {
    if (!s_loggedSkipHeap) {
      Serial.printf("telemetry: heap gate not met - need free>=%u blk>=%u, have free=%u blk=%u\n",
                    static_cast<unsigned>(HEAP_GATE_OTA), static_cast<unsigned>(minBlock),
                    static_cast<unsigned>(freeNow), static_cast<unsigned>(blkNow));
      s_loggedSkipHeap = true;
    }
    return;
  }
  s_loggedSkipHeap = false;

  // NTP before the first timestamp. Nothing else on this path syncs the clock: the only other
  // caller is putPoc(), which runs AFTER tick() in hardwareapi_client and whose first fire is a
  // full POC_INTERVAL_MS away -- so without this the first successful sample landed ~20 minutes
  // after boot instead of ~10.
  char ts[32] = {0};
  if (!fry_hwapi::ensureNtpSynced() || !nowIso8601(ts, sizeof(ts))) {
    if (!s_loggedSkipClock) {
      Serial.println("telemetry: clock not NTP-synced - skipping (a 1970 timestamp would mis-date the sample)");
      s_loggedSkipClock = true;
    }
    return;
  }
  s_loggedSkipClock = false;

  fry::TelemetrySample sample;
  sample.uptimeS = static_cast<uint32_t>(now / 1000);
  sample.heapFree = static_cast<uint32_t>(ESP.getFreeHeap());
  sample.heapMaxBlock = static_cast<uint32_t>(fry::queryMaxFreeBlock());
  sample.stackHighWater = stackHighWater();
  sample.rssi = fry_wifi::rssi();
  sample.chip = FRY_CHIP;
  sample.firmware = FRY_FIRMWARE_VERSION;

  char body[384];
  // Qualified: ordinary lookup cannot reach fry::buildTelemetryBody from inside
  // fry_telemetry, so an unqualified call compiles only by ADL on the fry::TelemetrySample
  // argument -- it would break the moment the first parameter changed type.
  if (fry::buildTelemetryBody(sample, FRY_MINER_CODE, installId, ts, body, sizeof(body)) == 0) {
    Serial.println("telemetry: body build failed - skipping");
    return;
  }

  WiFiClientSecure sec;
  HTTPClient http;
  int code = -1;
  if (fry_http::beginHttpsUrl(http, sec, url)) {
    http.addHeader("Authorization", "Bearer " + token);
    http.addHeader("Content-Type", "application/json");
    code = http.POST(body);
  }
  http.end();

  if (code > 0 && code < 300) {
    Serial.printf("telemetry: posted http=%d heap=%u blk=%u rssi=%d\n", code,
                  static_cast<unsigned>(sample.heapFree),
                  static_cast<unsigned>(sample.heapMaxBlock), static_cast<int>(sample.rssi));
    s_loggedFailure = false;
    return;
  }

  // Log once per failure run, never per cycle: a server-side outage must not turn into a serial
  // flood, and there is no retry here — the next interval is the retry.
  if (!s_loggedFailure) {
    Serial.printf("telemetry: post failed http=%d (will retry at the next interval)\n", code);
    s_loggedFailure = true;
  }
}

}  // namespace fry_telemetry
