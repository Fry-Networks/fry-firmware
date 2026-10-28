#include "telemetry.h"

#include <Arduino.h>
#include <string.h>
#include <time.h>

// http_tls.h is the per-chip TLS dispatch: it pulls ESP8266HTTPClient.h +
// WiFiClientSecureBearSSL.h on the 8266 and HTTPClient.h + WiFiClientSecure.h on the ESP32
// family. Including the ESP32 spellings directly here is a hard build break on ESP8266 --
// HTTPClient.h does not exist in that core at all.
#include "config.h"
#include "flash_print.h"
#include "fry_config.h"
#include "hardwareapi_client.h"
#include "heap_gate.h"
#include "heap_gate_wait.h"
#include "http_tls.h"
#include "miner_key.h"
#include "telemetry_body.h"
#include "wifi_station.h"

#include <generated/fry_secrets.h>

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
bool s_loggedSkipNoAuth = false;
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
#if defined(ARDUINO_ARCH_ESP8266)
  // Same text as the strftime below. strftime is the only caller that links newlib's time-locale tables and name strings (~480 B of DRAM)
  // into the ESP8266 image; the heap is whatever static RAM leaves.
  const int r = snprintf_P(out, outLen, PSTR("%04d-%02d-%02dT%02d:%02d:%02dZ"), t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour,
                           t.tm_min, t.tm_sec);
  return r > 0 && static_cast<size_t>(r) < outLen;  // strftime's contract: false when the text did not fit
#else
// keeps the ESP32/C3 line table (and so the app-descriptor ELF hash) identical to 0.4.15; drop on the next intentional ESP32/C3 change
#line 62
  return strftime(out, outLen, "%Y-%m-%dT%H:%M:%SZ", &t) > 0;
#endif
// keeps the ESP32/C3 line table (and so the app-descriptor ELF hash) identical to 0.4.15; drop on the next intentional ESP32/C3 change
#line 63
}

}  // namespace

void tick() {
  if (!fry_wifi::isConnected()) return;

  unsigned long now = millis();
  if (s_lastMs != 0 && (now - s_lastMs) < TELEMETRY_INTERVAL_MS) return;
  s_lastMs = now;

  // The device token is NOT the credential for this endpoint -- it is the readiness signal.
  // /measurements authenticates with the SHARED bearer (verify_bearer_token_general on ZEUS00,
  // mirrored in legacy-telemetry.ts: `token !== expected` -> 401), so a per-device token can
  // never satisfy it. Measured on hardware: sending the device token earns a flat
  // "post failed http=401" every interval. What the device token DOES tell us is that
  // registration has completed, so the server has a row this sample can be attributed to --
  // posting before that is accepted but never persisted ("unknown_install").
  if (fry_config::getDeviceToken().length() == 0) {
    if (!s_loggedSkipNoToken) {
      FRY_PRINTLN("telemetry: not registered yet - skipping until registration succeeds");
      s_loggedSkipNoToken = true;
    }
    return;
  }
  s_loggedSkipNoToken = false;

  String auth = String(FRY_API_TOKEN);
  if (auth.length() == 0) {
    if (!s_loggedSkipNoAuth) {
      FRY_PRINTLN("telemetry: no FRY_API_TOKEN compiled in - skipping (a POST would only earn a 401)");
      s_loggedSkipNoAuth = true;
    }
    return;
  }
  s_loggedSkipNoAuth = false;

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
      FRY_PRINTLN("telemetry: install id or miner key is empty - skipping");
      s_loggedSkipIdentity = true;
    }
    return;
  }
  s_loggedSkipIdentity = false;

  // The path parameter is the miner key. The server's fallback device lookup resolves that
  // hexId against minerKey/canonicalId, so sending the key (not the install id) is what makes
  // an unresolvable install still attributable.
  String url = fry_config::getApiBase() + FRY_TEXT("/measurements/") + minerKey;

  // TOTAL-FREE gate only. One attempt, no blocking wait: a bounded wait inside the loop has
  // previously starved it badly enough to trip the software watchdog.
  //
  // Deliberately NO contiguous-block requirement. Telemetry is a ~250-byte POST to hardwareapi,
  // which honours MFLN, so beginHttpsUrl() sizes BearSSL at 512/512 whenever the big path is
  // unaffordable -- the same path registration, lease renewal and PoC take, none of which gate
  // on heap at all. src/esp8266/http_tls.cpp states the rule outright: "Gating everything on the
  // OTA-sized threshold would block those small calls too."
  //
  // Both ways of getting this wrong were measured on hardware:
  //   * HEAP_GATE_OTA_BLOCK (36864) unconditionally -> heap_gate.h's documented ESP32 bug, where
  //     a T-Beam idling at 110,580 B contiguous still failed mid-session;
  //   * the same threshold via otaMinContiguousBlock() -> correct on ESP32, but on COM11
  //     (ESP8266, blk=32520 with the VPN up) it refused every cycle while that very board had
  //     just completed an HTTPS registration on the 512/512 path in the same second.
  // Sizing the TLS buffers is beginHttpsUrl()'s job, not this gate's. What remains here is the
  // one thing that is genuinely telemetry's business: do not run at all on a chip that is nearly
  // out of heap.
  //
  // Sample once and log THESE numbers: re-reading the heap to build the message prints values
  // the gate never saw, which makes a diagnostic line that cannot be trusted.
  const uint32_t freeNow = static_cast<uint32_t>(ESP.getFreeHeap());
  const uint32_t blkNow = static_cast<uint32_t>(fry::queryMaxFreeBlock());
  if (!fry::waitForHeapGate(HEAP_GATE_OTA, 0, 1)) {
    if (!s_loggedSkipHeap) {
      FRY_PRINTF("telemetry: heap gate not met - need free>=%u, have free=%u blk=%u\n",
                    static_cast<unsigned>(HEAP_GATE_OTA),
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
      FRY_PRINTLN("telemetry: clock not NTP-synced - skipping (a 1970 timestamp would mis-date the sample)");
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
    FRY_PRINTLN("telemetry: body build failed - skipping");
    return;
  }

  WiFiClientSecure sec;
  HTTPClient http;
  int code = -1;
  if (fry_http::beginHttpsUrl(http, sec, url)) {
    http.addHeader(FRY_TEXT("Authorization"), "Bearer " + auth);
    http.addHeader(FRY_TEXT("Content-Type"), FRY_TEXT("application/json"));
    code = http.POST(body);
  }
  http.end();

  if (code > 0 && code < 300) {
    FRY_PRINTF("telemetry: posted http=%d heap=%u blk=%u rssi=%d\n", code,
                  static_cast<unsigned>(sample.heapFree),
                  static_cast<unsigned>(sample.heapMaxBlock), static_cast<int>(sample.rssi));
    s_loggedFailure = false;
    return;
  }

  // Log once per failure run, never per cycle: a server-side outage must not turn into a serial
  // flood, and there is no retry here — the next interval is the retry.
  if (!s_loggedFailure) {
    FRY_PRINTF("telemetry: post failed http=%d (will retry at the next interval)\n", code);
    s_loggedFailure = true;
  }
}

}  // namespace fry_telemetry
