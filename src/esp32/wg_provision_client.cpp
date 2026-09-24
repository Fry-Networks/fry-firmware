#include "wg_provision_client.h"

#include <ArduinoJson.h>
#include <WiFi.h>
#include <esp_random.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/utils.h>

#include <cstring>

#include "../core/fry_config.h"
#include "../core/hardwareapi_client.h"
#include "../core/http_tls.h"
#include "../core/miner_key.h"
#include "config.h"
#include "heap_gate.h"
#include "wg_provision.h"

#ifndef FRY_FIRMWARE_VERSION
#define FRY_FIRMWARE_VERSION "0.0.0-dev"
#endif
#ifndef FRY_CHIP
#define FRY_CHIP "UNKNOWN"
#endif

namespace fry_wg_provision {

namespace {

unsigned long s_nextAttemptMs = 0;
uint32_t s_attemptNumber = 0;

// arduino-esp32's IPAddress packs the first octet in the LOW byte of its uint32_t conversion
// (confirmed by src/esp32/vpn_wireguard.cpp's existing `staIp.u_addr.ip4.addr =
// static_cast<uint32_t>(WiFi.localIP())` assignment into lwIP's network-byte-order field).
// lib/fry_core/wg_provision.h's IPv4 helpers use the opposite, human-reading convention (first
// octet in the HIGH byte, e.g. "10.13.13.1" -> 0x0A0D0D01) so they read the same on every
// platform this project targets. This is the one place that difference is bridged.
uint32_t arduinoIpToHostOrder(uint32_t arduinoOrder) {
  return ((arduinoOrder & 0xFFu) << 24) | ((arduinoOrder & 0xFF00u) << 8) |
        ((arduinoOrder & 0xFF0000u) >> 8) | ((arduinoOrder >> 24) & 0xFFu);
}

// Reuses the persisted keypair if both halves already exist (logging "wg: keypair reused
// pub=<8>"); otherwise generates one, persists it, and logs "wg: keypair generated pub=<8>".
// Writes the 44-char b64 public key (+ NUL) to `pubOut`. Never logs anything beyond the 8-char
// pubkey prefix - not the private key, not the rest of the public key. Returns false only if the
// point multiplication itself fails (should not happen in practice).
bool ensureKeypair(char pubOut[45]) {
  String existingPriv = fry_config::getWgPriv();
  String existingPub = fry_config::getWgPub();
  if (existingPriv.length() == 44 && existingPub.length() == 44) {
    std::strncpy(pubOut, existingPub.c_str(), 44);
    pubOut[44] = 0;
    Serial.printf("wg: keypair reused pub=%.8s\n", pubOut);
    return true;
  }

  // esp_fill_random is the ESP-IDF hardware RNG (already linked via the esp32 core - no new
  // lib_dep). crypto_scalarmult_curve25519_base clamps its input again internally (confirmed by
  // reading .pio/libdeps/esp32/libsodium's ref10 mult_base implementation), so applying our own
  // clamp first is redundant-but-harmless and means the NVS-persisted bytes are exactly what was
  // used to derive the public key — a reboot never re-derives a different keypair from stale,
  // never-clamped bytes.
  uint8_t priv[32];
  esp_fill_random(priv, sizeof(priv));
  fry::clampX25519Private(priv);

  uint8_t pub[32];
  if (crypto_scalarmult_curve25519_base(pub, priv) != 0) {
    sodium_memzero(priv, sizeof(priv));
    return false;
  }

  char privB64[45];
  char pubB64[45];
  fry::encodeWgKeyB64(priv, privB64, sizeof(privB64));
  fry::encodeWgKeyB64(pub, pubB64, sizeof(pubB64));
  sodium_memzero(priv, sizeof(priv));

  // Persisted BEFORE the POST is sent — a crash/reset between keygen and the server's response
  // never orphans it: the server's 200-idempotent-replay behavior recovers on retry.
  fry_config::setWgKeypair(privB64, pubB64);
  std::strncpy(pubOut, pubB64, 44);
  pubOut[44] = 0;
  Serial.printf("wg: keypair generated pub=%.8s\n", pubOut);
  return true;
}

}  // namespace

void tick() {
  if (fry_config::hasVpnConfig()) return;  // never re-provisions an existing config

  unsigned long now = millis();
  if (s_nextAttemptMs != 0 && now < s_nextAttemptMs) return;

  // Token: NVS fry/deviceToken ONLY. Deliberately NO fallback to a compiled bootstrap token
  // (unlike hardwareapi_client.cpp's addAuthHeader) — a board mints a WireGuard peer only once
  // it has actually registered and holds its own per-device token.
  String token = fry_config::getDeviceToken();
  bool hasToken = token.length() > 0;
  bool heapOk = fry::heapGatePass(
      ESP.getFreeHeap(), fry::queryMaxFreeBlock(), HEAP_GATE_OTA,
      fry::otaMinContiguousBlock(/*isHttps=*/true, /*bearsslSingleBuffer=*/false, HEAP_GATE_OTA_BLOCK));
  // A short, non-blocking check: if NTP already synced this returns true immediately; otherwise
  // it kicks off (or re-kicks) the sync and returns false without materially delaying tick().
  bool clockOk = fry_hwapi::ensureNtpSynced(/*timeoutMs=*/1);

  int32_t httpStatus = -1;
  uint32_t retryAfterS = 0;
  fry::WgProvisionConfig cfg;
  bool parsedOk = false;

  if (hasToken && heapOk && clockOk) {
    char pubB64[45];
    if (!ensureKeypair(pubB64)) {
      Serial.println("wg: keypair generation failed");
    } else {
      char minerKey[40];
      fry_identity::ensureMinerKey(minerKey, sizeof(minerKey));
      char body[192];
      fry::buildWgProvisionBody(pubB64, FRY_FIRMWARE_VERSION, FRY_CHIP, body, sizeof(body));

      String url = fry_config::getApiBase() + "/vpn/v1/wireguard/" + minerKey + "/peer";
      WiFiClientSecure sec;
      HTTPClient http;
      if (fry_http::beginHttpsUrl(http, sec, url)) {
        const char* retryAfterHeader[] = {"Retry-After"};
        http.collectHeaders(retryAfterHeader, 1);
        http.addHeader("Authorization", "Bearer " + token);
        http.addHeader("Content-Type", "application/json");
        httpStatus = http.POST(body);

        if (httpStatus > 0 && httpStatus < 300) {
          JsonDocument rdoc;
          DeserializationError jerr = deserializeJson(rdoc, http.getString());
          if (!jerr) {
            const char* serverPub = rdoc["server"]["public_key"] | "";
            const char* endpointHost = rdoc["server"]["endpoint_host"] | "";
            int32_t endpointPort = rdoc["server"]["endpoint_port"] | 0;
            const char* tunnelAddress = rdoc["peer"]["tunnel_address"] | "";

            JsonVariant pskVariant = rdoc["peer"]["preshared_key"];
            const char* psk = pskVariant.isNull() ? nullptr : pskVariant.as<const char*>();

            JsonVariant kaVariant = rdoc["peer"]["persistent_keepalive"];
            bool keepaliveProvided = !kaVariant.isNull();
            int32_t keepaliveValue = kaVariant | 0;

            const char* allowedPtrs[fry::kWgMaxAllowedIps];
            int allowedCount = 0;
            for (JsonVariant v : rdoc["peer"]["allowed_ips"].as<JsonArray>()) {
              if (allowedCount >= fry::kWgMaxAllowedIps) break;
              allowedPtrs[allowedCount++] = v.as<const char*>();
            }

            fry::WgProvisionRaw raw;
            raw.serverPub = serverPub;
            raw.endpointHost = endpointHost;
            raw.endpointPort = endpointPort;
            raw.tunnelAddress = tunnelAddress;
            raw.allowedIps = allowedPtrs;
            raw.allowedIpsCount = allowedCount;
            raw.psk = psk;
            raw.keepaliveProvided = keepaliveProvided;
            raw.keepaliveValue = keepaliveValue;

            cfg = fry::validateWgProvision(raw);
            parsedOk = cfg.ok;
            if (!cfg.ok) {
              Serial.printf("wg: provision response rejected reason=%s\n", cfg.rejectReason);
            }
          } else {
            Serial.println("wg: provision response - bad JSON");
          }
        } else {
          String ra = http.header("Retry-After");
          if (ra.length() > 0) retryAfterS = static_cast<uint32_t>(ra.toInt());
        }
      }
      http.end();
    }
  }

  if (parsedOk) {
    uint32_t staIp = arduinoIpToHostOrder(static_cast<uint32_t>(WiFi.localIP()));
    uint32_t staGw = arduinoIpToHostOrder(static_cast<uint32_t>(WiFi.gatewayIP()));
    uint32_t staMask = arduinoIpToHostOrder(static_cast<uint32_t>(WiFi.subnetMask()));
    int staPrefix = fry::maskToPrefix(staMask);

    const char* allowedPtrs[fry::kWgMaxAllowedIps];
    for (int i = 0; i < cfg.allowedIpsCount; i++) allowedPtrs[i] = cfg.allowedIps[i];
    fry::WgRoutePlan plan = fry::planWgRoutes(cfg.addressCidr, allowedPtrs, cfg.allowedIpsCount,
                                              staIp, staPrefix, staGw);

    String allowedCsv;
    for (int i = 0; i < plan.allowedCount; i++) {
      if (i > 0) allowedCsv += ";";
      allowedCsv += plan.allowedCidr[i];
    }

    fry_config::setWgProvisioned(cfg.serverPub, cfg.hasPsk ? cfg.psk : "", cfg.endpointHost,
                                cfg.endpointPort, cfg.addressCidr, allowedCsv.c_str(),
                                cfg.keepaliveS);
    char pub8[9] = {0};
    std::strncpy(pub8, cfg.serverPub, 8);
    Serial.printf("wg: provisioned peer=%s\n", pub8);
    s_nextAttemptMs = 0;
    s_attemptNumber = 0;
    return;
  }

  Serial.printf("wg: provision POST http=%d\n", static_cast<int>(httpStatus));
  fry::WgFetchOutcome outcome = fry::classifyWgFetch(hasToken, heapOk, clockOk, httpStatus);
  fry::WgRetrySchedule sched = fry::wgRetryDelayMs(outcome, s_attemptNumber, retryAfterS);
  if (s_attemptNumber != 0xFFFFFFFFu) s_attemptNumber++;
  s_nextAttemptMs = now + sched.delayMs;
  Serial.printf("wg: provision deferred reason=%s retry_in=%us\n", fry::wgOutcomeName(outcome),
                static_cast<unsigned>(sched.delayMs / 1000));
}

}  // namespace fry_wg_provision
