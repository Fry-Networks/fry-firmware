#pragma once
// HTTPS setup for the hardwareapi client (always TLS — PROTOCOL.md section 5's base URL is
// https://hardwareapi.frynetworks.com). T7's OTA client has its own scheme-dispatched helper
// since it must also support a plain-http lab server; this one is HTTPS-only by design.
#include <Arduino.h>

#if defined(ARDUINO_ARCH_ESP8266)
#include <ESP8266HTTPClient.h>
#include <WiFiClientSecureBearSSL.h>
using WiFiClientSecure = BearSSL::WiFiClientSecure;
#else
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#endif

namespace fry_http {

// Configures TLS + the default redirect policy (follow up to 5, HTTPC_FORCE_FOLLOW_REDIRECTS: the OTA manifest and
// image come through GitHub, a two-hop chain) and calls http.begin(sec, url). A caller that sends credentials can turn
// following off right after this returns: src/core/hardwareapi_client.cpp does that for its routes (noRedirects).
// src/core/telemetry.cpp and the ESP32 src/esp32/wg_provision_client.cpp still follow redirects for now. Returns false
// if TLS setup or begin() fails (e.g. ESP8266 heap gate).
//
// mflnProbeWorthwhile lets a caller say it already knows the peer will refuse Maximum Fragment
// Length Negotiation. On ESP8266 the probe is not free: probeMaxFragmentLength() opens its own
// throwaway session on BearSSL's DEFAULT 16384+16384 buffers (~32 KB) BEFORE any setBufferSizes()
// of ours applies, so asking a peer that will say no costs a 32 KB contiguous allocation to learn
// nothing. Leave it true for hardwareapi, which does honour MFLN and where a successful probe
// buys the cheap 512/512 path. Pass false for GitHub (the OTA manifest and image host), which
// does not. Ignored on ESP32, whose mbedtls has no equivalent probe.
bool beginHttpsUrl(HTTPClient& http, WiFiClientSecure& sec, const String& url,
                   bool mflnProbeWorthwhile = true);

#if defined(ARDUINO_ARCH_ESP8266)
// As above, for a caller that knows every TLS record of its request is small (the OTA manifest): a peer that does not
// honour MFLN then gets 8192/512 buffers instead of 16384/512 (lib/fry_core/tls_sizing.h, kTlsMediumRxBytes). The
// four-argument form is smallReply = false. ESP8266 only: the ESP32 declaration and image are unchanged.
bool beginHttpsUrl(HTTPClient& http, WiFiClientSecure& sec, const String& url, bool mflnProbeWorthwhile,
                   bool smallReply);
#endif

}  // namespace fry_http
