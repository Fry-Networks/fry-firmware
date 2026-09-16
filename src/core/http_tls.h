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

// Configures TLS + redirect policy (HTTPC_FORCE_FOLLOW_REDIRECTS, limit 5) and calls
// http.begin(sec, url). Returns false if TLS setup or begin() fails (e.g. ESP8266 heap gate).
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

}  // namespace fry_http
