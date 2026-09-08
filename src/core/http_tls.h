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
bool beginHttpsUrl(HTTPClient& http, WiFiClientSecure& sec, const String& url);

}  // namespace fry_http
