#pragma once
// TLS trust setup shared by the Pico (BearSSL) and BK7231N (mbedtls) HTTPS clients. The host -> trust set rule and the clock gate are
// lib/fry_core/tls_trust.h's, the same as the ESP8266's: a host without a trust set is refused (fail closed), there is no insecure
// fallback, and no session starts before the clock says the certificate's validity window can be judged.
#include <Arduino.h>
#include <WiFiClientSecure.h>

#include "tls_trust.h"

namespace fry_boards {

// Per platform (src/rp2040/tls_trust_pico.cpp, src/bk7231n/tls_trust_bk.cpp): installs the root of `set` on `sec`.
bool applyTrust(WiFiClientSecure& sec, fry::TrustSet set);

// Host of "scheme://host[:port]/path" into out ("" when it does not fit).
bool hostOfUrl(const char* url, char* out, size_t cap);

// True when the clock is plausible, starting SNTP (and waiting a bounded time for it) when it is not. False = refuse the session.
bool ensureClock();

// hostOfUrl + trustSetForHost + ensureClock + applyTrust. false = refused (logged).
bool prepareSecure(WiFiClientSecure& sec, const char* url);

}  // namespace fry_boards
