#pragma once
// Redirect policy for the firmware download and its manifest on the ESP8266.
//
// The HTTP client would follow redirects on its own, but it keeps one TLS client and one trust anchor set for every hop. The
// hosts of a release download need different roots, and keeping both resident costs heap the download does not have, so the
// firmware follows each redirect itself: it decides here whether the next hop may be taken, then replaces the anchors and
// re-checks the heap for that hop before connecting (src/core/ota_client.cpp, src/esp8266/http_tls.cpp).
#include <cstdint>

namespace fry {

constexpr uint8_t kMaxRedirectHops = 5;

enum class RedirectDecision : uint8_t {
  NotRedirect,  // the response is final
  Follow,       // take the next hop
  TooMany,      // more hops than kMaxRedirectHops
  NoLocation,   // a redirect without a usable Location
  NotHttps,     // Location is not an absolute https URL (plain http, a relative path, another scheme)
  UnknownHost,  // the Location host has no trust anchors
};

bool isRedirectStatus(int code);

// `hopsTaken` redirects were already followed. `location` is the Location header of the response (may be null or empty).
RedirectDecision decideRedirect(int code, uint8_t hopsTaken, const char* location);

}  // namespace fry
