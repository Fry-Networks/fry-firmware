#include "../core/http_tls.h"

#include "config.h"

namespace fry_http {

namespace {

// Extracts "host" from "scheme://host[:port]/path...". No port/userinfo support needed —
// every URL this firmware calls is a plain https://host/path.
String extractHost(const String& url) {
  int start = url.indexOf("://");
  start = (start < 0) ? 0 : start + 3;
  int end = url.indexOf('/', start);
  if (end < 0) end = url.length();
  return url.substring(start, end);
}

}  // namespace

bool beginHttpsUrl(HTTPClient& http, WiFiClientSecure& sec, const String& url) {
  // TODO(v0.2+): replace setInsecure() with a pinned/CA-validated BearSSL trust anchor.
  sec.setInsecure();

  // hardwareapi may honour MFLN (letting us run a 512/512-byte TLS buffer instead of the
  // default 16 KB/16 KB); GitHub (used by T7's OTA client, which shares this same helper's
  // pattern conceptually) does not, and a 16 KB receive buffer needs HEAP_GATE_OTA free heap
  // headroom or the handshake will OOM this chip's ~50 KB heap.
  String host = extractHost(url);
  if (WiFiClientSecure::probeMaxFragmentLength(host, 443, 512)) {
    sec.setBufferSizes(512, 512);
  } else {
    if (ESP.getFreeHeap() < HEAP_GATE_OTA) return false;
    sec.setBufferSizes(16384, 512);
  }

  if (!http.begin(sec, url)) return false;
  http.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);
  http.setRedirectLimit(5);
  return true;
}

}  // namespace fry_http
