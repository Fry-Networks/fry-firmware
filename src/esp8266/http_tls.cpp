#include "../core/http_tls.h"

#include "../core/heap_gate_wait.h"
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
  // DOCUMENTED LIMITATION (v0.2.0), not a bug for this run: unlike the ESP32 fix in this same
  // release (src/esp32/http_tls.cpp, sec.setCACertBundle()), this chip stays on setInsecure().
  // BearSSL trust-anchor verification (setTrustAnchors()/setX509Time()) needs its own
  // certificate-store buffer *in addition to* the 16384/512 (or 512/512 MFLN) I/O buffers this
  // function already sizes right at this chip's heap ceiling (HEAP_GATE_OTA_BLOCK above is
  // already ~46% of the ~80 KB total ESP8266 heap for the non-MFLN path alone) — there isn't
  // room left for the extra trust-anchor working set without starving the rest of the firmware
  // (WiFi/lwIP buffers, SOCKS5 relay, JSON parsing). Revisit only alongside a heap budget pass
  // (e.g. dropping the SOCKS5 relay or shrinking OTA_MANIFEST parsing) — not in scope here.
  sec.setInsecure();

  // hardwareapi may honour MFLN (letting us run a 512/512-byte TLS buffer instead of the
  // default 16 KB/16 KB); GitHub (used by T7's OTA client, which shares this same helper's
  // pattern conceptually) does not, and a 16 KB receive buffer needs both HEAP_GATE_OTA free
  // heap AND HEAP_GATE_OTA_BLOCK contiguous headroom or the handshake will OOM this chip's
  // ~50 KB heap.
  String host = extractHost(url);
  if (WiFiClientSecure::probeMaxFragmentLength(host, 443, 512)) {
    sec.setBufferSizes(512, 512);
  } else {
    // Dual gate (total free AND largest contiguous block) with a bounded wait — the 16 KB
    // buffer below needs one contiguous block, not just enough scattered free heap; see
    // HEAP_GATE_OTA_BLOCK in config.h for the field evidence.
    if (!fry::waitForHeapGate(HEAP_GATE_OTA, HEAP_GATE_OTA_BLOCK)) return false;
    sec.setBufferSizes(16384, 512);
  }

  if (!http.begin(sec, url)) return false;
  http.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);
  http.setRedirectLimit(5);
  return true;
}

}  // namespace fry_http
