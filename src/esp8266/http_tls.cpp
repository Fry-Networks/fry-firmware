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
  // Buffer sizing has to account for the MFLN probe itself, not just the buffers we go on to
  // request. probeMaxFragmentLength() opens its own throwaway TLS session with BearSSL still
  // on its DEFAULT 16384+16384 buffers — about 32 KB of contiguous allocation — before any
  // sizing of ours takes effect. Measured on COM11 at heap=42464 blk=34200 the probe alone
  // crashed the chip (Exception (4), rst cause:4, wdt reset).
  //
  // So: only probe when there is genuinely room for the big path. When there is not, skip the
  // probe and take the cheap 512/512 buffers. hardwareapi honours MFLN, so registration, lease
  // renewal and PoC keep working on a fragmented heap; a peer that does NOT honour it (GitHub,
  // i.e. OTA) then fails the handshake and returns an error instead of killing the chip.
  // Gating everything on the OTA-sized threshold would block those small calls too.
  //
  // attempts=1: no bounded wait here. This helper runs on every HTTPS call, and spinning up to
  // 3 s each time starved the loop badly enough to trip the software watchdog. The bounded
  // wait still applies where it belongs, at the OTA download gate in src/core/ota_client.cpp.
  const bool canAffordBigTls = fry::waitForHeapGate(HEAP_GATE_OTA, HEAP_GATE_OTA_BLOCK, 1);
  String host = extractHost(url);
  if (canAffordBigTls && !WiFiClientSecure::probeMaxFragmentLength(host, 443, 512)) {
    sec.setBufferSizes(16384, 512);
  } else {
    if (!canAffordBigTls) Serial.println("tls: low contiguous heap - MFLN probe skipped, 512/512");
    sec.setBufferSizes(512, 512);
  }

  if (!http.begin(sec, url)) return false;
  http.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);
  http.setRedirectLimit(5);
  return true;
}

}  // namespace fry_http
