#include "../core/http_tls.h"

#include "heap_gate.h"
#include "mfln_cache.h"
#include "tls_sizing.h"
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

bool probeMfln512(const char* host, void*) {
  return WiFiClientSecure::probeMaxFragmentLength(host, 443, 512);
}

}  // namespace

bool beginHttpsUrl(HTTPClient& http, WiFiClientSecure& sec, const String& url, bool mflnProbeWorthwhile,
                   bool smallReply) {
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
  // renewal and PoC keep working on a fragmented heap. A peer that does NOT honour it (GitHub,
  // i.e. OTA) is NOT given 512/512: the 0.3.3 bench board soft-reset (Exception 4) in that
  // handshake, so fry::planTls refuses the session instead and the caller gets `false`.
  // Gating everything on the OTA-sized threshold would block those small calls too.
  //
  // One sample, no bounded wait here. This helper runs on every HTTPS call, and spinning up to
  // 3 s each time starved the loop badly enough to trip the software watchdog. The bounded
  // wait still applies where it belongs, at the OTA download gate in src/core/ota_client.cpp.
  // A caller that already knows the peer refuses MFLN (GitHub, i.e. OTA) must not pay for the
  // probe. Measured on this board: the OTA manifest fetch passed the gate, ran the probe, and
  // still returned HTTP -1, because peak demand was max(32 KB probe, 16.4 KB iobuf) rather than
  // the 16.4 KB the gate was sized for. The gate SAMPLES and does not RESERVE, so the block it
  // saw did not survive to the allocation. Skipping the probe removes the 32 KB spike entirely
  // and leaves only the buffers we actually intend to use.
  // ONE sample drives the verdict and the buffer choice (fry::planTls, tested natively), taken now
  // that `sec` exists: constructing a WiFiClientSecure allocates BearSSL's 6200 B stack thunk, so a
  // sample taken before it (checkNow's gate) overstates what is left. A short heap is no longer
  // allowed to fall through to 512/512 for a peer that does not honour MFLN - see tls_sizing.h.
  const fry::HeapSample heap{static_cast<uint32_t>(ESP.getFreeHeap()), fry::queryMaxFreeBlock()};
  const fry::TlsPlan plan =
      fry::planTls(heap, HEAP_GATE_OTA, HEAP_GATE_OTA_BLOCK, mflnProbeWorthwhile, smallReply);
  String host = extractHost(url);
  switch (plan.sizing) {
    case fry::TlsSizing::Refuse:
      // printf_P/PSTR: the string stays in flash instead of costing ~130 B of the 80 KB heap budget.
      Serial.printf_P(PSTR("tls: refusing %s - heap too short for the big buffers and the peer does "
                           "not honour MFLN (need blk>=%u free>=%u, have blk=%u free=%u)\n"),
                      host.c_str(), static_cast<unsigned>(HEAP_GATE_OTA_BLOCK),
                      static_cast<unsigned>(HEAP_GATE_OTA), static_cast<unsigned>(heap.maxBlock),
                      static_cast<unsigned>(heap.freeTotal));
      return false;
    case fry::TlsSizing::Small:
      Serial.println("tls: low contiguous heap - MFLN probe skipped, 512/512");
      sec.setBufferSizes(512, 512);
      break;
    case fry::TlsSizing::Big:
      // blk is logged because the 30 s [health] line samples far too coarsely to catch this peak,
      // and HTTP -1 collapses connect-refused, iobuf-OOM and handshake-failure into one code. This
      // is the only place the deciding quantity is visible at the deciding moment.
      Serial.printf("tls: peer does not honour MFLN - probe skipped, 16384/512 (blk=%u)\n",
                    static_cast<unsigned>(heap.maxBlock));
      sec.setBufferSizes(16384, 512);
      break;
    case fry::TlsSizing::Medium:
      // The OTA manifest: github.com honours MFLN 512, the last hop (release-assets) does not and sends one 4146 B
      // Certificate record, then a ~2 KB JSON. 8192 holds that 1.98x over for 8 KB less heap than 16384.
      Serial.printf_P(PSTR("tls: small replies expected - probe skipped, %u/%u (blk=%u)\n"),
                      static_cast<unsigned>(fry::kTlsMediumRxBytes), static_cast<unsigned>(fry::kTlsTxBytes),
                      static_cast<unsigned>(heap.maxBlock));
      sec.setBufferSizes(fry::kTlsMediumRxBytes, fry::kTlsTxBytes);
      break;
    case fry::TlsSizing::ProbeFirst: {
      // The probe is a throwaway ~32 KB session plus a TIME_WAIT pcb: ask once per host per boot, not on
      // every call (positive answers only, see lib/fry_core/mfln_cache.h).
      static fry::MflnCache mflnCache;
      if (!fry::mflnHonours(mflnCache, host.c_str(), probeMfln512, nullptr)) {
        sec.setBufferSizes(16384, 512);
      } else {
        sec.setBufferSizes(512, 512);
      }
      break;
    }
  }

  if (!http.begin(sec, url)) return false;
  http.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);
  http.setRedirectLimit(5);
  return true;
}

bool beginHttpsUrl(HTTPClient& http, WiFiClientSecure& sec, const String& url, bool mflnProbeWorthwhile) {
  return beginHttpsUrl(http, sec, url, mflnProbeWorthwhile, /*smallReply=*/false);
}

}  // namespace fry_http
