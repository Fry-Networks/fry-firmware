// Built only by the Pico / BK7231N envs (platformio.boards.ini defines FRY_BOARDS_PORT); the ESP envs compile all of src/.
#if defined(FRY_BOARDS_PORT)
// src/core/http_tls.h for the Pico and BK7231N boards: fry_http::beginHttpsUrl() over the shared trust setup. Always TLS, always a
// pinned root for the host (src/boards/tls_client.h); the redirect policy is the one the header documents (follow up to 5), which a
// caller that sends credentials turns off right after.
#include "../core/http_tls.h"

#include "tls_client.h"

namespace fry_http {

bool beginHttpsUrl(HTTPClient& http, WiFiClientSecure& sec, const String& url, bool mflnProbeWorthwhile) {
  (void)mflnProbeWorthwhile;  // no MFLN probe on these cores
  if (!url.startsWith("https://")) return false;
  if (!fry_boards::prepareSecure(sec, url.c_str())) return false;
  http.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);
  http.setTimeout(15000);
  return http.begin(sec, url);
}

}  // namespace fry_http
#endif  // FRY_BOARDS_PORT
