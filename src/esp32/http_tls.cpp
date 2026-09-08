#include "../core/http_tls.h"

namespace fry_http {

bool beginHttpsUrl(HTTPClient& http, WiFiClientSecure& sec, const String& url) {
  // TODO(v0.2+): replace setInsecure() with sec.setCACertBundle(x509_crt_bundle) generated via
  // the framework's tools/gen_crt_bundle.py + board_build.embed_files. Deferred for v0.1.0: the
  // bundle-generation step needs a vendored Mozilla root store and IDF component tooling not
  // trivially available in a plain Arduino-framework PlatformIO build; setInsecure() is the
  // documented v0.1.0 fallback (see T5 scope note in the firmware build brief).
  sec.setInsecure();

  if (!http.begin(sec, url)) return false;
  http.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);
  http.setRedirectLimit(5);
  return true;
}

}  // namespace fry_http
