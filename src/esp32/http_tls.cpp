#include "../core/http_tls.h"

namespace fry_http {

// Mozilla root CA bundle, embedded via board_build.embed_files (platformio.ini [esp32common],
// inherited by esp32/esp32s3/esp32c3/esp32_lab) from data/cert/x509_crt_bundle.bin. Generated
// by data/cert/gen_crt_bundle.py — see that script's header for exactly which two chains it was
// built to verify (hardwareapi.frynetworks.com and github.com / objects.githubusercontent.com)
// and how the required root set (ISRG Root X1, ISRG Root X2, USERTrust ECC Certification
// Authority) was confirmed against the live chains with `openssl s_client`.
//
// Symbol name follows PlatformIO/GNU objcopy's binary-embed convention: the embedded file's
// project-relative path as given in board_build.embed_files, with every non-alphanumeric
// character (path separators, the dot before the extension) replaced by '_'.
extern const uint8_t x509_crt_bundle_start[] asm("_binary_data_cert_x509_crt_bundle_bin_start");

bool beginHttpsUrl(HTTPClient& http, WiFiClientSecure& sec, const String& url) {
  sec.setCACertBundle(x509_crt_bundle_start);

  if (!http.begin(sec, url)) return false;
  http.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);
  http.setRedirectLimit(5);
  return true;
}

}  // namespace fry_http
