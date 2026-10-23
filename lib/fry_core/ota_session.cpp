#include "ota_session.h"

#if !defined(ARDUINO) || defined(ARDUINO_ARCH_ESP8266)

namespace fry {

bool httpEndLeavesTlsOpen(bool reuseRequested, bool serverAllowsKeepAlive) {
  return reuseRequested && serverAllowsKeepAlive;
}

// 217c2bb never touched HTTPClient's keep-alive default. On the ESP8266 an https OTA request now
// asks for "Connection: close", so http.end() closes the TLS session and BearSSL's ~21 KB are freed
// before the manifest is parsed and before the download opens its own session. ESP32 and plain
// http (no TLS buffers to free) keep the default.
bool otaAsksForKeepAlive(bool isEsp8266, bool isHttps) { return !(isEsp8266 && isHttps); }

unsigned tlsSessionsOpenWhenDownloadOpens(bool isEsp8266, bool isHttps, bool serverAllowsKeepAlive) {
  if (!isHttps) return 1;  // plain http: no TLS session of either kind (counted as the download's 1)
  const bool manifestStillOpen =
      httpEndLeavesTlsOpen(otaAsksForKeepAlive(isEsp8266, isHttps), serverAllowsKeepAlive);
  return manifestStillOpen ? 2u : 1u;
}

}  // namespace fry

#endif  // !ARDUINO || ARDUINO_ARCH_ESP8266
