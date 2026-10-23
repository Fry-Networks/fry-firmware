#pragma once
// Which TLS session is still open when the OTA image download opens its own.
//
// checkNow() fetches the manifest through a WiFiClientSecure that lives on its stack and then calls
// downloadAndApply(), which builds a second one - while the first is still in scope. What the first
// still holds at that moment depends on HTTPClient::end(): ESP8266HTTPClient.cpp:218 (framework
// 3.30102.0) calls _client->stop(), which frees BearSSL's context and its 16709 B + 597 B I/O
// buffers (WiFiClientSecureBearSSL.cpp:194-203), only when it was NOT asked to keep the connection
// alive for reuse. HTTPClient asks for keep-alive by default ("Connection: keep-alive",
// ESP8266HTTPClient.cpp:963), so against a server that keeps the connection (GitHub) the manifest
// session stayed open through the whole download.
//
// Pure so both the mirror of the core's rule and the OTA policy are natively tested. ESP8266 and
// host only: the ESP32 build has no such translation unit.
#if !defined(ARDUINO) || defined(ARDUINO_ARCH_ESP8266)

namespace fry {

// ESP8266HTTPClient::disconnect(): the TLS session survives http.end() iff the client asked for
// reuse and the server did not send "Connection: close" (the core's _reuse && _canReuse).
bool httpEndLeavesTlsOpen(bool reuseRequested, bool serverAllowsKeepAlive);

// Whether the OTA client lets HTTPClient keep the connection alive for reuse.
bool otaAsksForKeepAlive(bool isEsp8266, bool isHttps);

// TLS sessions open at the moment the download session opens, after a manifest fetch whose
// http.end() has run and whose WiFiClientSecure is still in scope: the download's own (1) plus the
// manifest's if end() left it open.
unsigned tlsSessionsOpenWhenDownloadOpens(bool isEsp8266, bool isHttps, bool serverAllowsKeepAlive);

}  // namespace fry

#endif  // !ARDUINO || ARDUINO_ARCH_ESP8266
