#pragma once
// ESP8266: read the OTA manifest body ourselves, so it cannot be lost to the core's connection check, and say so when it does not
// arrive whole.
//
// HTTPClient::getString() reads the body through Stream::sendSize(), whose peek loop asks "is anything readable?" and only then
// "is the connection still open?" (StreamSend.cpp SendGenericPeekBuffer). BearSSL's connected() is the TCP state alone: false once the
// server's FIN is in, whatever is still queued (WiFiClientSecureBearSSL.cpp:264-274). WiFiClient::available() samples the queue and
// THEN yields (WiFiClient.cpp:246-257), so a body record and a FIN that land during that yield read as "nothing" followed by "closed":
// the loop gives up with 0 bytes, HTTPClient::returnError() stops the client (freeing the TLS session, bench P4 free +12.8 K) and
// getString() ignores the error and returns "" (ESP8266HTTPClient.cpp:749), which the caller then reports as "manifest parse failed".
//
// readManifestBody() samples connected() BEFORE available(): the FIN follows the data, so a close seen first can no longer hide data
// that is already queued, and a close with nothing queued afterwards really is the end. Anything short of the announced length is a
// distinct result (and a distinct log line), never an empty String.
//
// Pure and header-only (Conn and Sink are templates) so the host suite drives it with a simulated connection; ota_client.cpp adapts
// WiFiClient and String to it on ESP8266 only.
#include <cstddef>
#include <cstdint>

namespace fry {

// A release manifest is ~1 KB (992 B at 0.4.9). The body is buffered in a String on a heap that has ~14 KB free at that point.
constexpr size_t kManifestMaxBytes = 4096;
constexpr uint32_t kManifestReadTimeoutMs = 5000;  // no byte for this long: HTTPClient's own default TCP timeout
constexpr size_t kManifestReadChunk = 128;         // the stack buffer of one read

enum class ManifestRead : uint8_t {
  Ok,
  Closed,    // the connection ended before the announced length arrived
  TimedOut,  // it stayed open and went silent
  NoRoom,    // the body does not fit in memory
  TooBig,    // announced larger than kManifestMaxBytes
};

inline const char* manifestReadName(ManifestRead r) {
  switch (r) {
    case ManifestRead::Ok: return "ok";
    case ManifestRead::Closed: return "closed";
    case ManifestRead::TimedOut: return "timed out";
    case ManifestRead::NoRoom: return "no memory";
    case ManifestRead::TooBig: return "too big";
  }
  return "?";
}

// Worth asking again soon (lib/fry_core/ota_retry.h): the network or the heap let this one down. A manifest over the cap will not shrink.
inline bool manifestReadRetrySoon(ManifestRead r) {
  return r == ManifestRead::Closed || r == ManifestRead::TimedOut || r == ManifestRead::NoRoom;
}

enum class ManifestSize : uint8_t {
  Sized,    // Content-Length in 1..kManifestMaxBytes: read exactly that many bytes
  Unsized,  // none (HTTPClient::getSize() <= 0: chunked, or 0): HTTPClient's own bounded stream copy decides
  TooBig,
};

inline ManifestSize classifyManifestSize(int httpSize) {
  if (httpSize <= 0) return ManifestSize::Unsized;
  if (static_cast<size_t>(httpSize) > kManifestMaxBytes) return ManifestSize::TooBig;
  return ManifestSize::Sized;
}

// Reads exactly `expected` bytes into `out`.
//   Conn: bool connected(); int available(); int read(uint8_t*, size_t); uint32_t nowMs(); void idle();
//   Sink: bool append(const uint8_t*, size_t)   (false: no room)
// The timeout counts from the last byte that arrived, not from the start.
template <class Conn, class Sink>
inline ManifestRead readManifestBody(Conn& c, size_t expected, uint32_t timeoutMs, Sink& out) {
  uint8_t buf[kManifestReadChunk];
  size_t got = 0;
  uint32_t last = c.nowMs();
  while (got < expected) {
    const bool open = c.connected();  // first: the FIN comes after the data, so this order cannot lose a queued body
    const int avail = c.available();
    if (avail > 0) {
      size_t want = static_cast<size_t>(avail);
      if (want > sizeof(buf)) want = sizeof(buf);
      if (want > expected - got) want = expected - got;
      const int r = c.read(buf, want);
      if (r > 0) {
        if (!out.append(buf, static_cast<size_t>(r))) return ManifestRead::NoRoom;
        got += static_cast<size_t>(r);
        last = c.nowMs();
        continue;
      }
    } else if (!open) {
      return ManifestRead::Closed;
    }
    if (c.nowMs() - last >= timeoutMs) return ManifestRead::TimedOut;
    c.idle();
  }
  return ManifestRead::Ok;
}

}  // namespace fry
