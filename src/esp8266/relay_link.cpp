// ESP8266 relay link - see relay_link.h and lib/fry_core/relay_proto.h.
//
// Heap: everything the link needs - the BearSSL client (and with it the core's ~6 KB BearSSL
// stack thunk, reference-counted per client), the upstream WiFiClient, the SOCKS session and
// the frame buffers - lives in one Link object that exists ONLY while the link is being opened
// or is up. It is deleted on every drop, on pause() and so before every OTA check, which leaves
// the heap exactly as a 0.3.3 board has it for the 36 KB GitHub path (include/config.h
// HEAP_GATE_OTA_BLOCK). ESP8266 has no rollback: a 0.3.4 that could no longer pass its own OTA
// gate could only ever be updated over serial (IV5 T2 F1).
//
// TLS runs on 512/512 buffers (hardwareapi's edge honours MFLN 512 - proven with openssl
// -maxfraglen 512 in IV5 evidence/t9). Every buffer is fixed size; a frame that would not fit
// closes the link instead of growing anything.
#include "relay_link.h"

#include <ESP8266WiFi.h>
#include <WiFiClientSecureBearSSL.h>

#include <cstring>
#include <new>

#include "../core/fry_config.h"
#include "../core/miner_key.h"
#include "../core/wifi_station.h"
#include "dest_ctx.h"
#include "heap_gate.h"
#include "reconnect_backoff.h"
#include "relay_proto.h"
#include "ws_frame.h"

#ifndef FRY_FIRMWARE_VERSION
#define FRY_FIRMWARE_VERSION "0.0.0-dev"
#endif
#ifndef FRY_BUILD_ENV
#define FRY_BUILD_ENV "unknown"
#endif
#ifndef FRY_OTA_BOARD_ID
#define FRY_OTA_BOARD_ID "unknown"
#endif
#ifndef FRY_RELAY_PATH
#define FRY_RELAY_PATH "/relay/v1/ws/"
#endif

namespace fry_relay {

namespace {

// Only try to open the link with this much headroom; the TLS handshake peaks well above the
// steady-state session size.
constexpr uint32_t kMinFreeHeap = 24000;
constexpr uint32_t kMinBlock = 12000;
constexpr unsigned long kDeadAfterMs = 90000;  // hwapi (uvicorn) pings every 20 s
constexpr unsigned long kIoTimeoutMs = 5000;
constexpr unsigned long kUpgradeTimeoutMs = 10000;  // whole upgrade response, all header lines
constexpr unsigned long kNoTokenRecheckMs = 60000;

enum class LinkState : uint8_t { Off, Waiting, Up, Paused };

struct Link {
  BearSSL::WiFiClientSecure tls;
  WiFiClient upstream;
  fry::RelaySocksSession session;
  uint8_t rx[4 + fry::kWsMaxPayload];
  size_t rxLen = 0;
  uint8_t tx[fry::kWsMaxClientHeader + fry::kWsMaxPayload];
  uint8_t payload[fry::kWsMaxPayload];
};

LinkState s_state = LinkState::Off;
LinkState s_pausedFrom = LinkState::Off;
Link* s_link = nullptr;
fry::ReconnectBackoff s_backoff;
unsigned long s_nextAttemptMs = 0;
unsigned long s_upSinceMs = 0;
unsigned long s_lastRxMs = 0;
// A failed write or a protocol error inside one tick only records why; tick() tears the link
// down once, at its end, so no code path ever touches a Link that was deleted under it.
const char* s_dropWhy = nullptr;

void logHeap(const char* what) {
  Serial.printf_P(PSTR("relay: heap %s free=%u blk=%u\n"), what, static_cast<unsigned>(ESP.getFreeHeap()),
                static_cast<unsigned>(fry::queryMaxFreeBlock()));
}

void freeLink() {
  if (!s_link) return;
  if (s_link->upstream) s_link->upstream.stop();
  s_link->tls.stop();
  delete s_link;
  s_link = nullptr;
}

void scheduleRetry(fry::ReconnectBackoff::Failure kind) {
  uint32_t delayMs = s_backoff.onFailure(kind, ESP.random());
  s_nextAttemptMs = millis() + delayMs;
  s_state = LinkState::Waiting;
  Serial.printf_P(PSTR("relay: next link attempt in %lus\n"), static_cast<unsigned long>(delayMs / 1000));
}

void requestDrop(const char* why) {
  if (!s_dropWhy) s_dropWhy = why;
}

bool sendFrame(uint8_t opcode, const uint8_t* payload, size_t len) {
  if (s_dropWhy || !s_link) return false;
  uint8_t mask[4];
  uint32_t r = ESP.random();
  memcpy(mask, &r, 4);
  size_t n = fry::wsEncodeClientFrame(opcode, payload, len, mask, s_link->tx, sizeof(s_link->tx));
  if (n == 0 || s_link->tls.write(s_link->tx, n) != n) {
    requestDrop("write failed");
    return false;
  }
  return true;
}

bool sendRelay(uint8_t type, const uint8_t* data, size_t len) {
  if (len + 1 > sizeof(s_link->payload)) {
    requestDrop("oversize message");
    return false;
  }
  s_link->payload[0] = type;
  if (len) memmove(s_link->payload + 1, data, len);
  return sendFrame(fry::kWsBinary, s_link->payload, len + 1);
}

void endStream() {
  if (s_link->upstream) s_link->upstream.stop();
  s_link->session.reset();
}

// Tears the link down and frees every byte of it.
void dropLink(const char* why, bool retry) {
  const unsigned long up = millis() - s_upSinceMs;
  freeLink();
  s_dropWhy = nullptr;
  Serial.printf_P(PSTR("relay: link down (%s) after %lus\n"), why, up / 1000);
  logHeap("after link freed");
  s_backoff.onLinkDown(static_cast<uint32_t>(up));
  if (retry) scheduleRetry(fry::ReconnectBackoff::Failure::Transport);
}

void failOpen(const char* what, fry::ReconnectBackoff::Failure kind) {
  Serial.printf_P(PSTR("relay: %s\n"), what);
  freeLink();
  scheduleRetry(kind);
}

void openLink() {
  // hwapi accepts only the per-device token registration issues (proof of possession); the
  // shared bootstrap token is always refused. Until registration has stored one, wait for it
  // without spending the server's 12 connects/h on a guaranteed 403.
  String token = fry_config::getDeviceToken();
  if (token.length() == 0) {
    Serial.println(F("relay: no device token yet - link waits for registration"));
    s_nextAttemptMs = millis() + kNoTokenRecheckMs;
    s_state = LinkState::Waiting;
    return;
  }

  const uint32_t freeHeap = ESP.getFreeHeap();
  const uint32_t block = fry::queryMaxFreeBlock();
  if (freeHeap < kMinFreeHeap || block < kMinBlock) {
    Serial.printf_P(PSTR("relay: heap low (free=%u blk=%u) - link deferred\n"),
                  static_cast<unsigned>(freeHeap), static_cast<unsigned>(block));
    scheduleRetry(fry::ReconnectBackoff::Failure::Transport);
    return;
  }
  logHeap("before link");

  s_link = new (std::nothrow) Link();
  if (!s_link) {
    failOpen("link allocation failed", fry::ReconnectBackoff::Failure::Transport);
    return;
  }

  String base = fry_config::getApiBase();
  int hostStart = base.indexOf("://");
  hostStart = hostStart < 0 ? 0 : hostStart + 3;
  int hostEnd = base.indexOf('/', hostStart);
  String host = base.substring(hostStart, hostEnd < 0 ? base.length() : hostEnd);
  // The shipped base has no port (443). A bench build pointing HARDWAREAPI_BASE at a LAN relay
  // rig carries one ("https://<lan-ip>:8443").
  uint16_t port = 443;
  const int colon = host.indexOf(':');
  if (colon >= 0) {
    const long p = host.substring(colon + 1).toInt();
    if (p > 0 && p < 65536) port = static_cast<uint16_t>(p);
    host = host.substring(0, colon);
  }

  char minerKey[40];
  fry_identity::ensureMinerKey(minerKey, sizeof(minerKey));

  BearSSL::WiFiClientSecure& tls = s_link->tls;
  // hardwareapi honours MFLN, so take the 512/512 path outright: the probe would cost a 32 KB
  // allocation (see src/esp8266/http_tls.cpp) to learn what we already know.
  tls.setInsecure();
  tls.setBufferSizes(512, 512);
  tls.setTimeout(kIoTimeoutMs);
  if (!tls.connect(host.c_str(), port)) {
    Serial.printf_P(PSTR("relay: tls connect failed (blk=%u)\n"),
                  static_cast<unsigned>(fry::queryMaxFreeBlock()));
    failOpen("link not opened", fry::ReconnectBackoff::Failure::Transport);
    return;
  }

  uint8_t nonce[16];
  for (int i = 0; i < 16; i += 4) {
    uint32_t r = ESP.random();
    memcpy(nonce + i, &r, 4);
  }
  char key[25];
  fry::base64Encode(nonce, sizeof(nonce), key, sizeof(key));
  char accept[29];
  fry::wsAcceptFor(key, accept, sizeof(accept));

  // Literals stay in flash (F()): every DRAM byte here is one the OTA gate's 36 KB block lacks.
  String req;
  req.reserve(320 + token.length());
  req += F("GET " FRY_RELAY_PATH);
  req += minerKey;
  req += F(" HTTP/1.1\r\nHost: ");
  req += host;
  req += F("\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
           "Sec-WebSocket-Protocol: fry-relay.1\r\nSec-WebSocket-Key: ");
  req += key;
  req += F("\r\nUser-Agent: fry-firmware/" FRY_FIRMWARE_VERSION "\r\nAuthorization: Bearer ");
  req += token;
  req += F("\r\n\r\n");
  tls.print(req);
  req = String();

  // Bounded in bytes and lines by WsUpgradeResponse, and in time here.
  fry::WsUpgradeResponse resp(accept);
  fry::WsUpgradeResponse::Result r = fry::WsUpgradeResponse::Result::NeedMore;
  const unsigned long started = millis();
  char line[128];
  while (r == fry::WsUpgradeResponse::Result::NeedMore) {
    const unsigned long elapsed = millis() - started;
    if (elapsed >= kUpgradeTimeoutMs || !tls.connected()) break;
    tls.setTimeout(kUpgradeTimeoutMs - elapsed);
    size_t n = tls.readBytesUntil('\n', line, sizeof(line) - 1);
    if (n == 0 && millis() - started >= kUpgradeTimeoutMs) break;
    const size_t raw = n + 1;  // the '\n' readBytesUntil consumed
    line[n] = 0;
    if (n && line[n - 1] == '\r') line[n - 1] = 0;
    r = resp.feedLine(line, raw);
  }
  tls.setTimeout(kIoTimeoutMs);

  if (r != fry::WsUpgradeResponse::Result::Ok) {
    const int status = resp.status();
    Serial.printf_P(PSTR("relay: upgrade refused http=%d result=%u\n"), status, static_cast<unsigned>(r));
    failOpen("link not opened", status >= 400 && status < 500
                                    ? fry::ReconnectBackoff::Failure::Http4xx
                                    : fry::ReconnectBackoff::Failure::Transport);
    return;
  }

  s_state = LinkState::Up;
  s_upSinceMs = millis();
  s_lastRxMs = s_upSinceMs;
  s_dropWhy = nullptr;

  char hello[200];
  size_t n = fry::relayBuildHello(hello, sizeof(hello), FRY_FIRMWARE_VERSION, FRY_BUILD_ENV,
                                  FRY_OTA_BOARD_ID, ESP.getFlashChipRealSize(),
                                  ESP.getFlashChipSize(), ESP.getFlashChipId(), ESP.getFreeHeap(),
                                  fry::queryMaxFreeBlock());
  sendRelay(fry::kRelayHello, reinterpret_cast<const uint8_t*>(hello), n);
  Serial.printf_P(PSTR("relay: link up (heap=%u blk=%u)\n"), static_cast<unsigned>(ESP.getFreeHeap()),
                static_cast<unsigned>(fry::queryMaxFreeBlock()));
}

void connectUpstream() {
  fry::RelaySocksSession& session = s_link->session;
  IPAddress ip;
  uint8_t rep = fry::kSocksRepOk;
  if (!WiFi.hostByName(session.host(), ip, kIoTimeoutMs)) {
    rep = 0x04;  // host unreachable
  } else if (!fry::relayIpAllowed(ip[0], ip[1], ip[2], ip[3]) ||
             !fry::destFilterV4(fry_dest::hostOrder(ip), fry_dest::ctx())) {
    rep = fry::kSocksRepNotAllowed;
  } else {
    s_link->upstream.setTimeout(kIoTimeoutMs);
    if (!s_link->upstream.connect(ip, session.port())) rep = 0x05;  // connection refused
  }
  uint8_t reply[10];
  size_t n = session.onConnectResult(rep, reply, sizeof(reply));
  sendRelay(fry::kRelayData, reply, n);
  Serial.printf_P(PSTR("relay: probe connect %s:%u rep=%u\n"), session.host(), session.port(), rep);
  if (rep != fry::kSocksRepOk) {
    sendRelay(fry::kRelayEnd, nullptr, 0);
    endStream();
  }
}

void handleRelayMessage(const uint8_t* p, size_t len) {
  if (len == 0) return;
  if (p[0] == fry::kRelayEnd) {
    endStream();
    return;
  }
  if (p[0] != fry::kRelayData) return;  // unknown types are ignored, not fatal

  uint8_t reply[12];
  size_t replyLen = 0;
  bool forward = false;
  fry::RelaySocksSession::Action a =
      s_link->session.feed(p + 1, len - 1, reply, sizeof(reply), replyLen, forward);
  if (forward) {
    if (s_link->upstream.connected()) s_link->upstream.write(p + 1, len - 1);
    return;
  }
  if (replyLen) sendRelay(fry::kRelayData, reply, replyLen);
  if (a == fry::RelaySocksSession::Action::Connect) {
    connectUpstream();
  } else if (a == fry::RelaySocksSession::Action::Close) {
    sendRelay(fry::kRelayEnd, nullptr, 0);
    endStream();
  }
}

// Reads toward one complete server frame; handles it once complete.
void pumpLink() {
  uint8_t* rx = s_link->rx;
  size_t& rxLen = s_link->rxLen;
  fry::WsFrameHeader h;
  fry::WsParse r = fry::wsParseServerHeader(rx, rxLen, fry::kWsMaxPayload, h);
  size_t want;
  if (r == fry::WsParse::Ok) {
    want = h.headerLen + h.payloadLen;
  } else if (r == fry::WsParse::NeedMoreData) {
    want = rxLen < 2 ? 2 : 4;
  } else {
    // 1009 message too big / 1002 protocol error
    const uint8_t code[2] = {0x03, static_cast<uint8_t>(r == fry::WsParse::TooBig ? 0xF1 : 0xEA)};
    sendFrame(fry::kWsClose, code, 2);
    requestDrop(r == fry::WsParse::TooBig ? "frame too big" : "protocol error");
    return;
  }

  if (rxLen < want) {
    int avail = s_link->tls.available();
    if (avail <= 0) return;
    size_t take = want - rxLen;
    if (static_cast<size_t>(avail) < take) take = avail;
    int n = s_link->tls.read(rx + rxLen, take);
    if (n > 0) rxLen += n;
    s_lastRxMs = millis();
    if (r != fry::WsParse::Ok || rxLen < want) return;
  }

  const uint8_t* payload = rx + h.headerLen;
  rxLen = 0;  // the frame is consumed below; payload stays valid until the next read
  switch (h.opcode) {
    case fry::kWsPing:
      sendFrame(fry::kWsPong, payload, h.payloadLen);
      break;
    case fry::kWsBinary:
      handleRelayMessage(payload, h.payloadLen);
      break;
    case fry::kWsClose:
      sendFrame(fry::kWsClose, payload, h.payloadLen > 2 ? 2 : h.payloadLen);
      requestDrop("server close");
      break;
    default:  // text and pong carry nothing the board acts on
      break;
  }
}

void pumpUpstream() {
  if (s_link->session.state() != fry::RelaySocksSession::State::Relaying) return;
  int avail = s_link->upstream.available();
  if (avail > 0) {
    // Read straight into the DATA payload (after its type byte): no second 512-byte buffer.
    const int room = static_cast<int>(sizeof(s_link->payload)) - 1;
    int n = s_link->upstream.read(s_link->payload + 1, avail > room ? room : avail);
    if (n > 0) {
      s_link->payload[0] = fry::kRelayData;
      sendFrame(fry::kWsBinary, s_link->payload, n + 1);
    }
  } else if (!s_link->upstream.connected()) {
    sendRelay(fry::kRelayEnd, nullptr, 0);
    endStream();
  }
}

}  // namespace

void begin() {
  if (s_state != LinkState::Off) return;
  s_state = LinkState::Waiting;
  s_nextAttemptMs = millis();
  Serial.printf_P(PSTR("relay: link armed (%s%s<key>)\n"), fry_config::getApiBase().c_str(), FRY_RELAY_PATH);
}

void tick() {
  switch (s_state) {
    case LinkState::Off:
    case LinkState::Paused:
      return;
    case LinkState::Waiting:
      if (fry_wifi::isConnected() && static_cast<long>(millis() - s_nextAttemptMs) >= 0) openLink();
      return;
    case LinkState::Up:
      if (!s_link->tls.connected()) {
        requestDrop("tls closed");
      } else if (millis() - s_lastRxMs > kDeadAfterMs) {
        requestDrop("no frame for 90s");
      } else {
        pumpLink();
        if (!s_dropWhy) pumpUpstream();
      }
      if (s_dropWhy) dropLink(s_dropWhy, true);
      return;
  }
}

void pause() {
  if (s_state == LinkState::Off || s_state == LinkState::Paused) return;
  s_pausedFrom = s_state;
  if (s_state == LinkState::Up) dropLink("paused for OTA check", false);
  s_state = LinkState::Paused;
  logHeap("link paused");
}

void resume() {
  if (s_state != LinkState::Paused) return;
  s_state = LinkState::Waiting;
  // A link that was up reconnects now; one that was already waiting keeps its pending
  // back-off (a 1 h refusal wait must not shrink to the next OTA check).
  if (s_pausedFrom == LinkState::Up) s_nextAttemptMs = millis();
}

}  // namespace fry_relay
