// Single-client SOCKS5 CONNECT relay for ESP8266 (PROTOCOL.md section 6 / T6). ESP8266 has no
// spare heap/CPU for a WireGuard handshake, so its "VPN endpoint" is a SOCKS5 proxy: a client
// (e.g. the fry-app-android relay path) issues a CONNECT and this device relays bytes to the
// requested destination over its own STA uplink. Non-blocking state machine driven by tick() —
// ESP8266 is single-tasking cooperative, so nothing here may block for long or the captive
// portal / WiFi maintenance would stall too.
#include "../core/vpn_relay.h"

#include <ESP8266WiFi.h>

#include "../core/fry_config.h"
#include "socks5_parse.h"

namespace fry_vpn {

namespace {

enum class RelayState { Listening, Greeting, AwaitingConnect, Relaying };

const unsigned long kIdleTimeoutMs = 30000;
const size_t kCopyBufSize = 512;
const size_t kGreetingBufMax = 16;    // VER+NMETHODS(1)+up to 13 methods is generous already
const size_t kConnectBufMax = 262;    // worst case: 4 header + 1 len + 255 domain + 2 port

WiFiServer* s_server = nullptr;
WiFiClient s_client;
WiFiClient s_upstream;
RelayState s_state = RelayState::Listening;

uint8_t s_buf[kConnectBufMax];
size_t s_bufLen = 0;
unsigned long s_lastActivityMs = 0;
uint32_t s_relayedBytes = 0;

void resetToListening() {
  if (s_client) s_client.stop();
  if (s_upstream) s_upstream.stop();
  s_bufLen = 0;
  s_state = RelayState::Listening;
}

void sendConnectReply(bool ok) {
  // Fixed minimal reply: VER=5, REP, RSV=0, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0. Real
  // clients only care about the REP byte for a simple relay like this one.
  uint8_t reply[10] = {0x05, static_cast<uint8_t>(ok ? 0x00 : 0x01), 0x00, 0x01, 0, 0, 0, 0, 0, 0};
  s_client.write(reply, sizeof(reply));
}

void pumpRelay() {
  uint8_t buf[kCopyBufSize];
  bool activity = false;

  int avail = s_client.available();
  if (avail > 0) {
    int n = s_client.read(buf, avail > (int)sizeof(buf) ? sizeof(buf) : avail);
    if (n > 0) {
      s_upstream.write(buf, n);
      s_relayedBytes += n;
      activity = true;
    }
  }
  avail = s_upstream.available();
  if (avail > 0) {
    int n = s_upstream.read(buf, avail > (int)sizeof(buf) ? sizeof(buf) : avail);
    if (n > 0) {
      s_client.write(buf, n);
      s_relayedBytes += n;
      activity = true;
    }
  }

  if (activity) s_lastActivityMs = millis();
  if (!s_client.connected() || !s_upstream.connected() ||
      (millis() - s_lastActivityMs) > kIdleTimeoutMs) {
    resetToListening();
  }
}

}  // namespace

void init() {
  uint16_t port = static_cast<uint16_t>(fry_config::getSocksPort());
  s_server = new WiFiServer(port);
  s_server->begin();
  Serial.printf("socks5: listening :%u\n", port);
}

void tick() {
  if (!s_server) return;

  switch (s_state) {
    case RelayState::Listening: {
      if (s_server->hasClient()) {
        s_client = s_server->accept();
        s_bufLen = 0;
        s_state = RelayState::Greeting;
        s_lastActivityMs = millis();
      }
      break;
    }

    case RelayState::Greeting: {
      if (!s_client.connected()) {
        resetToListening();
        break;
      }
      int avail = s_client.available();
      if (avail > 0) {
        size_t room = kGreetingBufMax - s_bufLen;
        int n = s_client.read(s_buf + s_bufLen, avail > (int)room ? room : avail);
        if (n > 0) s_bufLen += n;
        s_lastActivityMs = millis();
      }
      fry::Socks5Greeting greeting;
      size_t consumed = 0;
      fry::Socks5Result r = fry::parseGreeting(s_buf, s_bufLen, greeting, consumed);
      if (r == fry::Socks5Result::Ok) {
        uint8_t ok[2] = {0x05, 0x00};
        s_client.write(ok, 2);
        s_bufLen = 0;
        s_state = RelayState::AwaitingConnect;
      } else if (r != fry::Socks5Result::NeedMoreData) {
        uint8_t fail[2] = {0x05, 0xFF};
        s_client.write(fail, 2);
        resetToListening();
      } else if (s_bufLen >= kGreetingBufMax) {
        resetToListening();  // malformed / oversized greeting — never grow the buffer unbounded
      }
      break;
    }

    case RelayState::AwaitingConnect: {
      if (!s_client.connected()) {
        resetToListening();
        break;
      }
      int avail = s_client.available();
      if (avail > 0) {
        size_t room = kConnectBufMax - s_bufLen;
        int n = s_client.read(s_buf + s_bufLen, avail > (int)room ? room : avail);
        if (n > 0) s_bufLen += n;
        s_lastActivityMs = millis();
      }
      fry::Socks5ConnectRequest req;
      size_t consumed = 0;
      fry::Socks5Result r = fry::parseConnectRequest(s_buf, s_bufLen, req, consumed);
      if (r == fry::Socks5Result::Ok) {
        bool ok = s_upstream.connect(req.host, req.port);
        sendConnectReply(ok);
        if (ok) {
          s_state = RelayState::Relaying;
          s_lastActivityMs = millis();
        } else {
          resetToListening();
        }
      } else if (r != fry::Socks5Result::NeedMoreData) {
        sendConnectReply(false);
        resetToListening();
      } else if (s_bufLen >= kConnectBufMax) {
        resetToListening();
      }
      break;
    }

    case RelayState::Relaying:
      pumpRelay();
      break;
  }
}

bool isUp() { return s_server != nullptr; }
uint32_t relayedBytes() { return s_relayedBytes; }

}  // namespace fry_vpn

extern "C" void fry_trigger_start_vpn() { fry_vpn::init(); }
