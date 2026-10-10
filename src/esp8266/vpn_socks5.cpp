// Single-client SOCKS5 CONNECT relay for ESP8266 (PROTOCOL.md section 6 / T6). ESP8266 has no
// spare heap/CPU for a WireGuard handshake, so its "VPN endpoint" is a SOCKS5 proxy: a client
// (e.g. the fry-app-android relay path) issues a CONNECT and this device relays bytes to the
// requested destination over its own STA uplink. Non-blocking state machine driven by tick() —
// ESP8266 is single-tasking cooperative, so nothing here may block for long or the captive
// portal / WiFi maintenance would stall too.
#include "../core/vpn_relay.h"

#include <ESP8266WiFi.h>

#include "../core/fry_config.h"
#include "dest_ctx.h"
#include "relay_link.h"
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

uint8_t s_denyRep = 0x01;  // REP byte of the failed connect reply (0x01 general, 0x02 blocked, 0x04 DNS)

void sendConnectReply(bool ok) {
  // Fixed minimal reply: VER=5, REP, RSV=0, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0. Real
  // clients only care about the REP byte for a simple relay like this one.
  uint8_t reply[10] = {0x05, static_cast<uint8_t>(ok ? 0x00 : s_denyRep), 0x00, 0x01, 0, 0, 0, 0, 0, 0};
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
  fry_relay::begin();  // IV5 G-3: the server-observable relay link, separate from :1080
}

void tick() {
  if (!s_server) return;
  fry_relay::tick();

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
        // Destination filter (lib/fry_core/dest_filter.h). The host is ALWAYS reduced to one IPv4
        // address, that address is checked, and the connect goes to THAT address, never to the host
        // string (lwIP would read "012.0.0.1" as octal 10.0.0.1). Non-canonical numeric forms are
        // blocked. Reply 0x02 = not allowed, 0x04 = host unreachable (DNS).
        bool ok = false;
        uint32_t dst = 0;
        bool haveIp = false;
        bool dnsFailed = false;
        bool literal = false;
        const fry::DestCtx dctx = fry_dest::ctx();
        const bool litAllowed = fry::destFilterText(req.host, dctx, &literal);
        if (literal) {
          haveIp = litAllowed && fry::destParseV4(req.host, &dst);
        } else {
          IPAddress resolved;
          if (WiFi.hostByName(req.host, resolved, 3000) == 1) {
            dst = fry_dest::hostOrder(resolved);
            haveIp = fry::destFilterV4(dst, dctx);
          } else {
            dnsFailed = true;
          }
        }
        if (haveIp) {
          ok = s_upstream.connect(IPAddress(dst >> 24, (dst >> 16) & 0xFF, (dst >> 8) & 0xFF, dst & 0xFF), req.port);
        }
        s_denyRep = ok ? 0x00 : (dnsFailed ? 0x04 : (haveIp ? 0x01 : 0x02));
        sendConnectReply(ok);
        if (ok) {
          s_state = RelayState::Relaying;
          s_lastActivityMs = millis();
        } else {
          resetToListening();
        }
      } else if (r != fry::Socks5Result::NeedMoreData) {
        s_denyRep = 0x01;
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
