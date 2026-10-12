// U4/U6 (ESP8266 FEM boards do not earn): the board-side behaviour hwapi's relay router needs
// before it can observe, and so credit, an ESP8266. Each step is what relay_link.cpp does on the
// wire: upgrade the WebSocket, send a HELLO frame, then carry SOCKS5 as DATA/END messages.
// The field base (0.3.3) has none of this code, so this test cannot build there.
#include <unity.h>

#include <cstring>

#include "relay_proto.h"
#include "ws_frame.h"

namespace {

using S = fry::RelaySocksSession;

// What relay_link.cpp puts on the wire: a masked binary frame whose payload is type + body.
size_t sendFrame(uint8_t type, const uint8_t* body, size_t len, uint8_t* wire, size_t cap) {
  uint8_t msg[fry::kWsMaxPayload];
  msg[0] = type;
  if (len) memcpy(msg + 1, body, len);
  const uint8_t mask[4] = {0x11, 0x22, 0x33, 0x44};
  return fry::wsEncodeClientFrame(fry::kWsBinary, msg, len + 1, mask, wire, cap);
}

// Server-side view: unmask a client frame (hwapi unmasks) and return the message length.
size_t unmask(const uint8_t* wire, size_t n, uint8_t* msg, size_t cap) {
  TEST_ASSERT_TRUE(n >= 6);
  TEST_ASSERT_EQUAL_HEX8(0x82, wire[0]);  // FIN + binary
  TEST_ASSERT_TRUE(wire[1] & 0x80);       // client frames are masked
  size_t len = wire[1] & 0x7F, off = 2;
  if (len == 126) {
    len = (static_cast<size_t>(wire[2]) << 8) | wire[3];
    off = 4;
  }
  const uint8_t* mask = wire + off;
  off += 4;
  TEST_ASSERT_EQUAL_UINT(n, off + len);
  TEST_ASSERT_TRUE(len <= cap);
  for (size_t i = 0; i < len; i++) msg[i] = wire[off + i] ^ mask[i & 3];
  return len;
}

void test_upgrade_accepts_server_key_proof() {
  char acc[40];
  TEST_ASSERT_TRUE(fry::wsAcceptFor("dGhlIHNhbXBsZSBub25jZQ==", acc, sizeof(acc)));
  TEST_ASSERT_EQUAL_STRING("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", acc);
  fry::WsUpgradeResponse r(acc);
  using R = fry::WsUpgradeResponse::Result;
  TEST_ASSERT_EQUAL(R::NeedMore, r.feedLine("HTTP/1.1 101 Switching Protocols", 34));
  TEST_ASSERT_EQUAL(R::NeedMore, r.feedLine("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", 52));
  TEST_ASSERT_EQUAL(R::Ok, r.feedLine("", 2));
}

void test_hello_frame_reaches_server_intact() {
  char json[256];
  size_t jl = fry::relayBuildHello(json, sizeof(json), "0.4.2", "esp8266", "esp8266-4m1m", 4194304,
                                   4194304, 0x16301c, 30000, 20000);
  TEST_ASSERT_TRUE(jl > 0);
  uint8_t wire[300], msg[300];
  size_t n = sendFrame(fry::kRelayHello, reinterpret_cast<const uint8_t*>(json), jl, wire,
                       sizeof(wire));
  TEST_ASSERT_TRUE(n > 0);
  size_t ml = unmask(wire, n, msg, sizeof(msg));
  TEST_ASSERT_EQUAL_UINT(jl + 1, ml);
  TEST_ASSERT_EQUAL_HEX8(0x02, msg[0]);
  TEST_ASSERT_EQUAL_MEMORY(json, msg + 1, jl);
  TEST_ASSERT_NOT_NULL(strstr(json, "\"env\":\"esp8266\""));
  TEST_ASSERT_NOT_NULL(strstr(json, "\"v\":\"0.4.2\""));
}

void test_server_socks5_probe_round_trips_as_data_and_end() {
  S s;
  uint8_t reply[16];
  size_t rl = 0;
  bool fwd = false;
  const uint8_t greet[] = {5, 1, 0};
  TEST_ASSERT_EQUAL(S::Action::None, s.feed(greet, 3, reply, sizeof(reply), rl, fwd));
  TEST_ASSERT_EQUAL_UINT(2, rl);
  TEST_ASSERT_EQUAL_HEX8(0x00, reply[1]);

  // The board's greeting answer goes back as a DATA frame.
  uint8_t wire[64], msg[64];
  size_t n = sendFrame(fry::kRelayData, reply, rl, wire, sizeof(wire));
  size_t ml = unmask(wire, n, msg, sizeof(msg));
  TEST_ASSERT_EQUAL_UINT(3, ml);
  TEST_ASSERT_EQUAL_HEX8(0x00, msg[0]);
  TEST_ASSERT_EQUAL_HEX8(0x05, msg[1]);

  const char* host = "hardwareapi.frynetworks.com";
  uint8_t req[64];
  size_t hl = strlen(host);
  req[0] = 5; req[1] = 1; req[2] = 0; req[3] = 3; req[4] = static_cast<uint8_t>(hl);
  memcpy(req + 5, host, hl);
  req[5 + hl] = 443 >> 8;
  req[6 + hl] = 443 & 0xFF;
  TEST_ASSERT_EQUAL(S::Action::Connect, s.feed(req, 7 + hl, reply, sizeof(reply), rl, fwd));
  TEST_ASSERT_EQUAL_STRING(host, s.host());
  TEST_ASSERT_EQUAL_UINT16(443, s.port());
  TEST_ASSERT_TRUE(fry::relayDestAllowed(fry::Socks5AddrType::Domain, s.host(), s.port()));
  TEST_ASSERT_EQUAL_UINT(10, s.onConnectResult(fry::kSocksRepOk, reply, sizeof(reply)));
  TEST_ASSERT_EQUAL(S::State::Relaying, s.state());

  // Relayed payload (the TLS ClientHello in the field) is carried byte-exact in DATA.
  uint8_t payload[200];
  for (size_t i = 0; i < sizeof(payload); i++) payload[i] = static_cast<uint8_t>(i * 7);
  uint8_t big[300], back[300];
  n = sendFrame(fry::kRelayData, payload, sizeof(payload), big, sizeof(big));
  ml = unmask(big, n, back, sizeof(back));
  TEST_ASSERT_EQUAL_UINT(sizeof(payload) + 1, ml);
  TEST_ASSERT_EQUAL_MEMORY(payload, back + 1, sizeof(payload));

  // END from either side: the next stream starts with a fresh greeting.
  n = sendFrame(fry::kRelayEnd, nullptr, 0, wire, sizeof(wire));
  ml = unmask(wire, n, msg, sizeof(msg));
  TEST_ASSERT_EQUAL_UINT(1, ml);
  TEST_ASSERT_EQUAL_HEX8(0x01, msg[0]);
  s.reset();
  TEST_ASSERT_EQUAL(S::State::Greeting, s.state());
}

void test_server_to_board_frames_parse() {
  const uint8_t data[] = {0x82, 0x04, 0x00, 5, 1, 0};  // unmasked server DATA frame
  fry::WsFrameHeader h;
  TEST_ASSERT_EQUAL(fry::WsParse::Ok,
                    fry::wsParseServerHeader(data, sizeof(data), fry::kWsMaxPayload, h));
  TEST_ASSERT_EQUAL_UINT8(fry::kWsBinary, h.opcode);
  TEST_ASSERT_EQUAL_UINT(4, h.payloadLen);
  TEST_ASSERT_EQUAL_UINT(2, h.headerLen);
  TEST_ASSERT_EQUAL_HEX8(fry::kRelayData, data[h.headerLen]);
}

void test_board_refuses_lan_and_foreign_destinations() {
  TEST_ASSERT_FALSE(fry::relayDestAllowed(fry::Socks5AddrType::Domain, "example.com", 443));
  TEST_ASSERT_FALSE(fry::relayIpAllowed(192, 168, 1, 1));
  TEST_ASSERT_TRUE(fry::relayIpAllowed(8, 8, 8, 8));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main() {
  UNITY_BEGIN();
  RUN_TEST(test_upgrade_accepts_server_key_proof);
  RUN_TEST(test_hello_frame_reaches_server_intact);
  RUN_TEST(test_server_socks5_probe_round_trips_as_data_and_end);
  RUN_TEST(test_server_to_board_frames_parse);
  RUN_TEST(test_board_refuses_lan_and_foreign_destinations);
  return UNITY_END();
}
