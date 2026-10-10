// ESP8266 relay link (IV5 G-3/B5): WebSocket framing, the RFC 6455 accept check, SOCKS5 carried
// over the link's DATA messages, the board-side destination policy and the reconnect schedule.
// Vectors marked RFC are copied from RFC 6455 section 1.3 / 5.7 and FIPS 180 / RFC 4648.
#include <unity.h>

#include <cstring>

#include "reconnect_backoff.h"
#include "relay_proto.h"
#include "sha1.h"
#include "ws_frame.h"

namespace {

void hexOf(const uint8_t* d, size_t n, char* out) {
  static const char* k = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    out[2 * i] = k[d[i] >> 4];
    out[2 * i + 1] = k[d[i] & 15];
  }
  out[2 * n] = 0;
}

// ── SHA-1 / base64 / accept ──────────────────────────────────────────────────────────────────

void test_sha1_fips_vectors() {
  uint8_t d[20];
  char hex[41];
  fry::Sha1::hash(reinterpret_cast<const uint8_t*>("abc"), 3, d);
  hexOf(d, 20, hex);
  TEST_ASSERT_EQUAL_STRING("a9993e364706816aba3e25717850c26c9cd0d89d", hex);
  fry::Sha1::hash(reinterpret_cast<const uint8_t*>(""), 0, d);
  hexOf(d, 20, hex);
  TEST_ASSERT_EQUAL_STRING("da39a3ee5e6b4b0d3255bfef95601890afd80709", hex);
  const char* two = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";  // spans two blocks
  fry::Sha1::hash(reinterpret_cast<const uint8_t*>(two), strlen(two), d);
  hexOf(d, 20, hex);
  TEST_ASSERT_EQUAL_STRING("84983e441c3bd26ebaae4aa1f95129e5e54670f1", hex);
}

void test_base64_rfc4648_vectors() {
  char out[16];
  const char* in[] = {"", "f", "fo", "foo", "foob", "fooba", "foobar"};
  const char* want[] = {"", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy"};
  for (int i = 0; i < 7; i++) {
    size_t n = fry::base64Encode(reinterpret_cast<const uint8_t*>(in[i]), strlen(in[i]), out,
                                 sizeof(out));
    TEST_ASSERT_EQUAL_STRING(want[i], out);
    TEST_ASSERT_EQUAL_UINT(strlen(want[i]), n);
  }
  TEST_ASSERT_EQUAL_UINT(0, fry::base64Encode(reinterpret_cast<const uint8_t*>("foo"), 3, out, 4));
}

void test_ws_accept_rfc6455_vector() {
  char out[29];
  TEST_ASSERT_TRUE(fry::wsAcceptFor("dGhlIHNhbXBsZSBub25jZQ==", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", out);
  TEST_ASSERT_FALSE(fry::wsAcceptFor("dGhlIHNhbXBsZSBub25jZQ==", out, 28));
}

// ── WebSocket frames ─────────────────────────────────────────────────────────────────────────

void test_encode_masked_hello_rfc6455_vector() {
  const uint8_t mask[4] = {0x37, 0xfa, 0x21, 0x3d};
  uint8_t out[32];
  size_t n = fry::wsEncodeClientFrame(fry::kWsText, reinterpret_cast<const uint8_t*>("Hello"), 5,
                                      mask, out, sizeof(out));
  const uint8_t want[] = {0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58};
  TEST_ASSERT_EQUAL_UINT(sizeof(want), n);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(want, out, sizeof(want));
}

void test_encode_16bit_length_and_unmask_round_trip() {
  uint8_t payload[300];
  for (int i = 0; i < 300; i++) payload[i] = static_cast<uint8_t>(i * 7);
  const uint8_t mask[4] = {1, 2, 3, 4};
  uint8_t out[400];
  size_t n = fry::wsEncodeClientFrame(fry::kWsBinary, payload, 300, mask, out, sizeof(out));
  TEST_ASSERT_EQUAL_UINT(8 + 300, n);
  TEST_ASSERT_EQUAL_HEX8(0x82, out[0]);
  TEST_ASSERT_EQUAL_HEX8(0xFE, out[1]);  // MASK bit + 126
  TEST_ASSERT_EQUAL_HEX8(0x01, out[2]);
  TEST_ASSERT_EQUAL_HEX8(0x2C, out[3]);
  for (int i = 0; i < 300; i++) TEST_ASSERT_EQUAL_HEX8(payload[i], out[8 + i] ^ mask[i % 4]);
}

void test_encode_refuses_oversize_and_small_buffers() {
  static uint8_t payload[600];
  static uint8_t out[700];
  const uint8_t mask[4] = {0, 0, 0, 0};
  TEST_ASSERT_EQUAL_UINT(0, fry::wsEncodeClientFrame(fry::kWsBinary, payload, 513, mask, out,
                                                     sizeof(out)));
  TEST_ASSERT_EQUAL_UINT(8 + 512, fry::wsEncodeClientFrame(fry::kWsBinary, payload, 512, mask,
                                                           out, sizeof(out)));
  TEST_ASSERT_EQUAL_UINT(0, fry::wsEncodeClientFrame(fry::kWsPong, payload, 126, mask, out,
                                                     sizeof(out)));
  TEST_ASSERT_EQUAL_UINT(0, fry::wsEncodeClientFrame(fry::kWsBinary, payload, 10, mask, out, 15));
}

void test_parse_server_frames() {
  fry::WsFrameHeader h;
  const uint8_t text[] = {0x81, 0x05, 'H', 'e', 'l', 'l', 'o'};
  TEST_ASSERT_EQUAL(fry::WsParse::Ok, fry::wsParseServerHeader(text, sizeof(text), 512, h));
  TEST_ASSERT_EQUAL_HEX8(fry::kWsText, h.opcode);
  TEST_ASSERT_EQUAL_UINT(5, h.payloadLen);
  TEST_ASSERT_EQUAL_UINT(2, h.headerLen);

  const uint8_t bin300[] = {0x82, 0x7E, 0x01, 0x2C};
  TEST_ASSERT_EQUAL(fry::WsParse::Ok, fry::wsParseServerHeader(bin300, 4, 512, h));
  TEST_ASSERT_EQUAL_UINT(300, h.payloadLen);
  TEST_ASSERT_EQUAL_UINT(4, h.headerLen);

  const uint8_t ping[] = {0x89, 0x00};
  TEST_ASSERT_EQUAL(fry::WsParse::Ok, fry::wsParseServerHeader(ping, 2, 512, h));
  TEST_ASSERT_EQUAL_HEX8(fry::kWsPing, h.opcode);
}

void test_parse_needs_more_data() {
  fry::WsFrameHeader h;
  const uint8_t one[] = {0x82};
  TEST_ASSERT_EQUAL(fry::WsParse::NeedMoreData, fry::wsParseServerHeader(one, 1, 512, h));
  const uint8_t part16[] = {0x82, 0x7E, 0x01};
  TEST_ASSERT_EQUAL(fry::WsParse::NeedMoreData, fry::wsParseServerHeader(part16, 3, 512, h));
}

void test_parse_refuses_what_the_link_never_carries() {
  fry::WsFrameHeader h;
  const uint8_t masked[] = {0x82, 0x85, 1, 2, 3, 4};
  TEST_ASSERT_EQUAL(fry::WsParse::Malformed, fry::wsParseServerHeader(masked, 6, 512, h));
  const uint8_t rsv[] = {0xC2, 0x01};
  TEST_ASSERT_EQUAL(fry::WsParse::Malformed, fry::wsParseServerHeader(rsv, 2, 512, h));
  const uint8_t notFin[] = {0x02, 0x01};
  TEST_ASSERT_EQUAL(fry::WsParse::Malformed, fry::wsParseServerHeader(notFin, 2, 512, h));
  const uint8_t contin[] = {0x80, 0x01};
  TEST_ASSERT_EQUAL(fry::WsParse::Malformed, fry::wsParseServerHeader(contin, 2, 512, h));
  const uint8_t len64[] = {0x82, 0x7F, 0, 0, 0, 0, 0, 0, 0, 1};
  TEST_ASSERT_EQUAL(fry::WsParse::Malformed, fry::wsParseServerHeader(len64, 10, 512, h));
  const uint8_t bigCtl[] = {0x89, 0x7E, 0x00, 0x7E};
  TEST_ASSERT_EQUAL(fry::WsParse::Malformed, fry::wsParseServerHeader(bigCtl, 4, 512, h));
  const uint8_t reserved[] = {0x83, 0x00};
  TEST_ASSERT_EQUAL(fry::WsParse::Malformed, fry::wsParseServerHeader(reserved, 2, 512, h));
  const uint8_t big[] = {0x82, 0x7E, 0x02, 0x01};  // 513
  TEST_ASSERT_EQUAL(fry::WsParse::TooBig, fry::wsParseServerHeader(big, 4, 512, h));
}

// ── Destination policy ───────────────────────────────────────────────────────────────────────

void test_destination_policy() {
  using A = fry::Socks5AddrType;
  TEST_ASSERT_TRUE(fry::relayDestAllowed(A::Domain, "echo.frynetworks.com", 7));
  TEST_ASSERT_TRUE(fry::relayDestAllowed(A::Domain, "ECHO.FryNetworks.COM", 443));
  TEST_ASSERT_FALSE(fry::relayDestAllowed(A::Domain, "echo.frynetworks.com", 22));
  TEST_ASSERT_FALSE(fry::relayDestAllowed(A::Domain, "evil.com", 7));
  TEST_ASSERT_FALSE(fry::relayDestAllowed(A::Domain, "evilfrynetworks.com", 7));
  TEST_ASSERT_FALSE(fry::relayDestAllowed(A::Domain, "x.frynetworks.com.evil.com", 7));
  TEST_ASSERT_FALSE(fry::relayDestAllowed(A::Domain, "frynetworks.com", 7));
  TEST_ASSERT_FALSE(fry::relayDestAllowed(A::Domain, ".frynetworks.com", 7));
  TEST_ASSERT_FALSE(fry::relayDestAllowed(A::Domain, "echo.frynetworks.com.", 7));
  TEST_ASSERT_FALSE(fry::relayDestAllowed(A::IPv4, "1.2.3.4", 7));
  TEST_ASSERT_FALSE(fry::relayDestAllowed(A::IPv6, "::1", 7));
}

void test_resolved_ip_policy() {
  TEST_ASSERT_TRUE(fry::relayIpAllowed(23, 87, 33, 15));
  TEST_ASSERT_TRUE(fry::relayIpAllowed(8, 8, 8, 8));
  TEST_ASSERT_TRUE(fry::relayIpAllowed(172, 32, 0, 1));
  TEST_ASSERT_TRUE(fry::relayIpAllowed(100, 128, 0, 1));
  TEST_ASSERT_FALSE(fry::relayIpAllowed(0, 0, 0, 0));
  TEST_ASSERT_FALSE(fry::relayIpAllowed(10, 0, 0, 1));
  TEST_ASSERT_FALSE(fry::relayIpAllowed(100, 64, 0, 1));
  TEST_ASSERT_FALSE(fry::relayIpAllowed(100, 127, 255, 255));
  TEST_ASSERT_FALSE(fry::relayIpAllowed(127, 0, 0, 1));
  TEST_ASSERT_FALSE(fry::relayIpAllowed(169, 254, 1, 1));
  TEST_ASSERT_FALSE(fry::relayIpAllowed(172, 16, 0, 1));
  TEST_ASSERT_FALSE(fry::relayIpAllowed(172, 31, 255, 255));
  TEST_ASSERT_FALSE(fry::relayIpAllowed(192, 168, 1, 2));
  TEST_ASSERT_FALSE(fry::relayIpAllowed(224, 0, 0, 1));
  TEST_ASSERT_FALSE(fry::relayIpAllowed(255, 255, 255, 255));
}

// ── SOCKS5 over the link ─────────────────────────────────────────────────────────────────────

using S = fry::RelaySocksSession;

size_t connectDomain(uint8_t* out, const char* host, uint16_t port) {
  size_t n = strlen(host);
  out[0] = 5; out[1] = 1; out[2] = 0; out[3] = 3; out[4] = static_cast<uint8_t>(n);
  memcpy(out + 5, host, n);
  out[5 + n] = static_cast<uint8_t>(port >> 8);
  out[6 + n] = static_cast<uint8_t>(port & 0xFF);
  return 7 + n;
}

void test_session_greeting_connect_relay() {
  S s;
  uint8_t reply[16];
  size_t rl = 0;
  bool fwd = false;
  const uint8_t greet[] = {5, 1, 0};
  TEST_ASSERT_EQUAL(S::Action::None, s.feed(greet, 3, reply, sizeof(reply), rl, fwd));
  TEST_ASSERT_EQUAL_UINT(2, rl);
  TEST_ASSERT_EQUAL_HEX8(0x05, reply[0]);
  TEST_ASSERT_EQUAL_HEX8(0x00, reply[1]);
  TEST_ASSERT_FALSE(fwd);

  uint8_t req[64];
  size_t n = connectDomain(req, "echo.frynetworks.com", 7);
  TEST_ASSERT_EQUAL(S::Action::Connect, s.feed(req, n, reply, sizeof(reply), rl, fwd));
  TEST_ASSERT_EQUAL_UINT(0, rl);
  TEST_ASSERT_EQUAL_STRING("echo.frynetworks.com", s.host());
  TEST_ASSERT_EQUAL_UINT16(7, s.port());
  TEST_ASSERT_EQUAL(S::State::Connecting, s.state());

  TEST_ASSERT_EQUAL_UINT(10, s.onConnectResult(fry::kSocksRepOk, reply, sizeof(reply)));
  const uint8_t ok[10] = {5, 0, 0, 1, 0, 0, 0, 0, 0, 0};
  TEST_ASSERT_EQUAL_UINT8_ARRAY(ok, reply, 10);
  TEST_ASSERT_EQUAL(S::State::Relaying, s.state());

  const uint8_t data[] = {'n', 'o', 'n', 'c', 'e'};
  TEST_ASSERT_EQUAL(S::Action::None, s.feed(data, 5, reply, sizeof(reply), rl, fwd));
  TEST_ASSERT_TRUE(fwd);
  TEST_ASSERT_EQUAL_UINT(0, rl);
}

void test_session_split_and_pipelined_input() {
  S s;
  uint8_t reply[16];
  size_t rl = 0;
  bool fwd = false;
  const uint8_t g1[] = {5};
  TEST_ASSERT_EQUAL(S::Action::None, s.feed(g1, 1, reply, sizeof(reply), rl, fwd));
  TEST_ASSERT_EQUAL_UINT(0, rl);
  // rest of greeting + whole CONNECT in one message (an optimistic client)
  uint8_t buf[80] = {1, 0};
  size_t n = 2 + connectDomain(buf + 2, "echo.frynetworks.com", 443);
  TEST_ASSERT_EQUAL(S::Action::Connect, s.feed(buf, n, reply, sizeof(reply), rl, fwd));
  TEST_ASSERT_EQUAL_UINT(2, rl);  // the method reply still goes out
  TEST_ASSERT_EQUAL_UINT16(443, s.port());
}

void test_session_refusals() {
  uint8_t reply[16];
  size_t rl = 0;
  bool fwd = false;
  const uint8_t greet[] = {5, 1, 0};

  {  // no NO-AUTH method
    S s;
    const uint8_t g[] = {5, 1, 2};
    TEST_ASSERT_EQUAL(S::Action::Close, s.feed(g, 3, reply, sizeof(reply), rl, fwd));
    TEST_ASSERT_EQUAL_UINT(2, rl);
    TEST_ASSERT_EQUAL_HEX8(0xFF, reply[1]);
  }
  {  // IPv4 literal: not allowed, never connects
    S s;
    s.feed(greet, 3, reply, sizeof(reply), rl, fwd);
    const uint8_t req[] = {5, 1, 0, 1, 10, 0, 0, 1, 0, 7};
    TEST_ASSERT_EQUAL(S::Action::Close, s.feed(req, sizeof(req), reply, sizeof(reply), rl, fwd));
    TEST_ASSERT_EQUAL_UINT(10, rl);
    TEST_ASSERT_EQUAL_HEX8(fry::kSocksRepNotAllowed, reply[1]);
  }
  {  // foreign domain
    S s;
    s.feed(greet, 3, reply, sizeof(reply), rl, fwd);
    uint8_t req[64];
    size_t n = connectDomain(req, "example.com", 7);
    TEST_ASSERT_EQUAL(S::Action::Close, s.feed(req, n, reply, sizeof(reply), rl, fwd));
    TEST_ASSERT_EQUAL_HEX8(fry::kSocksRepNotAllowed, reply[1]);
  }
  {  // bytes after CONNECT before the reply is a protocol violation
    S s;
    s.feed(greet, 3, reply, sizeof(reply), rl, fwd);
    uint8_t req[64];
    size_t n = connectDomain(req, "echo.frynetworks.com", 7);
    req[n++] = 'x';
    TEST_ASSERT_EQUAL(S::Action::Close, s.feed(req, n, reply, sizeof(reply), rl, fwd));
    TEST_ASSERT_EQUAL_HEX8(fry::kSocksRepFailure, reply[1]);
  }
  {  // BIND is unsupported
    S s;
    s.feed(greet, 3, reply, sizeof(reply), rl, fwd);
    uint8_t req[64];
    size_t n = connectDomain(req, "echo.frynetworks.com", 7);
    req[1] = 2;
    TEST_ASSERT_EQUAL(S::Action::Close, s.feed(req, n, reply, sizeof(reply), rl, fwd));
  }
  {  // input while Connecting
    S s;
    s.feed(greet, 3, reply, sizeof(reply), rl, fwd);
    uint8_t req[64];
    size_t n = connectDomain(req, "echo.frynetworks.com", 7);
    s.feed(req, n, reply, sizeof(reply), rl, fwd);
    TEST_ASSERT_EQUAL(S::Action::Close, s.feed(greet, 1, reply, sizeof(reply), rl, fwd));
  }
  {  // failed upstream connect closes
    S s;
    s.feed(greet, 3, reply, sizeof(reply), rl, fwd);
    uint8_t req[64];
    size_t n = connectDomain(req, "echo.frynetworks.com", 7);
    s.feed(req, n, reply, sizeof(reply), rl, fwd);
    TEST_ASSERT_EQUAL_UINT(10, s.onConnectResult(fry::kSocksRepFailure, reply, sizeof(reply)));
    TEST_ASSERT_EQUAL_HEX8(0x01, reply[1]);
    TEST_ASSERT_EQUAL(S::State::Closed, s.state());
  }
  {  // a garbage greeting never grows the buffer: bounded, then closed
    S s;
    uint8_t junk[300];
    memset(junk, 0x05, sizeof(junk));
    junk[1] = 0xFF;  // claims 255 methods, none of them NO-AUTH
    S::Action a = s.feed(junk, sizeof(junk), reply, sizeof(reply), rl, fwd);
    TEST_ASSERT_EQUAL(S::Action::Close, a);
  }
  {  // reset() starts a fresh stream after END
    S s;
    s.feed(greet, 3, reply, sizeof(reply), rl, fwd);
    s.reset();
    TEST_ASSERT_EQUAL(S::State::Greeting, s.state());
    TEST_ASSERT_EQUAL(S::Action::None, s.feed(greet, 3, reply, sizeof(reply), rl, fwd));
    TEST_ASSERT_EQUAL_UINT(2, rl);
  }
}

void test_hello_json() {
  char out[256];
  size_t n = fry::relayBuildHello(out, sizeof(out), "0.3.4", "esp8266", "esp8266-4m1m", 4194304,
                                  4194304, 0x16301c, 30000, 20000);
  const char* want =
      "{\"v\":\"0.3.4\",\"env\":\"esp8266\",\"board_id\":\"esp8266-4m1m\",\"flash_real\":4194304,"
      "\"flash_hdr\":4194304,\"flash_id\":\"16301c\",\"heap\":30000,\"blk\":20000}";
  TEST_ASSERT_EQUAL_STRING(want, out);
  TEST_ASSERT_EQUAL_UINT(strlen(want), n);
  TEST_ASSERT_EQUAL_UINT(0, fry::relayBuildHello(out, 20, "0.3.4", "esp8266", "esp8266-4m1m", 1, 1,
                                                 1, 1, 1));
}

// ── Reconnect schedule ───────────────────────────────────────────────────────────────────────

void test_backoff_doubles_to_cap_with_bounded_jitter() {
  fry::ReconnectBackoff b;
  using F = fry::ReconnectBackoff::Failure;
  const uint32_t nominal[] = {30000, 60000, 120000, 240000, 480000, 600000, 600000};
  for (uint32_t want : nominal) {
    fry::ReconnectBackoff lo = b, hi = b;
    uint32_t dLo = lo.onFailure(F::Transport, 0);
    uint32_t dHi = hi.onFailure(F::Transport, 0xFFFFFFFFu);
    TEST_ASSERT_EQUAL_UINT32(want / 10 * 8, dLo);  // -20 %
    TEST_ASSERT_TRUE(dHi < want / 10 * 12);        // < +20 %
    TEST_ASSERT_TRUE(dHi > want / 10 * 11);
    b.onFailure(F::Transport, 0x80000000u);
  }
}

void test_backoff_4xx_is_one_hour() {
  fry::ReconnectBackoff b;
  uint32_t d = b.onFailure(fry::ReconnectBackoff::Failure::Http4xx, 0x80000000u);
  TEST_ASSERT_EQUAL_UINT32(3600000, d);  // midpoint random word = no jitter
  TEST_ASSERT_TRUE(b.onFailure(fry::ReconnectBackoff::Failure::Http4xx, 0) >= 2880000);
}

void test_backoff_resets_only_after_a_stable_link() {
  fry::ReconnectBackoff b;
  using F = fry::ReconnectBackoff::Failure;
  b.onFailure(F::Transport, 0x80000000u);
  b.onFailure(F::Transport, 0x80000000u);
  b.onFailure(F::Transport, 0x80000000u);
  b.onLinkDown(599999);  // flapping link: keep backing off
  TEST_ASSERT_EQUAL_UINT32(240000, b.onFailure(F::Transport, 0x80000000u));
  b.onLinkDown(600000);
  TEST_ASSERT_EQUAL_UINT32(30000, b.onFailure(F::Transport, 0x80000000u));
}

void test_backoff_stays_under_the_server_connect_limit() {
  // hwapi relay_ws.py refuses a key's 13th connect within an hour (12/h). A link that keeps
  // failing, at the SHORTEST jitter, must stay at or under that: initial connect + retries.
  fry::ReconnectBackoff b;
  uint64_t t = 0;
  int connects = 1;
  while (true) {
    t += b.onFailure(fry::ReconnectBackoff::Failure::Transport, 0);
    if (t >= 3600000) break;
    connects++;
  }
  TEST_ASSERT_TRUE(connects <= 12);
  // ...and so must a link that comes up and drops just short of "stable".
  fry::ReconnectBackoff f;
  t = 0;
  connects = 1;
  while (true) {
    t += 599999;
    f.onLinkDown(599999);
    t += f.onFailure(fry::ReconnectBackoff::Failure::Transport, 0);
    if (t >= 3600000) break;
    connects++;
  }
  TEST_ASSERT_TRUE(connects <= 12);
}

void test_resolved_ip_policy_reserved_ranges() {
  // T2 F5: documentation/benchmark/IETF ranges are never real Fry endpoints.
  TEST_ASSERT_FALSE(fry::relayIpAllowed(192, 0, 0, 1));
  TEST_ASSERT_FALSE(fry::relayIpAllowed(192, 0, 2, 1));
  TEST_ASSERT_FALSE(fry::relayIpAllowed(198, 18, 0, 1));
  TEST_ASSERT_FALSE(fry::relayIpAllowed(198, 19, 255, 255));
  TEST_ASSERT_FALSE(fry::relayIpAllowed(198, 51, 100, 7));
  TEST_ASSERT_FALSE(fry::relayIpAllowed(203, 0, 113, 9));
  // neighbours stay allowed
  TEST_ASSERT_TRUE(fry::relayIpAllowed(192, 0, 1, 1));
  TEST_ASSERT_TRUE(fry::relayIpAllowed(198, 20, 0, 1));
  TEST_ASSERT_TRUE(fry::relayIpAllowed(198, 51, 101, 1));
  TEST_ASSERT_TRUE(fry::relayIpAllowed(203, 0, 114, 1));
}

// ── Upgrade response (T2 F6) ─────────────────────────────────────────────────────────────────

const char* kAccept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

void test_upgrade_ok() {
  fry::WsUpgradeResponse r(kAccept);
  using R = fry::WsUpgradeResponse::Result;
  TEST_ASSERT_EQUAL(R::NeedMore, r.feedLine("HTTP/1.1 101 Switching Protocols", 34));
  TEST_ASSERT_EQUAL(R::NeedMore, r.feedLine("Upgrade: websocket", 20));
  TEST_ASSERT_EQUAL(R::NeedMore, r.feedLine("sec-websocket-accept:   s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", 54));
  TEST_ASSERT_EQUAL(R::NeedMore, r.feedLine("Sec-WebSocket-Protocol: fry-relay.1", 37));
  TEST_ASSERT_EQUAL(R::Ok, r.feedLine("", 2));
  TEST_ASSERT_EQUAL_INT(101, r.status());
}

void test_upgrade_refused_status() {
  fry::WsUpgradeResponse r(kAccept);
  using R = fry::WsUpgradeResponse::Result;
  TEST_ASSERT_EQUAL(R::NeedMore, r.feedLine("HTTP/1.1 403 Forbidden", 24));
  TEST_ASSERT_EQUAL(R::NeedMore, r.feedLine("Content-Length: 0", 19));
  TEST_ASSERT_EQUAL(R::Refused, r.feedLine("", 2));
  TEST_ASSERT_EQUAL_INT(403, r.status());
}

void test_upgrade_bad_accept_or_status_line() {
  using R = fry::WsUpgradeResponse::Result;
  {
    fry::WsUpgradeResponse r(kAccept);
    r.feedLine("HTTP/1.1 101 Switching Protocols", 34);
    r.feedLine("Sec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=", 52);
    TEST_ASSERT_EQUAL(R::Malformed, r.feedLine("", 2));
  }
  {
    fry::WsUpgradeResponse r(kAccept);
    r.feedLine("HTTP/1.1 101 Switching Protocols", 34);
    TEST_ASSERT_EQUAL(R::Malformed, r.feedLine("", 2));  // no Accept at all
  }
  {
    fry::WsUpgradeResponse r(kAccept);
    TEST_ASSERT_EQUAL(R::Malformed, r.feedLine("SSH-2.0-OpenSSH_9.6", 21));
  }
  {
    fry::WsUpgradeResponse r(kAccept);
    TEST_ASSERT_EQUAL(R::Malformed, r.feedLine("", 2));  // empty before a status line
  }
}

void test_upgrade_is_bounded() {
  using R = fry::WsUpgradeResponse::Result;
  {
    fry::WsUpgradeResponse r(kAccept);
    r.feedLine("HTTP/1.1 101 Switching Protocols", 34);
    R last = R::NeedMore;
    for (int i = 0; i < 40 && last == R::NeedMore; i++) last = r.feedLine("X-Pad: 1", 10);
    TEST_ASSERT_EQUAL(R::TooLong, last);  // > kMaxLines
  }
  {
    fry::WsUpgradeResponse r(kAccept);
    r.feedLine("HTTP/1.1 101 Switching Protocols", 34);
    TEST_ASSERT_EQUAL(R::NeedMore, r.feedLine("X-Big: a", 1500));
    TEST_ASSERT_EQUAL(R::TooLong, r.feedLine("X-Big: b", 600));  // > kMaxBytes
  }
}

}  // namespace

void setUp() {}

void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_sha1_fips_vectors);
  RUN_TEST(test_base64_rfc4648_vectors);
  RUN_TEST(test_ws_accept_rfc6455_vector);
  RUN_TEST(test_encode_masked_hello_rfc6455_vector);
  RUN_TEST(test_encode_16bit_length_and_unmask_round_trip);
  RUN_TEST(test_encode_refuses_oversize_and_small_buffers);
  RUN_TEST(test_parse_server_frames);
  RUN_TEST(test_parse_needs_more_data);
  RUN_TEST(test_parse_refuses_what_the_link_never_carries);
  RUN_TEST(test_destination_policy);
  RUN_TEST(test_resolved_ip_policy);
  RUN_TEST(test_resolved_ip_policy_reserved_ranges);
  RUN_TEST(test_upgrade_ok);
  RUN_TEST(test_upgrade_refused_status);
  RUN_TEST(test_upgrade_bad_accept_or_status_line);
  RUN_TEST(test_upgrade_is_bounded);
  RUN_TEST(test_session_greeting_connect_relay);
  RUN_TEST(test_session_split_and_pipelined_input);
  RUN_TEST(test_session_refusals);
  RUN_TEST(test_hello_json);
  RUN_TEST(test_backoff_doubles_to_cap_with_bounded_jitter);
  RUN_TEST(test_backoff_4xx_is_one_hour);
  RUN_TEST(test_backoff_resets_only_after_a_stable_link);
  RUN_TEST(test_backoff_stays_under_the_server_connect_limit);
  return UNITY_END();
}
