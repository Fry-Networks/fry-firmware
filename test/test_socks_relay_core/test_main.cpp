// lib/fry_core/socks_relay_core.*: the pure core of the ESP32 SOCKS5 relay.
//
// Each group below pins one thing the 0.4.7 relay (src/esp32/vpn_wireguard.cpp at 25b7b7b) got
// wrong or left unguarded:
//   * errno trusted without the return value (stale errno / lwIP errno 119 closed live sockets)
//   * a CONNECT request pipelined behind the greeting was thrown away
//   * one client at a time: a stalled client blocked every other client
//   * select() result ignored, FD_SET unguarded, fixed 5 ms polling
// plus the deadline, backpressure and half-close behaviour of the per-client state machine.
#include <unity.h>

#include <cerrno>
#include <cstring>

#include "socks_relay_core.h"

using namespace fry_relay;

namespace {

const Timing kT;  // defaults: greeting 5000, request 5000, connect 3000, idle 30000, ...

const uint8_t kGreet[3] = {0x05, 0x01, 0x00};
const uint8_t kConnV4[10] = {0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50};  // 1.2.3.4:80

size_t buildDomainReq(uint8_t* out, const char* host, uint16_t port) {
  const size_t hl = strlen(host);
  size_t n = 0;
  out[n++] = 0x05;
  out[n++] = 0x01;
  out[n++] = 0x00;
  out[n++] = 0x03;
  out[n++] = static_cast<uint8_t>(hl);
  memcpy(out + n, host, hl);
  n += hl;
  out[n++] = static_cast<uint8_t>(port >> 8);
  out[n++] = static_cast<uint8_t>(port & 0xFF);
  return n;
}

// Do what the shim does: recv() into the slot's destination, then report the byte count.
void feed(Slot& s, Side from, const uint8_t* d, size_t n, uint32_t now) {
  size_t room = 0;
  uint8_t* dst = recvDest(s, from, room);
  TEST_ASSERT_TRUE_MESSAGE(room >= n, "recvDest offered too little room");
  memcpy(dst, d, n);
  onRecv(s, from, static_cast<long>(n), 0, now);
}

// Send everything pending toward `to`, as the shim would, and return the bytes.
size_t drain(Slot& s, Side to, uint8_t* out, size_t cap, uint32_t now) {
  size_t len = 0;
  const uint8_t* p = sendSrc(s, to, len);
  TEST_ASSERT_TRUE(len <= cap);
  if (len == 0) return 0;
  memcpy(out, p, len);
  onSend(s, to, static_cast<long>(len), 0, now);
  return len;
}

void toRelay(Slot& s, int cfd, int ufd, uint32_t now) {
  slotInit(s, cfd, now);
  feed(s, Side::Client, kGreet, sizeof(kGreet), now);
  feed(s, Side::Client, kConnV4, sizeof(kConnV4), now);
  onConnectStarted(s, ufd, now);
  onConnectResult(s, true, now);
  uint8_t sink[32];
  drain(s, Side::Client, sink, sizeof(sink), now);
  TEST_ASSERT_EQUAL((int)Phase::Relay, (int)s.phase);
}

// ---- errno / return-value classification -----------------------------------------------

void test_recv_data_ignores_stale_errno() {
  TEST_ASSERT_EQUAL((int)IoResult::Data, (int)classifyRecv(17, ECONNRESET));
  TEST_ASSERT_EQUAL((int)IoResult::Data, (int)classifyRecv(1, EINPROGRESS));
}

void test_recv_zero_is_eof_whatever_errno_says() {
  // recv() returning 0 does not touch errno: whatever is in it belongs to an older call.
  TEST_ASSERT_EQUAL((int)IoResult::Eof, (int)classifyRecv(0, 0));
  TEST_ASSERT_EQUAL((int)IoResult::Eof, (int)classifyRecv(0, ECONNRESET));
  TEST_ASSERT_EQUAL((int)IoResult::Eof, (int)classifyRecv(0, EINPROGRESS));
  TEST_ASSERT_EQUAL((int)IoResult::Eof, (int)classifyRecv(0, EWOULDBLOCK));
}

void test_recv_negative_transient_errnos_are_not_death() {
  // errno 119 on the bench is lwIP's EINPROGRESS; Arduino's WiFiClient closed the socket on it.
  TEST_ASSERT_EQUAL((int)IoResult::WouldBlock, (int)classifyRecv(-1, EINPROGRESS));
  TEST_ASSERT_EQUAL((int)IoResult::WouldBlock, (int)classifyRecv(-1, EALREADY));
  TEST_ASSERT_EQUAL((int)IoResult::WouldBlock, (int)classifyRecv(-1, EAGAIN));
  TEST_ASSERT_EQUAL((int)IoResult::WouldBlock, (int)classifyRecv(-1, EWOULDBLOCK));
  TEST_ASSERT_EQUAL((int)IoResult::WouldBlock, (int)classifyRecv(-1, EINTR));
}

void test_recv_negative_dead_errnos_are_closed() {
  TEST_ASSERT_EQUAL((int)IoResult::Closed, (int)classifyRecv(-1, ECONNRESET));
  TEST_ASSERT_EQUAL((int)IoResult::Closed, (int)classifyRecv(-1, ENOTCONN));
  TEST_ASSERT_EQUAL((int)IoResult::Closed, (int)classifyRecv(-1, ECONNABORTED));
  TEST_ASSERT_EQUAL((int)IoResult::Error, (int)classifyRecv(-1, EBADF));
}

void test_send_classification() {
  TEST_ASSERT_EQUAL((int)IoResult::Data, (int)classifySend(5, ECONNRESET));
  TEST_ASSERT_EQUAL((int)IoResult::WouldBlock, (int)classifySend(0, 0));
  TEST_ASSERT_EQUAL((int)IoResult::WouldBlock, (int)classifySend(-1, EAGAIN));
  TEST_ASSERT_EQUAL((int)IoResult::WouldBlock, (int)classifySend(-1, ENOMEM));  // lwIP ERR_MEM
  TEST_ASSERT_EQUAL((int)IoResult::Closed, (int)classifySend(-1, EPIPE));
  TEST_ASSERT_EQUAL((int)IoResult::Closed, (int)classifySend(-1, ECONNRESET));
}

void test_connect_start_classification() {
  TEST_ASSERT_EQUAL((int)ConnectStart::Done, (int)classifyConnectStart(0, 0));
  TEST_ASSERT_EQUAL((int)ConnectStart::Done, (int)classifyConnectStart(0, EINPROGRESS));  // stale
  TEST_ASSERT_EQUAL((int)ConnectStart::InProgress, (int)classifyConnectStart(-1, EINPROGRESS));
  TEST_ASSERT_EQUAL((int)ConnectStart::InProgress, (int)classifyConnectStart(-1, EALREADY));
  TEST_ASSERT_EQUAL((int)ConnectStart::Failed, (int)classifyConnectStart(-1, ECONNREFUSED));
  TEST_ASSERT_EQUAL((int)ConnectStart::Failed, (int)classifyConnectStart(-1, ENETUNREACH));
}

void test_select_result_is_never_ignored() {
  TEST_ASSERT_EQUAL((int)SelectAction::Ready, (int)classifySelect(2, 0));
  TEST_ASSERT_EQUAL((int)SelectAction::Timeout, (int)classifySelect(0, 0));
  TEST_ASSERT_EQUAL((int)SelectAction::Timeout, (int)classifySelect(0, EBADF));  // stale errno
  TEST_ASSERT_EQUAL((int)SelectAction::Interrupted, (int)classifySelect(-1, EINTR));
  TEST_ASSERT_EQUAL((int)SelectAction::Failed, (int)classifySelect(-1, EBADF));
  TEST_ASSERT_EQUAL((int)SelectAction::Failed, (int)classifySelect(-1, EINVAL));
}

void test_select_failure_backoff_is_bounded() {
  TEST_ASSERT_EQUAL_UINT32(0, selectFailBackoffMs(0));
  TEST_ASSERT_EQUAL_UINT32(10, selectFailBackoffMs(1));
  TEST_ASSERT_EQUAL_UINT32(50, selectFailBackoffMs(5));
  TEST_ASSERT_EQUAL_UINT32(100, selectFailBackoffMs(10));
  TEST_ASSERT_EQUAL_UINT32(100, selectFailBackoffMs(100000));
}

// ---- handshake: greeting, request, pipelining -------------------------------------------

void test_greeting_then_request_in_separate_reads() {
  Slot s;
  slotInit(s, 50, 1000);
  feed(s, Side::Client, kGreet, sizeof(kGreet), 1001);
  TEST_ASSERT_EQUAL((int)Phase::Request, (int)s.phase);
  uint8_t out[16];
  TEST_ASSERT_EQUAL(2, (int)drain(s, Side::Client, out, sizeof(out), 1001));
  TEST_ASSERT_EQUAL_UINT8(0x05, out[0]);
  TEST_ASSERT_EQUAL_UINT8(0x00, out[1]);
  feed(s, Side::Client, kConnV4, sizeof(kConnV4), 1002);
  TEST_ASSERT_EQUAL((int)Phase::NeedConnect, (int)s.phase);
  TEST_ASSERT_EQUAL_STRING("1.2.3.4", s.req.host);
  TEST_ASSERT_EQUAL_UINT16(80, s.req.port);
}

void test_greeting_split_one_byte_at_a_time() {
  Slot s;
  slotInit(s, 50, 0);
  for (size_t i = 0; i < sizeof(kGreet); i++) {
    TEST_ASSERT_EQUAL((int)Phase::Greeting, (int)s.phase);
    feed(s, Side::Client, kGreet + i, 1, 10 + i);
  }
  TEST_ASSERT_EQUAL((int)Phase::Request, (int)s.phase);
  for (size_t i = 0; i < sizeof(kConnV4); i++) feed(s, Side::Client, kConnV4 + i, 1, 20 + i);
  TEST_ASSERT_EQUAL((int)Phase::NeedConnect, (int)s.phase);
  TEST_ASSERT_EQUAL_STRING("1.2.3.4", s.req.host);
}

void test_pipelined_greeting_and_connect_in_one_segment() {
  // curl and others may send VER/NMETHODS/METHODS and the CONNECT request back to back. The
  // 0.4.7 relay reset its buffer after the greeting and lost the request.
  uint8_t seg[3 + 10];
  memcpy(seg, kGreet, 3);
  memcpy(seg + 3, kConnV4, 10);
  Slot s;
  slotInit(s, 50, 0);
  feed(s, Side::Client, seg, sizeof(seg), 5);
  TEST_ASSERT_EQUAL((int)Phase::NeedConnect, (int)s.phase);
  TEST_ASSERT_EQUAL_STRING("1.2.3.4", s.req.host);
  TEST_ASSERT_EQUAL_UINT16(80, s.req.port);
  uint8_t out[16];
  TEST_ASSERT_EQUAL(2, (int)drain(s, Side::Client, out, sizeof(out), 5));  // the method reply
  TEST_ASSERT_EQUAL_UINT8(0x00, out[1]);
}

void test_pipelined_greeting_consumes_exactly_the_greeting_bytes() {
  // Three methods offered: greeting is 5 bytes, the request begins at byte 5.
  uint8_t seg[5 + 10] = {0x05, 0x03, 0x02, 0x00, 0x01};
  memcpy(seg + 5, kConnV4, 10);
  Slot s;
  slotInit(s, 50, 0);
  feed(s, Side::Client, seg, sizeof(seg), 5);
  TEST_ASSERT_EQUAL((int)Phase::NeedConnect, (int)s.phase);
  TEST_ASSERT_EQUAL_STRING("1.2.3.4", s.req.host);
}

void test_pipelined_domain_request_and_early_payload() {
  // Greeting + CONNECT example.com:443 + the first bytes of a TLS ClientHello, all in one
  // segment. The payload must be held and forwarded upstream once connected.
  uint8_t req[64];
  const size_t rn = buildDomainReq(req, "example.com", 443);
  const uint8_t hello[6] = {0x16, 0x03, 0x01, 0x00, 0xF4, 0x01};
  uint8_t seg[128];
  size_t n = 0;
  memcpy(seg, kGreet, 3), n += 3;
  memcpy(seg + n, req, rn), n += rn;
  memcpy(seg + n, hello, sizeof(hello)), n += sizeof(hello);
  Slot s;
  slotInit(s, 50, 0);
  feed(s, Side::Client, seg, n, 5);
  TEST_ASSERT_EQUAL((int)Phase::NeedConnect, (int)s.phase);
  TEST_ASSERT_EQUAL_STRING("example.com", s.req.host);
  TEST_ASSERT_EQUAL_UINT16(443, s.req.port);
  onConnectStarted(s, 51, 6);
  onConnectResult(s, true, 7);
  TEST_ASSERT_EQUAL((int)Phase::Relay, (int)s.phase);
  size_t len = 0;
  const uint8_t* p = sendSrc(s, Side::Up, len);
  TEST_ASSERT_EQUAL(6, (int)len);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(hello, p, 6);
  // and the replies reach the client in order: method reply, then the connect reply
  uint8_t out[32];
  const size_t got = drain(s, Side::Client, out, sizeof(out), 8);
  TEST_ASSERT_EQUAL(12, (int)got);
  TEST_ASSERT_EQUAL_UINT8(0x00, out[1]);
  TEST_ASSERT_EQUAL_UINT8(0x00, out[2 + 1]);  // connect reply REP = success
}

void test_unsupported_method_gets_ff_then_closes_after_flush() {
  const uint8_t greet[3] = {0x05, 0x01, 0x02};  // only user/pass offered
  Slot s;
  slotInit(s, 50, 0);
  feed(s, Side::Client, greet, sizeof(greet), 1);
  TEST_ASSERT_EQUAL((int)Phase::Flush, (int)s.phase);
  uint8_t out[8];
  TEST_ASSERT_EQUAL(2, (int)drain(s, Side::Client, out, sizeof(out), 2));
  TEST_ASSERT_EQUAL_UINT8(0x05, out[0]);
  TEST_ASSERT_EQUAL_UINT8(0xFF, out[1]);
  TEST_ASSERT_TRUE(slotClosed(s));
  TEST_ASSERT_EQUAL((int)CloseReason::HandshakeBad, (int)s.reason);
}

void test_unsupported_command_gets_failure_reply() {
  const uint8_t bind[10] = {0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0, 80};  // BIND
  Slot s;
  slotInit(s, 50, 0);
  feed(s, Side::Client, kGreet, sizeof(kGreet), 1);
  feed(s, Side::Client, bind, sizeof(bind), 2);
  TEST_ASSERT_EQUAL((int)Phase::Flush, (int)s.phase);
  uint8_t out[32];
  const size_t n = drain(s, Side::Client, out, sizeof(out), 3);
  TEST_ASSERT_EQUAL(12, (int)n);  // method reply + failure reply
  TEST_ASSERT_EQUAL_UINT8(0x01, out[3]);
  TEST_ASSERT_TRUE(slotClosed(s));
}

void test_eof_before_a_complete_request_closes() {
  Slot s;
  slotInit(s, 50, 0);
  feed(s, Side::Client, kGreet, 2, 1);  // partial greeting
  onRecv(s, Side::Client, 0, 0, 2);
  TEST_ASSERT_TRUE(slotClosed(s));
  TEST_ASSERT_EQUAL((int)CloseReason::HandshakeEof, (int)s.reason);
}

void test_transient_errno_on_a_handshake_read_does_not_close() {
  // errno 119 around a fast close on the C3: a negative read with EINPROGRESS must be retried.
  Slot s;
  slotInit(s, 50, 0);
  onRecv(s, Side::Client, -1, EINPROGRESS, 2);
  TEST_ASSERT_EQUAL((int)Phase::Greeting, (int)s.phase);
  feed(s, Side::Client, kGreet, sizeof(kGreet), 3);
  TEST_ASSERT_EQUAL((int)Phase::Request, (int)s.phase);
}

// ---- deadlines ----------------------------------------------------------------------------

void test_greeting_deadline_5000ms() {
  Slot s;
  slotInit(s, 50, 100000);
  onTimer(s, kT, 100000 + 4999);
  TEST_ASSERT_EQUAL((int)Phase::Greeting, (int)s.phase);
  TEST_ASSERT_EQUAL_UINT32(1, slotRemainingMs(s, kT, 100000 + 4999));
  onTimer(s, kT, 100000 + 5000);
  TEST_ASSERT_TRUE(slotClosed(s));
  TEST_ASSERT_EQUAL((int)CloseReason::HandshakeTimeout, (int)s.reason);
}

void test_deadline_is_wrap_safe() {
  const uint32_t t0 = 0xFFFFFFFFu - 1000u;  // millis() wraps 1 s after accept
  Slot s;
  slotInit(s, 50, t0);
  onTimer(s, kT, t0 + 4000u);  // wrapped past zero
  TEST_ASSERT_EQUAL((int)Phase::Greeting, (int)s.phase);
  TEST_ASSERT_EQUAL_UINT32(1000, slotRemainingMs(s, kT, t0 + 4000u));
  onTimer(s, kT, t0 + 5000u);
  TEST_ASSERT_TRUE(slotClosed(s));
}

void test_request_deadline_counts_from_the_end_of_the_greeting() {
  Slot s;
  slotInit(s, 50, 0);
  feed(s, Side::Client, kGreet, sizeof(kGreet), 4000);
  TEST_ASSERT_EQUAL((int)Phase::Request, (int)s.phase);
  onTimer(s, kT, 8999);  // 8999 ms after accept but only 4999 into the request stage
  TEST_ASSERT_EQUAL((int)Phase::Request, (int)s.phase);
  onTimer(s, kT, 9000);
  TEST_ASSERT_TRUE(slotClosed(s));
}

void test_connect_timeout_replies_failure_then_closes() {
  Slot s;
  slotInit(s, 50, 0);
  feed(s, Side::Client, kGreet, sizeof(kGreet), 1);
  feed(s, Side::Client, kConnV4, sizeof(kConnV4), 2);
  onConnectStarted(s, 51, 3);
  TEST_ASSERT_EQUAL((int)Phase::Connecting, (int)s.phase);
  onTimer(s, kT, 3 + 2999);
  TEST_ASSERT_EQUAL((int)Phase::Connecting, (int)s.phase);
  onTimer(s, kT, 3 + 3000);
  TEST_ASSERT_EQUAL((int)Phase::Flush, (int)s.phase);
  uint8_t out[32];
  const size_t n = drain(s, Side::Client, out, sizeof(out), 4000);
  TEST_ASSERT_EQUAL(12, (int)n);
  TEST_ASSERT_EQUAL_UINT8(0x01, out[3]);
  TEST_ASSERT_TRUE(slotClosed(s));
  TEST_ASSERT_EQUAL((int)CloseReason::ConnectTimeout, (int)s.reason);
}

void test_connect_failure_replies_and_closes() {
  Slot s;
  slotInit(s, 50, 0);
  feed(s, Side::Client, kGreet, sizeof(kGreet), 1);
  feed(s, Side::Client, kConnV4, sizeof(kConnV4), 2);
  onConnectStarted(s, 51, 3);
  onConnectResult(s, false, 10);
  TEST_ASSERT_EQUAL((int)Phase::Flush, (int)s.phase);
  uint8_t out[32];
  drain(s, Side::Client, out, sizeof(out), 11);
  TEST_ASSERT_TRUE(slotClosed(s));
  TEST_ASSERT_EQUAL((int)CloseReason::ConnectFail, (int)s.reason);
}

void test_flush_deadline_closes_a_client_that_never_reads() {
  Slot s;
  slotInit(s, 50, 0);
  const uint8_t greet[3] = {0x05, 0x01, 0x02};
  feed(s, Side::Client, greet, sizeof(greet), 1);
  TEST_ASSERT_EQUAL((int)Phase::Flush, (int)s.phase);
  onTimer(s, kT, 1 + 1999);
  TEST_ASSERT_EQUAL((int)Phase::Flush, (int)s.phase);
  onTimer(s, kT, 1 + 2000);
  TEST_ASSERT_TRUE(slotClosed(s));
}

// ---- a stalled client must not block another ------------------------------------------

void test_stalled_client_does_not_block_a_second_client() {
  Slot a, b;
  Slot* pool[kMaxSlots] = {&a, nullptr, nullptr, nullptr};
  slotInit(a, 50, 0);  // connects, sends nothing

  // the pool still offers a free slot while `a` is stalled in the greeting stage
  const int idx = poolFreeIndex(pool, kMaxSlots);
  TEST_ASSERT_EQUAL(1, idx);
  pool[idx] = &b;
  slotInit(b, 52, 100);

  uint8_t seg[13];
  memcpy(seg, kGreet, 3);
  memcpy(seg + 3, kConnV4, 10);
  feed(b, Side::Client, seg, sizeof(seg), 110);
  onConnectStarted(b, 53, 111);
  onConnectResult(b, true, 112);
  uint8_t out[32];
  drain(b, Side::Client, out, sizeof(out), 113);
  TEST_ASSERT_EQUAL((int)Phase::Relay, (int)b.phase);
  TEST_ASSERT_EQUAL((int)Phase::Greeting, (int)a.phase);

  // payload flows through b while a is still stalled
  const uint8_t req[5] = {'H', 'E', 'L', 'L', 'O'};
  feed(b, Side::Client, req, 5, 200);
  size_t len = 0;
  sendSrc(b, Side::Up, len);
  TEST_ASSERT_EQUAL(5, (int)len);

  // a times out on its own deadline without disturbing b
  onTimer(a, kT, 5000);
  onTimer(b, kT, 5000);
  TEST_ASSERT_TRUE(slotClosed(a));
  TEST_ASSERT_EQUAL((int)Phase::Relay, (int)b.phase);
}

void test_pool_free_index_with_busy_slots() {
  Slot a, b, c, d;
  Slot* pool[kMaxSlots] = {&a, &b, nullptr, &d};
  TEST_ASSERT_EQUAL(2, poolFreeIndex(pool, kMaxSlots));
  pool[2] = &c;
  TEST_ASSERT_EQUAL(-1, poolFreeIndex(pool, kMaxSlots));
}

void test_pool_evicts_oldest_stalled_handshake_only() {
  Slot a, b, c, d;
  slotInit(a, 50, 1000);   // stalled, oldest
  slotInit(b, 51, 3000);   // stalled, younger
  toRelay(c, 52, 53, 500); // relaying, oldest of all but never evictable
  slotInit(d, 54, 9900);   // fresh
  Slot* pool[kMaxSlots] = {&a, &b, &c, &d};
  TEST_ASSERT_EQUAL(0, poolEvictIndex(pool, kMaxSlots, 10000, 1000));
  pool[0] = nullptr;
  TEST_ASSERT_EQUAL(1, poolEvictIndex(pool, kMaxSlots, 10000, 1000));
  pool[1] = nullptr;
  TEST_ASSERT_EQUAL(-1, poolEvictIndex(pool, kMaxSlots, 10000, 1000));  // d is too young
  TEST_ASSERT_EQUAL(3, poolEvictIndex(pool, kMaxSlots, 10000, 50));
}

void test_pool_evict_age_is_wrap_safe() {
  Slot a;
  slotInit(a, 50, 0xFFFFFF00u);
  Slot* pool[kMaxSlots] = {&a, nullptr, nullptr, nullptr};
  TEST_ASSERT_EQUAL(0, poolEvictIndex(pool, kMaxSlots, 0x00000300u, 1000));  // 1024 ms old
  TEST_ASSERT_EQUAL(-1, poolEvictIndex(pool, kMaxSlots, 0x00000100u, 1000));  // 512 ms old
}

// ---- select timeout: block, do not poll -------------------------------------------------

void test_select_timeout_without_clients_blocks_on_the_listener() {
  Slot* pool[kMaxSlots] = {nullptr, nullptr, nullptr, nullptr};
  TEST_ASSERT_EQUAL_UINT32(1000, poolSelectTimeoutMs(pool, kMaxSlots, kT, 12345, 1000));
}

void test_select_timeout_is_the_nearest_deadline() {
  Slot a, b;
  slotInit(a, 50, 0);      // greeting deadline 5000
  slotInit(b, 51, 2000);   // greeting deadline 7000
  Slot* pool[kMaxSlots] = {&a, nullptr, &b, nullptr};
  TEST_ASSERT_EQUAL_UINT32(3000, poolSelectTimeoutMs(pool, kMaxSlots, kT, 2000, 10000));
  TEST_ASSERT_EQUAL_UINT32(400, poolSelectTimeoutMs(pool, kMaxSlots, kT, 2000, 400));  // capped
  TEST_ASSERT_EQUAL_UINT32(0, poolSelectTimeoutMs(pool, kMaxSlots, kT, 5000, 10000));  // expired
}

void test_select_timeout_with_one_relaying_slot_is_not_a_5ms_poll() {
  Slot a;
  toRelay(a, 50, 51, 0);
  Slot* pool[kMaxSlots] = {&a, nullptr, nullptr, nullptr};
  const uint32_t ms = poolSelectTimeoutMs(pool, kMaxSlots, kT, 10, 1000);
  TEST_ASSERT_TRUE(ms > 5);
  TEST_ASSERT_EQUAL_UINT32(1000, ms);
}

// ---- FD_SETSIZE guard ---------------------------------------------------------------------

void test_watch_list_skips_unused_and_adds_valid_fds() {
  Slot a;
  slotInit(a, 55, 0);  // Greeting: wants client read only; upFd is -1 but not wanted
  Slot* pool[kMaxSlots] = {&a, nullptr, nullptr, nullptr};
  WatchList wl;
  buildWatchList(pool, kMaxSlots, 54, true, 64, wl);
  TEST_ASSERT_EQUAL(2, wl.n);
  TEST_ASSERT_EQUAL(55, wl.maxFd);
  TEST_ASSERT_FALSE(wl.listenBad);
  TEST_ASSERT_FALSE(wl.slotBad[0]);
  TEST_ASSERT_EQUAL(54, wl.w[0].fd);
  TEST_ASSERT_TRUE(wl.w[0].rd);
  TEST_ASSERT_FALSE(wl.w[0].wr);
  TEST_ASSERT_EQUAL(55, wl.w[1].fd);
  TEST_ASSERT_TRUE(wl.w[1].rd);
}

void test_watch_list_never_contains_an_out_of_range_fd() {
  Slot a, b, c;
  slotInit(a, 64, 0);   // == FD_SETSIZE: out of range
  slotInit(b, -1, 0);   // wanted but invalid
  slotInit(c, 63, 0);   // last valid fd
  Slot* pool[kMaxSlots] = {&a, &b, &c, nullptr};
  WatchList wl;
  buildWatchList(pool, kMaxSlots, 70, true, 64, wl);
  TEST_ASSERT_TRUE(wl.listenBad);
  TEST_ASSERT_TRUE(wl.slotBad[0]);
  TEST_ASSERT_TRUE(wl.slotBad[1]);
  TEST_ASSERT_FALSE(wl.slotBad[2]);
  for (int i = 0; i < wl.n; i++) {
    TEST_ASSERT_TRUE(wl.w[i].fd >= 0 && wl.w[i].fd < 64);
  }
  TEST_ASSERT_EQUAL(1, wl.n);
  TEST_ASSERT_EQUAL(63, wl.w[0].fd);
  TEST_ASSERT_EQUAL(63, wl.maxFd);
}

void test_watch_list_flags_a_bad_upstream_fd_while_connecting() {
  Slot a;
  slotInit(a, 50, 0);
  feed(a, Side::Client, kGreet, sizeof(kGreet), 1);
  feed(a, Side::Client, kConnV4, sizeof(kConnV4), 1);
  onConnectStarted(a, 200, 2);  // Connecting with an fd outside the select range
  Slot* pool[kMaxSlots] = {&a, nullptr, nullptr, nullptr};
  WatchList wl;
  buildWatchList(pool, kMaxSlots, 49, false, 64, wl);
  TEST_ASSERT_TRUE(wl.slotBad[0]);
  // the client fd (the method reply is still unsent) is valid, the upstream fd 200 is not listed
  TEST_ASSERT_EQUAL(1, wl.n);
  TEST_ASSERT_EQUAL(50, wl.w[0].fd);
  TEST_ASSERT_TRUE(wl.w[0].wr);
}

void test_listener_not_watched_when_pool_is_full() {
  Slot a;
  slotInit(a, 50, 0);
  Slot* pool[kMaxSlots] = {&a, nullptr, nullptr, nullptr};
  WatchList wl;
  buildWatchList(pool, kMaxSlots, 49, false, 64, wl);
  TEST_ASSERT_EQUAL(1, wl.n);
  TEST_ASSERT_EQUAL(50, wl.w[0].fd);
}

// ---- relay: wants, backpressure, half-close, deadlines -------------------------------------

void test_wants_follow_the_phase() {
  Slot s;
  slotInit(s, 50, 0);
  Wants w = slotWants(s);
  TEST_ASSERT_TRUE(w.clientRd);
  TEST_ASSERT_FALSE(w.clientWr);
  TEST_ASSERT_FALSE(w.upRd);
  TEST_ASSERT_FALSE(w.upWr);
  feed(s, Side::Client, kGreet, sizeof(kGreet), 1);  // method reply now pending
  w = slotWants(s);
  TEST_ASSERT_TRUE(w.clientRd);
  TEST_ASSERT_TRUE(w.clientWr);
  feed(s, Side::Client, kConnV4, sizeof(kConnV4), 2);
  onConnectStarted(s, 51, 3);
  w = slotWants(s);
  TEST_ASSERT_TRUE(w.upWr);
  TEST_ASSERT_FALSE(w.upRd);
}

void test_relay_copies_both_ways() {
  Slot s;
  toRelay(s, 50, 51, 0);
  const uint8_t up[4] = {1, 2, 3, 4};
  feed(s, Side::Client, up, 4, 10);
  uint8_t out[16];
  TEST_ASSERT_EQUAL(4, (int)drain(s, Side::Up, out, sizeof(out), 10));
  TEST_ASSERT_EQUAL_UINT8_ARRAY(up, out, 4);
  const uint8_t down[3] = {9, 8, 7};
  feed(s, Side::Up, down, 3, 11);
  TEST_ASSERT_EQUAL(3, (int)drain(s, Side::Client, out, sizeof(out), 11));
  TEST_ASSERT_EQUAL_UINT8_ARRAY(down, out, 3);
  TEST_ASSERT_EQUAL((int)Phase::Relay, (int)s.phase);
}

void test_relay_backpressure_holds_reads_until_the_send_completes() {
  Slot s;
  toRelay(s, 50, 51, 0);
  uint8_t big[kBufSize];
  memset(big, 0xAB, sizeof(big));
  feed(s, Side::Client, big, sizeof(big), 5);
  size_t room = 99;
  recvDest(s, Side::Client, room);
  TEST_ASSERT_EQUAL(0, (int)room);  // full: do not read the client again yet
  Wants w = slotWants(s);
  TEST_ASSERT_FALSE(w.clientRd);
  TEST_ASSERT_TRUE(w.upWr);

  size_t len = 0;
  sendSrc(s, Side::Up, len);
  TEST_ASSERT_EQUAL((int)kBufSize, (int)len);
  onSend(s, Side::Up, 300, 0, 6);  // partial write
  sendSrc(s, Side::Up, len);
  TEST_ASSERT_EQUAL((int)kBufSize - 300, (int)len);
  onSend(s, Side::Up, -1, EAGAIN, 7);  // would block: nothing changes
  sendSrc(s, Side::Up, len);
  TEST_ASSERT_EQUAL((int)kBufSize - 300, (int)len);
  onSend(s, Side::Up, static_cast<long>(kBufSize - 300), 0, 8);
  sendSrc(s, Side::Up, len);
  TEST_ASSERT_EQUAL(0, (int)len);
  recvDest(s, Side::Client, room);
  TEST_ASSERT_EQUAL((int)kBufSize, (int)room);
  TEST_ASSERT_TRUE(slotWants(s).clientRd);
}

void test_client_fin_is_forwarded_after_pending_data_and_upstream_can_finish() {
  Slot s;
  toRelay(s, 50, 51, 0);
  const uint8_t req[3] = {'G', 'E', 'T'};
  feed(s, Side::Client, req, 3, 10);
  onRecv(s, Side::Client, 0, 0, 11);  // FIN while the request is still unsent
  TEST_ASSERT_FALSE(takeShutdown(s, Side::Up));  // not before the data is out
  uint8_t out[8];
  TEST_ASSERT_EQUAL(3, (int)drain(s, Side::Up, out, sizeof(out), 12));
  TEST_ASSERT_TRUE(takeShutdown(s, Side::Up));
  TEST_ASSERT_FALSE(takeShutdown(s, Side::Up));  // one-shot
  TEST_ASSERT_EQUAL((int)Phase::Relay, (int)s.phase);
  // the reply still flows after the half-close
  const uint8_t resp[2] = {'O', 'K'};
  feed(s, Side::Up, resp, 2, 13);
  TEST_ASSERT_EQUAL(2, (int)drain(s, Side::Client, out, sizeof(out), 13));
  onRecv(s, Side::Up, 0, 0, 14);  // upstream finishes
  TEST_ASSERT_TRUE(slotClosed(s));
  TEST_ASSERT_EQUAL((int)CloseReason::Done, (int)s.reason);
}

void test_stale_errno_in_relay_is_a_half_close_not_a_reset() {
  Slot s;
  toRelay(s, 50, 51, 0);
  onRecv(s, Side::Client, 0, ECONNRESET, 10);  // EOF with a stale errno
  TEST_ASSERT_EQUAL((int)Phase::Relay, (int)s.phase);
  TEST_ASSERT_TRUE(takeShutdown(s, Side::Up));
}

void test_half_close_has_a_deadline() {
  Slot s;
  toRelay(s, 50, 51, 0);
  onRecv(s, Side::Client, 0, 0, 1000);
  onTimer(s, kT, 1000 + 4999);
  TEST_ASSERT_EQUAL((int)Phase::Relay, (int)s.phase);
  TEST_ASSERT_EQUAL_UINT32(1, slotRemainingMs(s, kT, 1000 + 4999));
  onTimer(s, kT, 1000 + 5000);
  TEST_ASSERT_TRUE(slotClosed(s));
  TEST_ASSERT_EQUAL((int)CloseReason::HalfCloseTimeout, (int)s.reason);
}

void test_idle_deadline_resets_on_activity() {
  Slot s;
  toRelay(s, 50, 51, 0);
  const uint8_t b[1] = {1};
  feed(s, Side::Client, b, 1, 20000);
  uint8_t out[4];
  drain(s, Side::Up, out, sizeof(out), 20000);
  onTimer(s, kT, 29999 + 20000);
  TEST_ASSERT_EQUAL((int)Phase::Relay, (int)s.phase);
  onTimer(s, kT, 30000 + 20000);
  TEST_ASSERT_TRUE(slotClosed(s));
  TEST_ASSERT_EQUAL((int)CloseReason::Idle, (int)s.reason);
}

void test_reset_in_relay_closes_immediately() {
  Slot s;
  toRelay(s, 50, 51, 0);
  onRecv(s, Side::Up, -1, ECONNRESET, 5);
  TEST_ASSERT_TRUE(slotClosed(s));
  TEST_ASSERT_EQUAL((int)CloseReason::IoError, (int)s.reason);

  Slot t;
  toRelay(t, 52, 53, 0);
  const uint8_t b[2] = {1, 2};
  feed(t, Side::Client, b, 2, 6);
  onSend(t, Side::Up, -1, EPIPE, 7);
  TEST_ASSERT_TRUE(slotClosed(t));
}

void test_transient_errno_in_relay_keeps_the_connection() {
  Slot s;
  toRelay(s, 50, 51, 0);
  onRecv(s, Side::Client, -1, EINPROGRESS, 5);
  onRecv(s, Side::Up, -1, EAGAIN, 5);
  onSend(s, Side::Client, -1, ENOMEM, 5);
  TEST_ASSERT_EQUAL((int)Phase::Relay, (int)s.phase);
}

void test_force_close_records_the_reason_once() {
  Slot s;
  slotInit(s, 50, 0);
  slotForceClose(s, CloseReason::Evicted);
  slotForceClose(s, CloseReason::FdGuard);
  TEST_ASSERT_TRUE(slotClosed(s));
  TEST_ASSERT_EQUAL((int)CloseReason::Evicted, (int)s.reason);
}


// ---- review follow-up: eviction by activity, inactivity-based half-close, one-shot FIN ---

void test_handshake_bytes_refresh_the_activity_clock() {
  Slot s;
  slotInit(s, 50, 100);
  TEST_ASSERT_EQUAL_UINT32(100, s.lastActivityMs);
  const uint8_t one[1] = {0x05};
  feed(s, Side::Client, one, 1, 4000);  // partial greeting: still Greeting, but not silent
  TEST_ASSERT_EQUAL((int)Phase::Greeting, (int)s.phase);
  TEST_ASSERT_EQUAL_UINT32(4000, s.lastActivityMs);
}

void test_pool_evicts_by_idle_time_not_by_accept_age() {
  // `a` was accepted first but sent a byte 500 ms ago (its greeting was queued while the loop was
  // blocked); `b` was accepted later and has been silent for 2000 ms. `b` is the stalled one.
  Slot a, b;
  slotInit(a, 50, 0);
  const uint8_t one[1] = {0x05};
  feed(a, Side::Client, one, 1, 9500);
  slotInit(b, 51, 8000);
  Slot* pool[kMaxSlots] = {&a, &b, nullptr, nullptr};
  TEST_ASSERT_EQUAL(1, poolEvictIndex(pool, kMaxSlots, 10000, 1000));
  pool[1] = nullptr;
  TEST_ASSERT_EQUAL(-1, poolEvictIndex(pool, kMaxSlots, 10000, 1000));  // `a` is active: keep it
  TEST_ASSERT_EQUAL(0, poolEvictIndex(pool, kMaxSlots, 10600, 1000));   // quiet for 1100 ms now
}

void test_half_close_deadline_is_inactivity_based() {
  // A response that keeps flowing after the client's FIN must not be cut at halfCloseMs from the
  // FIN: the deadline counts from the last byte that moved.
  Slot s;
  toRelay(s, 50, 51, 0);
  onRecv(s, Side::Client, 0, 0, 1000);  // client FIN
  const uint8_t d[2] = {1, 2};
  uint8_t out[8];
  feed(s, Side::Up, d, 2, 5900);  // upstream still talking 4900 ms after the FIN
  drain(s, Side::Client, out, sizeof(out), 5900);
  onTimer(s, kT, 6000);  // 5000 ms after the FIN, only 100 ms after the last byte
  TEST_ASSERT_EQUAL((int)Phase::Relay, (int)s.phase);
  feed(s, Side::Up, d, 2, 10800);
  drain(s, Side::Client, out, sizeof(out), 10800);
  onTimer(s, kT, 15799);
  TEST_ASSERT_EQUAL((int)Phase::Relay, (int)s.phase);
  TEST_ASSERT_EQUAL_UINT32(1, slotRemainingMs(s, kT, 15799));
  onTimer(s, kT, 15800);
  TEST_ASSERT_TRUE(slotClosed(s));
  TEST_ASSERT_EQUAL((int)CloseReason::HalfCloseTimeout, (int)s.reason);
}

void test_half_close_deadline_also_follows_send_progress() {
  // The client FINs with a request still queued for a slow upstream that accepts a byte at a time.
  Slot s;
  toRelay(s, 50, 51, 0);
  const uint8_t req[3] = {'a', 'b', 'c'};
  feed(s, Side::Client, req, 3, 10);
  onRecv(s, Side::Client, 0, 0, 20);  // FIN with the request unsent
  onSend(s, Side::Up, 1, 0, 4000);
  onTimer(s, kT, 5020);  // would be 5000 ms after the FIN
  TEST_ASSERT_EQUAL((int)Phase::Relay, (int)s.phase);
  onSend(s, Side::Up, 1, 0, 8000);
  onTimer(s, kT, 12999);
  TEST_ASSERT_EQUAL((int)Phase::Relay, (int)s.phase);
  onTimer(s, kT, 13000);  // 5000 ms after the last byte moved
  TEST_ASSERT_TRUE(slotClosed(s));
}

void test_shutdown_toward_upstream_is_one_shot_across_later_events() {
  // Every recv/send result re-runs the relay bookkeeping; none of them may re-arm a FIN that
  // the shim has already forwarded.
  Slot s;
  toRelay(s, 50, 51, 0);
  onRecv(s, Side::Client, 0, 0, 10);
  TEST_ASSERT_TRUE(takeShutdown(s, Side::Up));
  const uint8_t d[2] = {1, 2};
  uint8_t out[8];
  feed(s, Side::Up, d, 2, 11);
  onRecv(s, Side::Client, -1, EAGAIN, 12);
  drain(s, Side::Client, out, sizeof(out), 13);
  onRecv(s, Side::Up, -1, EINPROGRESS, 14);
  TEST_ASSERT_FALSE(takeShutdown(s, Side::Up));
  TEST_ASSERT_FALSE(takeShutdown(s, Side::Client));  // the upstream has not closed
  TEST_ASSERT_EQUAL((int)Phase::Relay, (int)s.phase);
}

void test_shutdown_toward_client_is_one_shot_too() {
  Slot s;
  toRelay(s, 50, 51, 0);
  onRecv(s, Side::Up, 0, 0, 10);  // upstream FIN, nothing left to deliver
  TEST_ASSERT_TRUE(takeShutdown(s, Side::Client));
  const uint8_t d[2] = {1, 2};
  uint8_t out[8];
  feed(s, Side::Client, d, 2, 11);
  drain(s, Side::Up, out, sizeof(out), 12);
  onRecv(s, Side::Up, 0, ECONNRESET, 13);  // a second EOF report with a stale errno
  onSend(s, Side::Up, -1, EAGAIN, 14);
  TEST_ASSERT_FALSE(takeShutdown(s, Side::Client));
  TEST_ASSERT_FALSE(takeShutdown(s, Side::Up));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_recv_data_ignores_stale_errno);
  RUN_TEST(test_recv_zero_is_eof_whatever_errno_says);
  RUN_TEST(test_recv_negative_transient_errnos_are_not_death);
  RUN_TEST(test_recv_negative_dead_errnos_are_closed);
  RUN_TEST(test_send_classification);
  RUN_TEST(test_connect_start_classification);
  RUN_TEST(test_select_result_is_never_ignored);
  RUN_TEST(test_select_failure_backoff_is_bounded);
  RUN_TEST(test_greeting_then_request_in_separate_reads);
  RUN_TEST(test_greeting_split_one_byte_at_a_time);
  RUN_TEST(test_pipelined_greeting_and_connect_in_one_segment);
  RUN_TEST(test_pipelined_greeting_consumes_exactly_the_greeting_bytes);
  RUN_TEST(test_pipelined_domain_request_and_early_payload);
  RUN_TEST(test_unsupported_method_gets_ff_then_closes_after_flush);
  RUN_TEST(test_unsupported_command_gets_failure_reply);
  RUN_TEST(test_eof_before_a_complete_request_closes);
  RUN_TEST(test_transient_errno_on_a_handshake_read_does_not_close);
  RUN_TEST(test_greeting_deadline_5000ms);
  RUN_TEST(test_deadline_is_wrap_safe);
  RUN_TEST(test_request_deadline_counts_from_the_end_of_the_greeting);
  RUN_TEST(test_connect_timeout_replies_failure_then_closes);
  RUN_TEST(test_connect_failure_replies_and_closes);
  RUN_TEST(test_flush_deadline_closes_a_client_that_never_reads);
  RUN_TEST(test_stalled_client_does_not_block_a_second_client);
  RUN_TEST(test_pool_free_index_with_busy_slots);
  RUN_TEST(test_pool_evicts_oldest_stalled_handshake_only);
  RUN_TEST(test_pool_evict_age_is_wrap_safe);
  RUN_TEST(test_select_timeout_without_clients_blocks_on_the_listener);
  RUN_TEST(test_select_timeout_is_the_nearest_deadline);
  RUN_TEST(test_select_timeout_with_one_relaying_slot_is_not_a_5ms_poll);
  RUN_TEST(test_watch_list_skips_unused_and_adds_valid_fds);
  RUN_TEST(test_watch_list_never_contains_an_out_of_range_fd);
  RUN_TEST(test_watch_list_flags_a_bad_upstream_fd_while_connecting);
  RUN_TEST(test_listener_not_watched_when_pool_is_full);
  RUN_TEST(test_wants_follow_the_phase);
  RUN_TEST(test_relay_copies_both_ways);
  RUN_TEST(test_relay_backpressure_holds_reads_until_the_send_completes);
  RUN_TEST(test_client_fin_is_forwarded_after_pending_data_and_upstream_can_finish);
  RUN_TEST(test_stale_errno_in_relay_is_a_half_close_not_a_reset);
  RUN_TEST(test_half_close_has_a_deadline);
  RUN_TEST(test_idle_deadline_resets_on_activity);
  RUN_TEST(test_reset_in_relay_closes_immediately);
  RUN_TEST(test_transient_errno_in_relay_keeps_the_connection);
  RUN_TEST(test_force_close_records_the_reason_once);
  RUN_TEST(test_handshake_bytes_refresh_the_activity_clock);
  RUN_TEST(test_pool_evicts_by_idle_time_not_by_accept_age);
  RUN_TEST(test_half_close_deadline_is_inactivity_based);
  RUN_TEST(test_half_close_deadline_also_follows_send_progress);
  RUN_TEST(test_shutdown_toward_upstream_is_one_shot_across_later_events);
  RUN_TEST(test_shutdown_toward_client_is_one_shot_too);
  return UNITY_END();
}
