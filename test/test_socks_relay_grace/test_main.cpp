// lib/fry_core/socks_relay_core.*: the client's FIN waits a moment for the upstream's own FIN.
//
// When the client finishes first, the relay used to close() the upstream at once. A server that has
// not finished yet then gets an RST for everything it still sends (its TLS close_notify, the FIN
// itself): lwIP aborts a closed pcb on data. In a host simulation of the relay on the ESP-IDF lwIP
// that was two RSTs per session toward the upstream, where the old half-close ended every session
// with a plain FIN exchange. A close() cannot be made graceful, only a half-close can, and a
// half-close toward a peer that is still open is what corrupted the heap (see test_socks_relay_fin).
//
// So the relay now gives the upstream finGraceMs to finish on its own before the descriptor is
// closed. Servers that close right after the client's close_notify (TLS) end the session with FINs
// toward two peers that had already sent theirs: no RST, no TIME_WAIT pcb on the board. A server that
// waits for the FIN gets the old close() after the grace time. What the upstream sends during the
// grace is read and dropped, exactly what the close() used to discard.
#include <unity.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "socks_relay_core.h"

using namespace fry_relay;

namespace {

const Timing kT;

const uint8_t kGreet[3] = {0x05, 0x01, 0x00};
const uint8_t kConnV4[10] = {0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50};  // 1.2.3.4:80

void feed(Slot& s, Side from, const uint8_t* d, size_t n, uint32_t now) {
  size_t room = 0;
  uint8_t* dst = recvDest(s, from, room);
  TEST_ASSERT_TRUE_MESSAGE(room >= n, "recvDest offered too little room");
  memcpy(dst, d, n);
  onRecv(s, from, static_cast<long>(n), 0, now);
}

size_t drain(Slot& s, Side to, uint32_t now) {
  size_t len = 0;
  sendSrc(s, to, len);
  if (len == 0) return 0;
  onSend(s, to, static_cast<long>(len), 0, now);
  return len;
}

// A relaying slot, with the grace time the shim would copy from Timing.
void toRelay(Slot& s, uint32_t graceMs) {
  slotInit(s, 50, 0);
  feed(s, Side::Client, kGreet, sizeof(kGreet), 0);
  feed(s, Side::Client, kConnV4, sizeof(kConnV4), 0);
  onConnectStarted(s, 51, 0);
  onConnectResult(s, true, 0);
  drain(s, Side::Client, 0);
  TEST_ASSERT_EQUAL((int)Phase::Relay, (int)s.phase);
  s.finGraceMs = graceMs;
}

// ---- the decision ----------------------------------------------------------------------------

void test_the_defaults() {
  TEST_ASSERT_EQUAL_UINT32(500, kT.finGraceMs);
  Slot s;
  slotInit(s, 50, 0);
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(0, s.finGraceMs, "a slot has no grace until the shim sets one");
  TEST_ASSERT_FALSE(s.graceUp);
}

void test_without_a_grace_time_a_client_fin_is_a_close_at_once() {
  Slot s;
  toRelay(s, 0);
  onRecv(s, Side::Client, 0, 0, 100);
  TEST_ASSERT_EQUAL((int)FinAction::Close, (int)takeFinAction(s, Side::Up));
}

void test_a_client_fin_waits_for_the_upstreams_own_fin() {
  Slot s;
  toRelay(s, 1000);
  onRecv(s, Side::Client, 0, 0, 100);  // the client finished; the upstream is still open
  TEST_ASSERT_EQUAL((int)FinAction::None, (int)takeFinAction(s, Side::Up));
  TEST_ASSERT_EQUAL((int)FinAction::None, (int)takeFinAction(s, Side::Client));
  TEST_ASSERT_EQUAL((int)Phase::Relay, (int)s.phase);
  TEST_ASSERT_TRUE(s.graceUp);
  // select() must wake up when the grace ends, not later
  TEST_ASSERT_EQUAL_UINT32(1000, slotRemainingMs(s, kT, 100));
  TEST_ASSERT_EQUAL_UINT32(700, slotRemainingMs(s, kT, 400));
  TEST_ASSERT_EQUAL_UINT32(0, slotRemainingMs(s, kT, 1100));
}

void test_the_upstream_finishing_in_time_makes_the_teardown_graceful() {
  Slot s;
  toRelay(s, 1000);
  onRecv(s, Side::Client, 0, 0, 100);
  onRecv(s, Side::Up, 0, 0, 400);  // the server closes after the client's close_notify
  // both FINs now go toward peers that sent their own: plain half-closes, nothing is closed early
  TEST_ASSERT_EQUAL((int)FinAction::HalfClose, (int)takeFinAction(s, Side::Up));
  TEST_ASSERT_EQUAL((int)FinAction::HalfClose, (int)takeFinAction(s, Side::Client));
  TEST_ASSERT_TRUE(slotClosed(s));
  TEST_ASSERT_EQUAL((int)CloseReason::Done, (int)s.reason);
  TEST_ASSERT_FALSE(s.graceUp);
}

void test_when_the_grace_runs_out_the_upstream_is_closed_as_before() {
  Slot s;
  toRelay(s, 1000);
  onRecv(s, Side::Client, 0, 0, 100);
  onTimer(s, kT, 1099);
  TEST_ASSERT_EQUAL((int)FinAction::None, (int)takeFinAction(s, Side::Up));
  onTimer(s, kT, 1100);
  TEST_ASSERT_EQUAL((int)FinAction::Close, (int)takeFinAction(s, Side::Up));  // armed by the timer alone
  TEST_ASSERT_EQUAL((int)FinAction::None, (int)takeFinAction(s, Side::Up));   // one-shot
  TEST_ASSERT_FALSE(s.graceUp);
  onSideClosed(s, Side::Up, 1101);
  TEST_ASSERT_TRUE(slotClosed(s));
  TEST_ASSERT_EQUAL((int)CloseReason::Done, (int)s.reason);
  TEST_ASSERT_EQUAL((int)FinAction::HalfClose, (int)takeFinAction(s, Side::Client));  // the client's FIN was seen
}

void test_what_the_upstream_sends_during_the_grace_is_dropped() {
  Slot s;
  toRelay(s, 1000);
  onRecv(s, Side::Client, 0, 0, 100);
  const uint8_t alert[3] = {0x15, 0x03, 0x03};
  feed(s, Side::Up, alert, sizeof(alert), 200);
  size_t len = 99;
  sendSrc(s, Side::Client, len);
  TEST_ASSERT_EQUAL_MESSAGE(0, (int)len, "bytes read during the grace must not be queued for the client");
  TEST_ASSERT_FALSE(slotWants(s).clientWr);
  TEST_ASSERT_EQUAL_UINT32(200, s.lastActivityMs);  // it still counts as a byte that moved
  size_t room = 0;
  recvDest(s, Side::Up, room);
  TEST_ASSERT_TRUE_MESSAGE(room > 0, "the upstream keeps being read during the grace (its FIN is what is waited for)");
  onRecv(s, Side::Up, 0, 0, 300);
  TEST_ASSERT_EQUAL((int)FinAction::HalfClose, (int)takeFinAction(s, Side::Up));
  TEST_ASSERT_EQUAL((int)FinAction::HalfClose, (int)takeFinAction(s, Side::Client));
}

void test_data_read_after_the_grace_ran_out_but_before_the_close_is_still_dropped() {
  Slot s;
  toRelay(s, 1000);
  onRecv(s, Side::Client, 0, 0, 100);
  onTimer(s, kT, 1100);  // the FIN toward the upstream is armed, the shim has not carried it out yet
  const uint8_t late[4] = {1, 2, 3, 4};
  feed(s, Side::Up, late, sizeof(late), 1100);
  size_t len = 99;
  sendSrc(s, Side::Client, len);
  TEST_ASSERT_EQUAL_MESSAGE(0, (int)len, "a hole in the stream: bytes after dropped ones were forwarded");
  TEST_ASSERT_FALSE_MESSAGE(s.graceUp, "an armed FIN was deferred again by a later socket event");
  onTimer(s, kT, 1101);
  TEST_ASSERT_FALSE(s.graceUp);
  TEST_ASSERT_EQUAL((int)FinAction::Close, (int)takeFinAction(s, Side::Up));  // and the upstream is still open
}

void test_the_grace_starts_when_the_clients_last_bytes_are_out() {
  Slot s;
  toRelay(s, 1000);
  const uint8_t req[3] = {'G', 'E', 'T'};
  feed(s, Side::Client, req, sizeof(req), 90);
  onRecv(s, Side::Client, 0, 0, 100);  // FIN behind data that has not reached the upstream yet
  TEST_ASSERT_FALSE_MESSAGE(s.graceUp, "no grace while the client's data is still queued for the upstream");
  const uint8_t resp[2] = {'O', 'K'};
  feed(s, Side::Up, resp, sizeof(resp), 150);  // the upstream answers meanwhile: that is delivered
  size_t len = 0;
  sendSrc(s, Side::Client, len);
  TEST_ASSERT_EQUAL(2, (int)len);
  TEST_ASSERT_EQUAL(3, (int)drain(s, Side::Up, 160));
  TEST_ASSERT_TRUE(s.graceUp);
  TEST_ASSERT_EQUAL_UINT32(1000, slotRemainingMs(s, kT, 160));
  onTimer(s, kT, 1159);
  TEST_ASSERT_EQUAL((int)FinAction::None, (int)takeFinAction(s, Side::Up));
  onTimer(s, kT, 1160);
  TEST_ASSERT_EQUAL((int)FinAction::Close, (int)takeFinAction(s, Side::Up));
}

void test_an_upstream_fin_that_comes_first_is_still_a_close_toward_the_client() {
  Slot s;
  toRelay(s, 1000);
  onRecv(s, Side::Up, 0, 0, 100);  // upstream first: no grace on this side
  TEST_ASSERT_FALSE(s.graceUp);
  TEST_ASSERT_EQUAL((int)FinAction::Close, (int)takeFinAction(s, Side::Client));
}

void test_a_client_fin_after_the_upstream_fin_does_not_wait() {
  Slot s;
  toRelay(s, 1000);
  onRecv(s, Side::Up, 0, 0, 100);
  onRecv(s, Side::Client, 0, 0, 101);  // both finished before the shim acted on either
  TEST_ASSERT_FALSE(s.graceUp);
  TEST_ASSERT_EQUAL((int)FinAction::HalfClose, (int)takeFinAction(s, Side::Up));
  TEST_ASSERT_EQUAL((int)FinAction::HalfClose, (int)takeFinAction(s, Side::Client));
  TEST_ASSERT_TRUE(slotClosed(s));
}

void test_the_half_close_cutoff_still_applies_during_the_grace() {
  Timing t;
  t.finGraceMs = 100000;  // longer than halfCloseMs: the no-progress cutoff must win
  Slot s;
  toRelay(s, t.finGraceMs);
  onRecv(s, Side::Client, 0, 0, 100);
  onTimer(s, t, 100 + t.halfCloseMs);
  TEST_ASSERT_TRUE(slotClosed(s));
  TEST_ASSERT_EQUAL((int)CloseReason::HalfCloseTimeout, (int)s.reason);
}

// ---- whole sessions against a model of the shim's socket handling --------------------------------
//
// Same idea as test_socks_relay_fin, now with the grace on: peers finish at random moments, the model
// does what src/esp32/vpn_wireguard.cpp does (recv/send into the slot buffers, run the timer, carry
// out the armed FINs) and counts what the firmware depends on. A half-close toward a peer that has not
// sent FIN, a use of a closed descriptor, a session that never ends and lost or reordered data are all
// failures; the last two numbers show that both the graceful path and the fallback are exercised.

struct Rng {
  uint32_t x;
  explicit Rng(uint32_t seed) : x(seed * 2654435761u + 12345u) {}
  uint32_t next() {
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return x;
  }
  uint32_t below(uint32_t n) { return n ? next() % n : 0; }
};

struct Event {
  int step;
  size_t bytes;  // 0 = FIN
};

struct Peer {
  uint8_t tag = 0;
  std::deque<uint8_t> rx;
  std::vector<uint8_t> sentAll;
  std::vector<uint8_t> got;
  std::vector<Event> script;
  bool finDue = false;
  bool closed = false;
  int eofSeenAt = -1;
  int closedAt = -1;
};

struct Tally {
  int halfCloseOfOpenPeer = 0;
  int useAfterClose = 0;
  int sessions = 0;
  int unfinished = 0;
  int badStream = 0;
  int graceful = 0;   // ended without a close() of either side
  int fallback = 0;   // the upstream was closed after the grace
  int lateClose = 0;  // closed although the upstream's FIN had been there long enough to be read
};

void schedule(Peer& p, Rng& r, size_t total, int finAt) {
  size_t left = total;
  int chunks = 1 + static_cast<int>(r.below(3));
  for (int i = 0; i < chunks && left > 0; i++) {
    size_t n = (i == chunks - 1) ? left : 1 + r.below(static_cast<uint32_t>(left));
    p.script.push_back({1 + static_cast<int>(r.below(static_cast<uint32_t>(finAt))), n});
    left -= n;
  }
  p.script.push_back({finAt, 0});
}

void applyEvents(Peer& p, int step) {
  for (const Event& e : p.script) {
    if (e.step != step || p.closed) continue;
    if (e.bytes == 0) {
      p.finDue = true;
    } else {
      for (size_t i = 0; i < e.bytes; i++) {
        const uint8_t b = static_cast<uint8_t>(p.tag * 37 + p.sentAll.size() * 7);
        p.sentAll.push_back(b);
        p.rx.push_back(b);
      }
    }
  }
}

void relayRecv(Slot& s, Peer& p, Side from, int step, Rng& r, Tally& t) {
  size_t room = 0;
  uint8_t* dst = recvDest(s, from, room);
  if (room == 0) return;
  if (p.closed) {
    t.useAfterClose++;
    return;
  }
  if (!p.rx.empty()) {
    const size_t n = std::min<size_t>(std::min(room, p.rx.size()), 1 + r.below(static_cast<uint32_t>(room)));
    for (size_t i = 0; i < n; i++) {
      dst[i] = p.rx.front();
      p.rx.pop_front();
    }
    onRecv(s, from, static_cast<long>(n), 0, static_cast<uint32_t>(step));
  } else if (p.finDue) {
    if (p.eofSeenAt < 0) p.eofSeenAt = step;
    onRecv(s, from, 0, ECONNRESET /* stale errno: must be ignored */, static_cast<uint32_t>(step));
  } else {
    onRecv(s, from, -1, EAGAIN, static_cast<uint32_t>(step));
  }
}

void relaySend(Slot& s, Peer& p, Side to, int step, Rng& r, Tally& t) {
  size_t len = 0;
  const uint8_t* src = sendSrc(s, to, len);
  if (len == 0) return;
  if (p.closed) {
    t.useAfterClose++;
    return;
  }
  if (r.below(5) == 0) {
    onSend(s, to, -1, EAGAIN, static_cast<uint32_t>(step));
    return;
  }
  const size_t n = 1 + r.below(static_cast<uint32_t>(len));
  p.got.insert(p.got.end(), src, src + n);
  onSend(s, to, static_cast<long>(n), 0, static_cast<uint32_t>(step));
}

void relayFin(Slot& s, Peer& p, Side side, int step, Tally& t, bool& anyClose) {
  int& fd = side == Side::Client ? s.clientFd : s.upFd;
  const uint32_t now = static_cast<uint32_t>(step);
  switch (takeFinAction(s, side)) {
    case FinAction::None:
      break;
    case FinAction::HalfClose:
      if (fd >= 0) {
        if (p.closed) t.useAfterClose++;
        else if (!p.finDue) t.halfCloseOfOpenPeer++;
      }
      break;
    case FinAction::Close:
      anyClose = true;
      if (fd >= 0) {
        if (side == Side::Up && p.finDue && p.eofSeenAt >= 0 && p.eofSeenAt < step) t.lateClose++;
        p.rx.clear();
        p.closed = true;
        p.closedAt = step;
        fd = kNoFd;
      }
      onSideClosed(s, side, now);
      break;
  }
}

bool isPrefix(const std::vector<uint8_t>& a, const std::vector<uint8_t>& full) {
  return a.size() <= full.size() && std::equal(a.begin(), a.end(), full.begin());
}

constexpr uint32_t kModelGrace = 40;

// finAfterTimer: carry out the armed FINs right after onTimer (what the glue does) as well as after the
// socket pass; without it a FIN armed by the timer waits until the end of the step. The core must not
// let a hole into the stream either way.
void runSession(uint32_t seed, bool finAfterTimer, Tally& t) {
  Rng r(seed);
  Peer cl, up;
  cl.tag = 1;
  up.tag = 2;
  const int clFin = 3 + static_cast<int>(r.below(80));
  const int upFin = 3 + static_cast<int>(r.below(160));  // often later than clFin + grace: the fallback
  schedule(cl, r, r.below(3000), clFin);
  schedule(up, r, r.below(3000), upFin);

  Slot s;
  toRelay(s, kModelGrace);
  Timing tm;
  tm.finGraceMs = kModelGrace;
  bool ended = false, anyClose = false;
  for (int step = 1; step <= 6000 && !ended; step++) {
    applyEvents(cl, step);
    applyEvents(up, step);
    onTimer(s, tm, static_cast<uint32_t>(step));
    if (finAfterTimer) {
      relayFin(s, up, Side::Up, step, t, anyClose);
      relayFin(s, cl, Side::Client, step, t, anyClose);
    }
    if (!slotClosed(s)) {
      relayRecv(s, cl, Side::Client, step, r, t);
      relaySend(s, up, Side::Up, step, r, t);
      relayRecv(s, up, Side::Up, step, r, t);
      relaySend(s, cl, Side::Client, step, r, t);
    }
    // the FINs run after the timer and the socket pass, whether or not a socket was ready
    relayFin(s, up, Side::Up, step, t, anyClose);
    relayFin(s, cl, Side::Client, step, t, anyClose);
    ended = slotClosed(s);
  }
  t.sessions++;
  if (!ended) {
    t.unfinished++;
    return;
  }
  if (!isPrefix(up.got, cl.sentAll) || !isPrefix(cl.got, up.sentAll)) t.badStream++;
  const bool clientFirst = cl.eofSeenAt >= 0 && (up.eofSeenAt < 0 || cl.eofSeenAt <= up.eofSeenAt);
  const bool upFirst = up.eofSeenAt >= 0 && (cl.eofSeenAt < 0 || up.eofSeenAt < cl.eofSeenAt);
  if (clientFirst && up.got != cl.sentAll) t.badStream++;
  if (upFirst && cl.got != up.sentAll) t.badStream++;
  if (!anyClose) t.graceful++;
  if (clientFirst && up.closed) t.fallback++;
}

Tally runMany(int n, bool finAfterTimer) {
  Tally t;
  for (int i = 0; i < n; i++) runSession(5000u + static_cast<uint32_t>(i), finAfterTimer, t);
  return t;
}

void checkModel(const Tally& t) {
  TEST_ASSERT_EQUAL(3000, t.sessions);
  TEST_ASSERT_EQUAL_MESSAGE(0, t.halfCloseOfOpenPeer, "shutdown(SHUT_WR) toward a peer that had not sent FIN");
  TEST_ASSERT_EQUAL_MESSAGE(0, t.useAfterClose, "a closed descriptor was used again");
  TEST_ASSERT_EQUAL_MESSAGE(0, t.unfinished, "a session never ended");
  TEST_ASSERT_EQUAL_MESSAGE(0, t.badStream, "data lost, duplicated or reordered");
  TEST_ASSERT_EQUAL_MESSAGE(0, t.lateClose, "closed although the upstream's FIN was already there");
}

void test_sessions_with_a_grace_never_half_close_an_open_peer() { checkModel(runMany(3000, true)); }

void test_sessions_with_a_grace_are_safe_when_the_timers_fin_waits_for_the_socket_pass() {
  checkModel(runMany(3000, false));
}

void test_the_model_exercises_both_the_graceful_path_and_the_fallback() {
  const Tally t = runMany(3000, true);
  TEST_ASSERT_TRUE_MESSAGE(t.graceful > 300, "no session ended gracefully");
  TEST_ASSERT_TRUE_MESSAGE(t.fallback > 300, "the fallback close after the grace never ran");
}

// ---- the glue ------------------------------------------------------------------------------------
// src/esp32/vpn_wireguard.cpp needs lwIP and the Arduino core, so the native tests cannot run it; what
// the grace needs from it is read off the source: a FIN armed by the timer is carried out right after
// the timers ran (no socket event wakes the slot then), and each new slot gets its grace time.

bool readFile(const std::string& path, std::string& out) {
  std::ifstream f(path.c_str(), std::ios::in | std::ios::binary);
  if (!f) return false;
  std::ostringstream ss;
  ss << f.rdbuf();
  out = ss.str();
  return !out.empty();
}

bool loadRelaySource(std::string& out) {
  const std::string rel = "src/esp32/vpn_wireguard.cpp";
  const std::string self = __FILE__;
  const std::string tail = "test/test_socks_relay_grace/test_main.cpp";
  std::vector<std::string> prefixes;
  if (self.size() >= tail.size() && self.compare(self.size() - tail.size(), tail.size(), tail) == 0) {
    prefixes.push_back(self.substr(0, self.size() - tail.size()));
  }
  const char* ups[] = {"", "../", "../../", "../../../", "../../../../"};
  for (size_t i = 0; i < sizeof(ups) / sizeof(ups[0]); i++) prefixes.push_back(ups[i]);
  for (size_t i = 0; i < prefixes.size(); i++) {
    if (readFile(prefixes[i] + rel, out)) return true;
  }
  return false;
}

void test_the_glue_carries_out_the_fins_the_timer_armed() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadRelaySource(src), "cannot read src/esp32/vpn_wireguard.cpp");
  const size_t t = src.find("onTimer(*slots[i], timing, now);");
  TEST_ASSERT_TRUE_MESSAGE(t != std::string::npos, "the relay loop no longer runs onTimer for each slot");
  // the release loop that follows must come after the FINs, or a closed slot would be released first
  const size_t rel = src.find("releaseSlot(slots[i], st);", t);
  TEST_ASSERT_TRUE_MESSAGE(rel != std::string::npos, "no slot release after the timers");
  const std::string between = src.substr(t, rel - t);
  TEST_ASSERT_TRUE_MESSAGE(between.find("forwardFin(*slots[i], Side::Up") != std::string::npos,
                           "no forwardFin(Up) between onTimer and the slot release");
  TEST_ASSERT_TRUE_MESSAGE(between.find("forwardFin(*slots[i], Side::Client") != std::string::npos,
                           "no forwardFin(Client) between onTimer and the slot release");
}

void test_the_glue_gives_each_slot_the_grace_time() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadRelaySource(src), "cannot read src/esp32/vpn_wireguard.cpp");
  TEST_ASSERT_TRUE_MESSAGE(src.find("->finGraceMs = Timing().finGraceMs;") != std::string::npos,
                           "the accepted slot does not get Timing::finGraceMs");
  // the bench switch that restores the old behaviour must also switch the grace off
  const size_t g = src.find("->finGraceMs = Timing().finGraceMs;");
  const size_t hc = src.rfind("FRY_RELAY_HALFCLOSE", g);
  TEST_ASSERT_TRUE_MESSAGE(hc != std::string::npos && g - hc < 400, "the grace is not tied to FRY_RELAY_HALFCLOSE");
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_defaults);
  RUN_TEST(test_without_a_grace_time_a_client_fin_is_a_close_at_once);
  RUN_TEST(test_a_client_fin_waits_for_the_upstreams_own_fin);
  RUN_TEST(test_the_upstream_finishing_in_time_makes_the_teardown_graceful);
  RUN_TEST(test_when_the_grace_runs_out_the_upstream_is_closed_as_before);
  RUN_TEST(test_what_the_upstream_sends_during_the_grace_is_dropped);
  RUN_TEST(test_data_read_after_the_grace_ran_out_but_before_the_close_is_still_dropped);
  RUN_TEST(test_the_grace_starts_when_the_clients_last_bytes_are_out);
  RUN_TEST(test_an_upstream_fin_that_comes_first_is_still_a_close_toward_the_client);
  RUN_TEST(test_a_client_fin_after_the_upstream_fin_does_not_wait);
  RUN_TEST(test_the_half_close_cutoff_still_applies_during_the_grace);
  RUN_TEST(test_sessions_with_a_grace_never_half_close_an_open_peer);
  RUN_TEST(test_sessions_with_a_grace_are_safe_when_the_timers_fin_waits_for_the_socket_pass);
  RUN_TEST(test_the_model_exercises_both_the_graceful_path_and_the_fallback);
  RUN_TEST(test_the_glue_carries_out_the_fins_the_timer_armed);
  RUN_TEST(test_the_glue_gives_each_slot_the_grace_time);
  return UNITY_END();
}
