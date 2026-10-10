// INF-1: an aged WireGuard session must not read as "up" forever.
//
// Hardware root cause: esp_wireguard_peer_is_up() returns OK while EITHER the current or the
// previous keypair is valid, and the previous keypair is never expired once the current one is
// destroyed at ~180 s. A board whose session rekeyed before the hub removed its peer therefore
// reports up forever, WgRecover2 never sees up=false and never recovers.
//
// Real code under test: fry::wgPeerHealthy, fry::kWg2DeadAfterS and fry::WgRecover2::decide
// (lib/fry_core/wg_recover2.{h,cpp}). Modeled: ONLY the WireGuard library's verdict (libSaysUp)
// and the handshake age as the library would report them.
// Run the QA timer variant with: PLATFORMIO_BUILD_FLAGS=-DFRY_QA_COMPRESSED_TIMERS=1
#include <unity.h>

#include "wg_recover2.h"

using fry::WgRecover2;
using fry::WgRecover2Input;
using fry::WgRecoverAction;

void setUp() {}
void tearDown() {}

namespace {

constexpr uint32_t kThr = fry::kWg2DeadAfterS;

// Simulated board whose last handshake happened at t=0 and whose hub removed the peer: no new
// handshake ever arrives. The lib verdict is "up" the whole time (stale prev keypair still valid).
// Returns the first non-None action over `untilS` seconds of 5/kWg2TimerDiv-second ticks, with
// `useHelper` choosing between the fixed health check and the pre-fix lib-verdict-only check.
struct Fired { WgRecoverAction a = WgRecoverAction::None; uint32_t atS = 0; };
Fired walkAgedSession(bool useHelper, uint32_t sessionAgeAtStartS, uint32_t untilS) {
  WgRecover2 r;
  Fired f;
  const uint32_t step = 5 / fry::kWg2TimerDiv ? 5 / fry::kWg2TimerDiv : 1;
  for (uint32_t t = 0; t <= untilS; t += step) {
    const bool libSaysUp = true;
    const uint32_t age = sessionAgeAtStartS + t;
    const bool up = useHelper ? fry::wgPeerHealthy(libSaysUp, true, age) : libSaysUp;
    WgRecover2Input in;
    in.armed = true;
    in.up = up;
    in.wifiUp = true;
    in.nowMs = t * 1000;
    in.hostnameEndpoint = false;
    in.clockSynced = true;
    in.hostResolves = true;
    in.epochNow = 1790000000 + t;
    WgRecoverAction a = r.decide(in);
    if (a != WgRecoverAction::None) { f.a = a; f.atS = t; return f; }
  }
  return f;
}

}  // namespace

// (a) BUG CASE: lib says up (curr destroyed, prev valid), last handshake older than the threshold.
void test_bug_case_stale_prev_keypair_is_not_healthy() {
  TEST_ASSERT_FALSE(fry::wgPeerHealthy(true, true, kThr + 1));
  TEST_ASSERT_FALSE(fry::wgPeerHealthy(true, true, kThr + 300));
  TEST_ASSERT_FALSE(fry::wgPeerHealthy(true, true, 0xFFFFFFFFu));
}

// (b) a healthy board: lib up and a recent handshake.
void test_recent_handshake_is_healthy() {
  TEST_ASSERT_TRUE(fry::wgPeerHealthy(true, true, 0));
  TEST_ASSERT_TRUE(fry::wgPeerHealthy(true, true, 5 < kThr ? 5 : 0));
  TEST_ASSERT_TRUE(fry::wgPeerHealthy(true, true, kThr / 2));
}

// (c) boundary, from the constant (never a literal): healthy iff age < kWg2DeadAfterS.
void test_boundary_follows_dead_after_constant() {
  TEST_ASSERT_TRUE(kThr >= 2);
  TEST_ASSERT_TRUE(fry::wgPeerHealthy(true, true, kThr - 1));
  TEST_ASSERT_FALSE(fry::wgPeerHealthy(true, true, kThr));
  TEST_ASSERT_FALSE(fry::wgPeerHealthy(true, true, kThr + 1));
  TEST_ASSERT_EQUAL_UINT32(180 / fry::kWg2TimerDiv, kThr);  // 180 release, 18 QA
}

// (d) lib says down: never healthy, whatever the age; no handshake time: not healthy.
void test_lib_down_or_no_handshake_is_not_healthy() {
  TEST_ASSERT_FALSE(fry::wgPeerHealthy(false, true, 0));
  TEST_ASSERT_FALSE(fry::wgPeerHealthy(false, true, kThr - 1));
  TEST_ASSERT_FALSE(fry::wgPeerHealthy(false, true, kThr + 1));
  TEST_ASSERT_FALSE(fry::wgPeerHealthy(false, false, 0));
  TEST_ASSERT_FALSE(fry::wgPeerHealthy(true, false, 0));
}

// Aged session, hub removed the peer: the fixed check feeds decide() up=false once the handshake
// is >= kWg2DeadAfterS old, and decide() reaches a recover action; the pre-fix check never does.
void test_aged_session_reaches_recover_action() {
  const uint32_t horizon = 420 / fry::kWg2TimerDiv;  // the hardware observation window
  // Session already 150 s (QA: 15 s) old when the peer is removed.
  const uint32_t startAge = 150 / fry::kWg2TimerDiv;
  Fired pre = walkAgedSession(false, startAge, horizon);
  TEST_ASSERT_TRUE(pre.a == WgRecoverAction::None);  // pre-fix behaviour: stuck "up" forever
  Fired post = walkAgedSession(true, startAge, horizon);
  TEST_ASSERT_TRUE(post.a != WgRecoverAction::None);
  TEST_ASSERT_TRUE(post.atS <= horizon);
}

// A healthy board that keeps handshaking never recovers.
void test_young_sessions_never_recover() {
  WgRecover2 r;
  for (uint32_t t = 0; t <= 1000; t += 5) {
    WgRecover2Input in;
    in.armed = true;
    in.up = fry::wgPeerHealthy(true, true, t % (kThr / 2 + 1));  // re-handshakes keep age low
    in.wifiUp = true;
    in.nowMs = t * 1000;
    in.clockSynced = true;
    in.hostResolves = true;
    in.epochNow = 1790000000 + t;
    TEST_ASSERT_TRUE(r.decide(in) == WgRecoverAction::None);
  }
}

int main() {
  UNITY_BEGIN();
  RUN_TEST(test_bug_case_stale_prev_keypair_is_not_healthy);
  RUN_TEST(test_recent_handshake_is_healthy);
  RUN_TEST(test_boundary_follows_dead_after_constant);
  RUN_TEST(test_lib_down_or_no_handshake_is_not_healthy);
  RUN_TEST(test_aged_session_reaches_recover_action);
  RUN_TEST(test_young_sessions_never_recover);
  return UNITY_END();
}
