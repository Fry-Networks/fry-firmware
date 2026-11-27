// ScreenAnimator: 7 MinerStates, non-blocking tick, frame progression, distinct frames per state,
// zero heap growth after begin(), bounded per-tick work.
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unity.h>

#include <new>

#include "../../include/fry_touch_ui.h"
#include "../../lib/fry_ui/mem_canvas.h"

using namespace fry;
using namespace fry::ui;

// Global allocation counter (the whole test binary shares it; only the delta inside a window counts).
static unsigned long g_allocs = 0;
void* operator new(size_t n) {
  g_allocs++;
  void* p = malloc(n ? n : 1);
  if (!p) abort();
  return p;
}
void* operator new[](size_t n) {
  g_allocs++;
  void* p = malloc(n ? n : 1);
  if (!p) abort();
  return p;
}
void operator delete(void* p) noexcept { free(p); }
void operator delete[](void* p) noexcept { free(p); }
void operator delete(void* p, size_t) noexcept { free(p); }
void operator delete[](void* p, size_t) noexcept { free(p); }

static const MinerState kStates[7] = {MinerState::Boot,        MinerState::SetupAP,  MinerState::WifiConnecting,
                                      MinerState::Mining,      MinerState::HeartbeatOk, MinerState::OtaUpdating,
                                      MinerState::Error};

static MinerStatus mk(MinerState st) {
  MinerStatus s;
  memset(&s, 0, sizeof(s));
  s.state = st;
  strcpy(s.ssid, "HomeNet");
  strcpy(s.ip, "192.168.1.50");
  strcpy(s.apSsid, "FRY-Setup-A1B2");
  strcpy(s.apIp, "192.168.4.1");
  strcpy(s.fwVersion, "0.4.31");
  strcpy(s.otaStage, "download");
  s.otaPct = 40;
  s.rssi = -60;
  s.uptimeS = 3600;
  s.lastHeartbeatOk = true;
  s.errCode = 7;
  return s;
}

void setUp(void) {}
void tearDown(void) {}

void test_first_tick_draws_and_rate_caps() {
  disp::MemCanvas c(128, 64, true);
  ScreenAnimator a;
  a.begin(c, 10);  // 10 fps -> 100 ms
  MinerStatus s = mk(MinerState::Mining);
  TEST_ASSERT_TRUE(a.tick(1000, s));
  TEST_ASSERT_EQUAL_UINT32(1, a.framesDrawn());
  TEST_ASSERT_FALSE(a.tick(1040, s));
  TEST_ASSERT_FALSE(a.tick(1099, s));
  TEST_ASSERT_TRUE(a.tick(1100, s));
  TEST_ASSERT_EQUAL_UINT32(2, a.framesDrawn());
  TEST_ASSERT_TRUE(c.flushes() >= 2);
}

void test_state_change_redraws_immediately() {
  disp::MemCanvas c(128, 64, true);
  ScreenAnimator a;
  a.begin(c, 10);
  MinerStatus s = mk(MinerState::Mining);
  a.tick(1000, s);
  s.state = MinerState::Error;
  TEST_ASSERT_TRUE(a.tick(1010, s));
}

void test_distinct_frames_per_state_all_canvas_sizes() {
  const uint16_t dims[3][3] = {{128, 64, 1}, {128, 32, 1}, {240, 240, 0}};
  for (int d = 0; d < 3; d++) {
    uint32_t hashes[7];
    for (int i = 0; i < 7; i++) {
      disp::MemCanvas c(dims[d][0], dims[d][1], dims[d][2] != 0);
      ScreenAnimator a;
      a.begin(c, 10);
      MinerStatus s = mk(kStates[i]);
      TEST_ASSERT_TRUE(a.tick(1000, s));
      hashes[i] = c.hash();
      TEST_ASSERT_TRUE(c.countNonZero() > 0);
    }
    for (int i = 0; i < 7; i++)
      for (int j = i + 1; j < 7; j++) {
        char msg[64];
        snprintf(msg, sizeof(msg), "dim %d states %d/%d identical", d, i, j);
        TEST_ASSERT_TRUE_MESSAGE(hashes[i] != hashes[j], msg);
      }
  }
}

void test_frames_progress_within_each_state() {
  for (int i = 0; i < 7; i++) {
    disp::MemCanvas c(128, 64, true);
    ScreenAnimator a;
    a.begin(c, 10);
    MinerStatus s = mk(kStates[i]);
    uint32_t prev = 0;
    int distinctRuns = 0;
    for (int f = 0; f < 12; f++) {
      TEST_ASSERT_TRUE(a.tick(1000 + f * 100, s));
      const uint32_t h = c.hash();
      if (f > 0 && h != prev) distinctRuns++;
      prev = h;
    }
    char msg[48];
    snprintf(msg, sizeof(msg), "state %d does not animate", i);
    TEST_ASSERT_TRUE_MESSAGE(distinctRuns >= 10, msg);  // essentially every consecutive frame differs
  }
}

void test_text_content_per_state() {
  disp::MemCanvas c(240, 240, false);
  ScreenAnimator a;
  a.begin(c, 10);
  MinerStatus s = mk(MinerState::SetupAP);
  a.tick(1000, s);
  TEST_ASSERT_TRUE(c.hasText("FRY-Setup-A1B2"));
  s = mk(MinerState::OtaUpdating);
  a.tick(1200, s);
  TEST_ASSERT_TRUE(c.hasText("40%"));
  s = mk(MinerState::Error);
  a.tick(1400, s);
  TEST_ASSERT_TRUE(c.hasText("7"));
  s = mk(MinerState::Mining);
  a.tick(1600, s);
  TEST_ASSERT_TRUE(c.hasText("HomeNet"));
}

void test_zero_heap_after_begin() {
  disp::MemCanvas c(240, 240, false);
  ScreenAnimator a;
  a.begin(c, 20);
  MinerStatus s = mk(MinerState::Boot);
  const unsigned long before = g_allocs;
  uint32_t t = 1000;
  for (int i = 0; i < 700; i++) {
    s.state = kStates[(i / 100) % 7];
    t += 25;
    a.tick(t, s);
  }
  TEST_ASSERT_EQUAL_UINT32(0, (uint32_t)(g_allocs - before));
  TEST_ASSERT_TRUE(a.framesDrawn() > 300);
}

void test_tick_time_and_op_budget() {
  disp::MemCanvas c(240, 240, false);
  ScreenAnimator a;
  a.begin(c, 30);
  MinerStatus s = mk(MinerState::Mining);
  uint32_t maxOps = 0;
  long maxNs = 0;
  uint32_t t = 1000;
  for (int i = 0; i < 2100; i++) {
    s.state = kStates[(i / 300) % 7];
    t += 34;
    c.resetOps();
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    a.tick(t, s);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    const long ns = (t1.tv_sec - t0.tv_sec) * 1000000000L + (t1.tv_nsec - t0.tv_nsec);
    if (ns > maxNs) maxNs = ns;
    if (c.ops() > maxOps) maxOps = c.ops();
  }
  // Non-blocking: a full-screen frame on the host is well under 20 ms, and bounded draw calls.
  TEST_ASSERT_TRUE_MESSAGE(maxNs < 20L * 1000000L, "tick exceeded 20 ms");
  TEST_ASSERT_TRUE_MESSAGE(maxOps <= 120, "too many draw calls in one frame");
  // Between frames the tick is a no-op (no draw calls at all).
  c.resetOps();
  a.tick(t + 1, s);
  TEST_ASSERT_EQUAL_UINT32(0, c.ops());
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_first_tick_draws_and_rate_caps);
  RUN_TEST(test_state_change_redraws_immediately);
  RUN_TEST(test_distinct_frames_per_state_all_canvas_sizes);
  RUN_TEST(test_frames_progress_within_each_state);
  RUN_TEST(test_text_content_per_state);
  RUN_TEST(test_zero_heap_after_begin);
  RUN_TEST(test_tick_time_and_op_budget);
  return UNITY_END();
}
