// The image download's floors are the whole-stream sweep data, not a number: this test holds that data (lo/c1-sw7 .. c1-sw11-all.lines.txt of the
// esp6 run; c1/reports/dl32ab2-floors.md) and checks that lib/fry_core/ota_heap_budget.h derives from it.
//
//   free: the session's use at the stream gate (held free - the last gate sample) of every stream-gate FAIL of dl-30, dl-31 and dl-32a2, and the
//         PEAK use (held free - min_free over the whole stream) of every PASS of dl-32a2 and dl-32b2; the need is the larger, the PASS peak.
//   blk:  dl-32b2 held total free at 32400 and stepped the largest block only; its outcome per target, and what a failure is made of.
#include <unity.h>

#include <cstdint>

#include "ota_heap_budget.h"

namespace budget = fry::ota_heap;

namespace {

// 18 stream-gate FAILs: session use at the gate, and how many attempts showed it (dl-30 attempts 4..12, dl-31 attempts 4..9, dl-32a2 37, 38, 39, 42).
struct Used {
  uint32_t used;
  int count;
};
const Used kGateUsed[] = {{25120, 10}, {25144, 4}, {25560, 4}};

// 61 PASSes (full 1387 KB stream to the sha256 check): free held at the download's begin, the lowest free seen during the stream (min_free of the
// RESULT line), and how many attempts showed that pair. dl-32a2 (lo/c1-sw10-all.lines.txt, 38 PASS) then dl-32b2 (lo/c1-sw11-all.lines.txt, 23 PASS).
// The worst is dl-32b2 attempt 3 (target 30000): 32400 - 936 = 31464. dl-30/dl-31 did not log the whole-stream min_free in the RESULT line.
struct Peak {
  uint32_t heldFree;
  uint32_t minFree;
  int count;
};
const Peak kPassPeaks[] = {
    {30216, 2920, 1}, {30224, 512, 1}, {30616, 1504, 1}, {30616, 2192, 1}, {30616, 2512, 1}, {30816, 1456, 1}, {30816, 1728, 1}, {30816, 2712, 1},
    {31016, 1368, 1}, {31016, 1480, 1}, {31016, 2912, 1}, {31016, 3384, 1}, {31024, 3368, 1}, {31216, 1152, 1}, {31216, 1952, 1}, {31216, 2016, 1},
    {31216, 3256, 1}, {31216, 3568, 1}, {31216, 3584, 1}, {31416, 1640, 1}, {31416, 1992, 1}, {31416, 2144, 1}, {31416, 2424, 1}, {31416, 3312, 1},
    {31416, 3792, 1}, {31616, 1952, 1}, {31616, 2040, 1}, {31616, 2080, 1}, {31616, 3000, 1}, {31616, 3280, 1}, {31616, 3880, 1}, {31816, 2568, 1},
    {31816, 3464, 1}, {31816, 3664, 1}, {32016, 2520, 1}, {32016, 4144, 1}, {32016, 4392, 1}, {33168, 5512, 1},
    {32400, 936, 1}, {32400, 968, 1}, {32400, 1336, 1}, {32400, 1920, 1}, {32400, 4272, 2}, {32400, 4496, 1}, {32400, 4528, 1}, {32400, 4552, 1},
    {32400, 4664, 2}, {32400, 4728, 3}, {32400, 4744, 1}, {32400, 4752, 1}, {32400, 4768, 2}, {32400, 4776, 2}, {32408, 4784, 1}, {32424, 2568, 1},
    {32728, 2360, 1},
};

// dl-32b2, free held at 32400: per largest-block target, attempts and passes. Failures: 25000 rep 0 no-buffer (stage 3), 24000 rep 0 and
// 22000 reps 0, 1 Update.begin (stage 2); 20000 both attempts GET -1.
struct Step {
  uint32_t target;
  int attempts;
  int passes;
  uint32_t postBlk;  // the largest block after the GET at that target (every row of the target showed the same value for the ones below 27000)
};
const Step kBlkSteps[] = {{31000, 3, 3, 0}, {30000, 3, 3, 0}, {29000, 3, 3, 0}, {28000, 3, 3, 0}, {27000, 3, 3, 0},
                          {26000, 3, 3, 5848}, {25000, 3, 2, 4848}, {24000, 3, 2, 3848}, {22000, 3, 1, 1848}, {20000, 2, 0, 0}};

// What the download allocates after the GET, from Updater.cpp:172-177 and ota_client.cpp (a 1024 B buffer, new(nothrow)), in umm_malloc blocks
// (request + 4 B header, rounded up to 8).
constexpr uint32_t kUpdaterBigBuffer = 4096 + 8;
constexpr uint32_t kDownloadBuffer = 1024 + 8;

}  // namespace

void setUp() {}
void tearDown() {}

void test_worst_session_use_is_the_largest_gate_sample() {
  uint32_t worst = 0;
  int rows = 0;
  for (const Used& u : kGateUsed) {
    if (u.used > worst) worst = u.used;
    rows += u.count;
  }
  TEST_ASSERT_EQUAL_INT(18, rows);
  TEST_ASSERT_EQUAL_UINT32(worst, budget::kDownloadSessionUsedWorst);
}

// The free need is the worst PASS peak of the whole-stream sweeps, read straight from the table, not a sum of the gate-time use and the stream gate.
void test_free_need_is_the_worst_pass_peak() {
  uint32_t worst = 0;
  uint32_t worstHeld = 0;
  uint32_t worstMin = 0;
  int passes = 0;
  for (const Peak& p : kPassPeaks) {
    TEST_ASSERT_TRUE_MESSAGE(p.heldFree > p.minFree, "a PASS cannot use more than it was given");
    const uint32_t used = p.heldFree - p.minFree;
    if (used > worst) {
      worst = used;
      worstHeld = p.heldFree;
      worstMin = p.minFree;
    }
    passes += p.count;
  }
  TEST_ASSERT_EQUAL_INT(61, passes);
  TEST_ASSERT_EQUAL_UINT32(31464, worst);
  TEST_ASSERT_EQUAL_UINT32(32400, worstHeld);
  TEST_ASSERT_EQUAL_UINT32(936, worstMin);
  TEST_ASSERT_EQUAL_UINT32(worst, budget::kDownloadPeakUsed);
  TEST_ASSERT_EQUAL_UINT32(worstHeld, budget::kDownloadPeakHeldFree);
  TEST_ASSERT_EQUAL_UINT32(worstMin, budget::kDownloadPeakMinFree);
  TEST_ASSERT_EQUAL_UINT32(worst, budget::kDownloadNeedFree);
  // it is the stricter of the two readings: above the gate-time use + the stream gate (30936), which it replaces
  TEST_ASSERT_TRUE(budget::kDownloadNeedFree > budget::kDownloadSessionUsedWorst + budget::kStreamGateFree);
  // begin-time floor: need + margin
  const fry::TlsFloors f = fry::tlsFloorsAtBegin(budget::kDownloadGateFree, budget::kDownloadGateBlock, false);
  TEST_ASSERT_EQUAL_UINT32(31464 + 4096, f.freeTotal);  // 35560
}

void test_block_need_is_the_lowest_target_that_never_failed() {
  uint32_t lowestClean = 0;
  for (const Step& s : kBlkSteps) {
    if (s.passes == s.attempts) {
      lowestClean = s.target;
    } else {
      break;  // the table is in descending target order: the first target that failed ends the clean run
    }
  }
  TEST_ASSERT_EQUAL_UINT32(lowestClean, budget::kDownloadNeedBlk);
  uint32_t firstFail = 0;
  for (const Step& s : kBlkSteps) {
    if (s.passes != s.attempts) {
      firstFail = s.target;
      break;
    }
  }
  TEST_ASSERT_EQUAL_UINT32(firstFail, budget::kDownloadFailBlk);
  const fry::TlsFloors f = fry::tlsFloorsAtBegin(budget::kDownloadGateFree, budget::kDownloadGateBlock, false);
  TEST_ASSERT_EQUAL_UINT32(26000 + 4096, f.block);  // 30096
}

// Every failure is the session plus the 4096 B Updater buffer plus the 1024 B buffer not fitting in the held block: the targets at which the post-GET
// block is below that sum are exactly the ones that failed, and the sum is what the need derives from.
void test_failures_are_the_session_plus_both_buffers() {
  const uint32_t needAfterGet = kUpdaterBigBuffer + kDownloadBuffer;  // 5136
  TEST_ASSERT_EQUAL_UINT32(25288, budget::kDownloadSessionBlkTaken + needAfterGet);
  for (const Step& s : kBlkSteps) {
    if (s.postBlk == 0) continue;
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(s.target - budget::kDownloadSessionBlkTaken, s.postBlk, "post-GET block = target - what the session takes");
    const bool fitsBoth = s.postBlk >= needAfterGet;
    TEST_ASSERT_EQUAL_INT_MESSAGE(fitsBoth ? 1 : 0, s.passes == s.attempts ? 1 : 0, "a target fails exactly when the 4096 B path cannot fit both buffers");
  }
  // 20000 is below the session itself: GET -1
  TEST_ASSERT_TRUE(20000 < budget::kDownloadSessionBlkTaken);
  TEST_ASSERT_TRUE(budget::kDownloadNeedBlk >= budget::kDownloadSessionBlkTaken + needAfterGet);
}

// The gate is above both measured needs by the margin in begin-time units, so a heap that passes it passes every sweep row.
void test_gate_is_need_plus_margin_in_begin_units() {
  const fry::TlsFloors f = fry::tlsFloorsAtBegin(budget::kDownloadGateFree, budget::kDownloadGateBlock, false);
  TEST_ASSERT_EQUAL_UINT32(budget::kDownloadNeedBlk + budget::kMarginBytes, f.block);
  TEST_ASSERT_EQUAL_UINT32(budget::kDownloadNeedFree + budget::kMarginBytes, f.freeTotal);
  // a heap exactly at the floors is above every sweep row on BOTH axes (dl-32b2 ran at free 32400 with blocks down to 26000; dl-32a2 at blocks
  // equal to its free, down to 29600 with free 30224): the corner (30096, 35560) is dominated by passing runs, never an untested combination.
  TEST_ASSERT_TRUE(f.freeTotal > 32400);
  TEST_ASSERT_TRUE(f.block > 29600);
}

// The shipped gate is derived from the named needs with the literal 4096 margin, the BearSSL thunk and the clients block, never typed in: the same
// derivation as the static_asserts in ota_heap_budget.h, with the margin as a literal so a change of kMarginBytes cannot move both sides.
void test_gate_is_need_plus_4096_plus_thunk_and_clients() {
  TEST_ASSERT_EQUAL_UINT32(budget::kDownloadNeedFree + 4096 + fry::kBearsslStackThunkBytes + fry::kOtaClientsBytes, budget::kDownloadGateFree);
  TEST_ASSERT_EQUAL_UINT32(budget::kDownloadNeedBlk + 4096 + fry::kBearsslStackThunkBytes + fry::kOtaClientsBytes, budget::kDownloadGateBlock);
  TEST_ASSERT_EQUAL_UINT32(6208, fry::kBearsslStackThunkBytes);
  TEST_ASSERT_EQUAL_UINT32(512, fry::kOtaClientsBytes);
  TEST_ASSERT_EQUAL_UINT32(42280, budget::kDownloadGateFree);
  TEST_ASSERT_EQUAL_UINT32(36816, budget::kDownloadGateBlock);
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_worst_session_use_is_the_largest_gate_sample);
  RUN_TEST(test_free_need_is_the_worst_pass_peak);
  RUN_TEST(test_block_need_is_the_lowest_target_that_never_failed);
  RUN_TEST(test_failures_are_the_session_plus_both_buffers);
  RUN_TEST(test_gate_is_need_plus_margin_in_begin_units);
  RUN_TEST(test_gate_is_need_plus_4096_plus_thunk_and_clients);
  return UNITY_END();
}
