// The image download's floors are the whole-stream sweep data, not a number: this test holds that data (lo/c1-sw7 .. c1-sw11-all.lines.txt of the
// esp6 run; c1/reports/dl32ab2-floors.md) and checks that lib/fry_core/ota_heap_budget.h derives from it.
//
//   free: the session's use at the stream gate (held free - the last gate sample) of every stream-gate FAIL of dl-30, dl-31 and dl-32a2.
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

void test_free_need_is_worst_use_plus_the_stream_gate() {
  TEST_ASSERT_EQUAL_UINT32(budget::kDownloadSessionUsedWorst + budget::kStreamGateFree, budget::kDownloadNeedFree);
  // begin-time floor: need + margin
  const fry::TlsFloors f = fry::tlsFloorsAtBegin(budget::kDownloadGateFree, budget::kDownloadGateBlock, false);
  TEST_ASSERT_EQUAL_UINT32(25560 + 5376 + 4096, f.freeTotal);  // 35032
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
  // equal to its free, down to 29600 with free 30224): the corner (30096, 35032) is dominated by passing runs, never an untested combination.
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
  TEST_ASSERT_EQUAL_UINT32(41752, budget::kDownloadGateFree);
  TEST_ASSERT_EQUAL_UINT32(36816, budget::kDownloadGateBlock);
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_worst_session_use_is_the_largest_gate_sample);
  RUN_TEST(test_free_need_is_worst_use_plus_the_stream_gate);
  RUN_TEST(test_block_need_is_the_lowest_target_that_never_failed);
  RUN_TEST(test_failures_are_the_session_plus_both_buffers);
  RUN_TEST(test_gate_is_need_plus_margin_in_begin_units);
  RUN_TEST(test_gate_is_need_plus_4096_plus_thunk_and_clients);
  return UNITY_END();
}
