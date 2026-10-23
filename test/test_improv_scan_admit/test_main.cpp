// When an Improv "request scanned Wi-Fi networks" is answered (lib/fry_core/improv_scan.*).
//
// Before: any board that booted straight into its network (transport never started) answered the
// scan with Improv error 4, although Wi-Fi settings had been accepted in every phase since round 2
// F8, and a scan whose start failed was reported as an empty list. The rules below: a provisionable
// board always scans; a joined running board scans when the station is joined, at most every
// kRunningScanMinIntervalMs, and with a minimum contiguous heap block; a failed scan start or a
// failed scan is an error, not "no networks".
#include <unity.h>

#include <climits>

#include "improv_scan.h"

using fry::improv::admitScan;
using fry::improv::classifyScanPoll;
using fry::improv::classifyScanStart;
using fry::improv::kRunningScanMinIntervalMs;
using fry::improv::kScanFailed;
using fry::improv::kScanRunning;
using fry::improv::ScanAdmit;
using fry::improv::ScanPoll;
using fry::improv::ScanStart;

namespace {

const uint32_t kFloor = 6000;  // a stand-in for the glue's measured floor
const uint32_t kBlock = 20000;

void test_provisionable_board_always_scans() {
  // Not joined, no heap, a scan one tick ago: the provisionable path is not rate limited or gated.
  TEST_ASSERT_EQUAL(ScanAdmit::Run, admitScan(true, false, true, 1001, 1000, 0, kFloor));
  TEST_ASSERT_EQUAL(ScanAdmit::Run, admitScan(true, true, false, 0, 0, kBlock, kFloor));
}

void test_running_joined_first_scan_is_admitted() {
  TEST_ASSERT_EQUAL(ScanAdmit::Run, admitScan(false, true, false, 5000, 0, kBlock, kFloor));
}

void test_running_board_not_joined_is_refused() {
  // ConnectingWifi also has no transport; a scan then would disconnect the joining station.
  TEST_ASSERT_EQUAL(ScanAdmit::Refuse, admitScan(false, false, false, 5000, 0, kBlock, kFloor));
}

void test_running_scan_within_the_interval_is_refused() {
  TEST_ASSERT_EQUAL(ScanAdmit::Refuse, admitScan(false, true, true, 1000 + 1, 1000, kBlock, kFloor));
  TEST_ASSERT_EQUAL(ScanAdmit::Refuse,
                    admitScan(false, true, true, 1000 + kRunningScanMinIntervalMs - 1, 1000, kBlock,
                              kFloor));
}

void test_running_scan_at_the_interval_is_admitted() {
  TEST_ASSERT_EQUAL(ScanAdmit::Run, admitScan(false, true, true, 1000 + kRunningScanMinIntervalMs,
                                              1000, kBlock, kFloor));
}

void test_millis_wrap_does_not_lock_the_scan_out_or_skip_the_interval() {
  const unsigned long last = ULONG_MAX - 10;
  // 11 ms after the wrap is 12 ms since the scan: refused. A full interval later: admitted.
  TEST_ASSERT_EQUAL(ScanAdmit::Refuse, admitScan(false, true, true, 1, last, kBlock, kFloor));
  TEST_ASSERT_EQUAL(ScanAdmit::Run,
                    admitScan(false, true, true, kRunningScanMinIntervalMs, last, kBlock, kFloor));
}

void test_heap_floor_edge() {
  TEST_ASSERT_EQUAL(ScanAdmit::Run, admitScan(false, true, false, 5000, 0, kFloor, kFloor));
  TEST_ASSERT_EQUAL(ScanAdmit::Refuse, admitScan(false, true, false, 5000, 0, kFloor - 1, kFloor));
}

void test_esp8266_floor_is_the_measured_drop_plus_margin() {
  const uint32_t floor = fry::improv::kRunningScanMinBlockEsp8266;
  // Bench: ~146 bytes per result (3504 / 24 networks); up to 64 networks plus a 4096 margin is about
  // 13.4 KB, rounded up to 16384. The lowest block seen on a healthy running board was 29248.
  TEST_ASSERT_EQUAL_UINT32(16384, floor);
  TEST_ASSERT_TRUE(floor >= 64u * 146u + 4096u);
  TEST_ASSERT_TRUE(floor <= 29248u);
  TEST_ASSERT_EQUAL(ScanAdmit::Run, admitScan(false, true, false, 5000, 0, floor, floor));
  TEST_ASSERT_EQUAL(ScanAdmit::Refuse, admitScan(false, true, false, 5000, 0, floor - 1, floor));
  // The healthy running board (lowest block seen at a request: 29248) is never refused by it.
  TEST_ASSERT_EQUAL(ScanAdmit::Run, admitScan(false, true, false, 5000, 0, 29248, floor));
}

void test_failed_scan_start_is_not_a_started_scan() {
  TEST_ASSERT_EQUAL(ScanStart::Failed, classifyScanStart(kScanFailed));
  TEST_ASSERT_EQUAL(ScanStart::Started, classifyScanStart(kScanRunning));
  TEST_ASSERT_EQUAL(ScanStart::Started, classifyScanStart(0));
  TEST_ASSERT_EQUAL(ScanStart::Started, classifyScanStart(12));
}

void test_poll_failed_scan_is_an_error_not_zero_rows() {
  TEST_ASSERT_EQUAL(ScanPoll::Wait, classifyScanPoll(kScanRunning));
  TEST_ASSERT_EQUAL(ScanPoll::Failed, classifyScanPoll(kScanFailed));
  TEST_ASSERT_EQUAL(ScanPoll::Done, classifyScanPoll(0));
  TEST_ASSERT_EQUAL(ScanPoll::Done, classifyScanPoll(7));
}

void test_poll_zero_networks_on_a_joined_running_board_is_an_error() {
  TEST_ASSERT_EQUAL(ScanPoll::Failed, classifyScanPoll(0, true));
  TEST_ASSERT_EQUAL(ScanPoll::Done, classifyScanPoll(1, true));
  TEST_ASSERT_EQUAL(ScanPoll::Wait, classifyScanPoll(kScanRunning, true));
  TEST_ASSERT_EQUAL(ScanPoll::Failed, classifyScanPoll(kScanFailed, true));
  // A provisionable board's empty scan is a legitimate empty list.
  TEST_ASSERT_EQUAL(ScanPoll::Done, classifyScanPoll(0, false));
  TEST_ASSERT_EQUAL(ScanPoll::Done, classifyScanPoll(0));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main() {
  UNITY_BEGIN();
  RUN_TEST(test_provisionable_board_always_scans);
  RUN_TEST(test_running_joined_first_scan_is_admitted);
  RUN_TEST(test_running_board_not_joined_is_refused);
  RUN_TEST(test_running_scan_within_the_interval_is_refused);
  RUN_TEST(test_running_scan_at_the_interval_is_admitted);
  RUN_TEST(test_millis_wrap_does_not_lock_the_scan_out_or_skip_the_interval);
  RUN_TEST(test_heap_floor_edge);
  RUN_TEST(test_esp8266_floor_is_the_measured_drop_plus_margin);
  RUN_TEST(test_failed_scan_start_is_not_a_started_scan);
  RUN_TEST(test_poll_failed_scan_is_an_error_not_zero_rows);
  RUN_TEST(test_poll_zero_networks_on_a_joined_running_board_is_an_error);
  return UNITY_END();
}
