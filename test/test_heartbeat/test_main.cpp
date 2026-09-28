// Heartbeat bookkeeping (lib/fry_core/ota_health.*): the first hardwareapi HTTP response of ANY
// status proves the new image can reach the network and marks it valid - a 401 for a legacy key
// is an answer, and rolling back on it would put a working board back on old firmware. Only a 2xx
// counts toward the "hb" age the status surfaces report.
#include <unity.h>

#include "ota_health.h"

using fry::HeartbeatTracker;

namespace {

void test_nothing_seen_yet() {
  HeartbeatTracker hb;
  TEST_ASSERT_FALSE(hb.anyResponse());
  TEST_ASSERT_EQUAL_INT32(-1, hb.ageS(123456));
  TEST_ASSERT_EQUAL_INT(0, hb.lastHttp());
}

void test_transport_errors_are_not_heartbeats() {
  HeartbeatTracker hb;
  TEST_ASSERT_FALSE(hb.note(-1, 1000));
  TEST_ASSERT_FALSE(hb.note(0, 2000));
  TEST_ASSERT_FALSE(hb.anyResponse());
  TEST_ASSERT_EQUAL_INT32(-1, hb.ageS(3000));
}

void test_first_response_of_any_status_fires_exactly_once() {
  HeartbeatTracker hb;
  TEST_ASSERT_TRUE(hb.note(401, 5000));  // legacy key: still proves the network path
  TEST_ASSERT_TRUE(hb.anyResponse());
  TEST_ASSERT_FALSE(hb.note(503, 6000));
  TEST_ASSERT_FALSE(hb.note(202, 7000));
  TEST_ASSERT_EQUAL_INT(202, hb.lastHttp());
}

void test_age_counts_only_successes() {
  HeartbeatTracker hb;
  hb.note(500, 1000);
  TEST_ASSERT_EQUAL_INT32(-1, hb.ageS(2000));  // an answer, but not a heartbeat
  hb.note(200, 10000);
  TEST_ASSERT_EQUAL_INT32(0, hb.ageS(10999));
  TEST_ASSERT_EQUAL_INT32(5, hb.ageS(15000));
  hb.note(409, 20000);                         // a later failure does not reset the age
  TEST_ASSERT_EQUAL_INT32(15, hb.ageS(25000));
  hb.note(204, 30000);
  TEST_ASSERT_EQUAL_INT32(0, hb.ageS(30000));
}

void test_age_survives_millis_wraparound() {
  HeartbeatTracker hb;
  hb.note(200, 0xFFFFF000u);
  TEST_ASSERT_EQUAL_INT32(8, hb.ageS(3904u));  // 4096 ms to the wrap + 3904 ms after it
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_nothing_seen_yet);
  RUN_TEST(test_transport_errors_are_not_heartbeats);
  RUN_TEST(test_first_response_of_any_status_fires_exactly_once);
  RUN_TEST(test_age_counts_only_successes);
  RUN_TEST(test_age_survives_millis_wraparound);
  return UNITY_END();
}
