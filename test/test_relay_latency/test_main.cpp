// lib/fry_core/relay_latency.h: the bounded ring of relay connect latencies and the two
// percentiles the installation heartbeat reports as relay_p50_ms / relay_p95_ms / relay_samples.
//
// Definitions pinned here (and in the header):
//   p50 = median: the middle value, or for an even count the mean of the two middle values,
//         truncated to whole milliseconds;
//   p95 = nearest-rank: sorted[ceil(0.95 * n) - 1];
//   no samples -> 0/0 with count 0, because the three heartbeat keys are unconditional (a reader
//         tells "no data" from "0 ms" by relay_samples == 0).
// The ring holds the last kLatencySamples (60) samples, so the buffer's cost is fixed.
#include <unity.h>

#include <cstdint>

#include "relay_latency.h"

using fry_relay::kLatencySamples;
using fry_relay::LatencyRing;

namespace {

uint32_t p50Of(const uint32_t* v, int n) {
  LatencyRing r;
  for (int i = 0; i < n; i++) r.add(v[i]);
  return r.p50Ms();
}

uint32_t p95Of(const uint32_t* v, int n) {
  LatencyRing r;
  for (int i = 0; i < n; i++) r.add(v[i]);
  return r.p95Ms();
}

void test_no_samples_reports_zero_and_a_zero_count() {
  LatencyRing r;
  TEST_ASSERT_EQUAL_UINT32(0, r.count());
  TEST_ASSERT_EQUAL_UINT32(0, r.p50Ms());
  TEST_ASSERT_EQUAL_UINT32(0, r.p95Ms());
}

void test_a_single_sample_is_both_percentiles() {
  LatencyRing r;
  r.add(37);
  TEST_ASSERT_EQUAL_UINT32(1, r.count());
  TEST_ASSERT_EQUAL_UINT32(37, r.p50Ms());
  TEST_ASSERT_EQUAL_UINT32(37, r.p95Ms());
}

void test_an_odd_count_takes_the_middle_value() {
  const uint32_t v[] = {30, 10, 20};  // unsorted on purpose
  TEST_ASSERT_EQUAL_UINT32(20, p50Of(v, 3));
  TEST_ASSERT_EQUAL_UINT32(30, p95Of(v, 3));
}

void test_an_even_count_averages_the_two_middle_values() {
  const uint32_t v[] = {10, 20, 30, 40};
  TEST_ASSERT_EQUAL_UINT32(25, p50Of(v, 4));  // (20 + 30) / 2
  TEST_ASSERT_EQUAL_UINT32(40, p95Of(v, 4));  // ceil(0.95 * 4) = 4 -> the largest
  const uint32_t w[] = {21, 20};              // (20 + 21) / 2 = 20.5 -> 20
  TEST_ASSERT_EQUAL_UINT32(20, p50Of(w, 2));
  TEST_ASSERT_EQUAL_UINT32(21, p95Of(w, 2));
  const uint32_t same[] = {7, 7, 7, 7};
  TEST_ASSERT_EQUAL_UINT32(7, p50Of(same, 4));
}

void test_p95_is_the_nearest_rank_not_an_interpolation() {
  // 20 samples: ceil(0.95 * 20) = 19 -> the 19th smallest, never the maximum.
  uint32_t v[20];
  for (int i = 0; i < 20; i++) v[i] = 100 + static_cast<uint32_t>(i);
  TEST_ASSERT_EQUAL_UINT32(118, p95Of(v, 20));
  // 10 samples: ceil(9.5) = 10 -> the maximum.
  uint32_t w[10];
  for (int i = 0; i < 10; i++) w[i] = 200 + static_cast<uint32_t>(i);
  TEST_ASSERT_EQUAL_UINT32(209, p95Of(w, 10));
  // 40 samples: ceil(38) = 38 -> 1-based rank 38, i.e. the 38th smallest.
  uint32_t x[40];
  for (int i = 0; i < 40; i++) x[i] = 300 + static_cast<uint32_t>(i);
  TEST_ASSERT_EQUAL_UINT32(337, p95Of(x, 40));
}

void test_a_full_sixty_sample_ring() {
  uint32_t v[kLatencySamples];
  for (int i = 0; i < kLatencySamples; i++) v[i] = static_cast<uint32_t>(i + 1);  // 1..60
  LatencyRing r;
  for (int i = 0; i < kLatencySamples; i++) r.add(v[i]);
  TEST_ASSERT_EQUAL_UINT32(kLatencySamples, r.count());
  TEST_ASSERT_EQUAL_UINT32(30, r.p50Ms());  // (30 + 31) / 2 = 30 (truncated)
  TEST_ASSERT_EQUAL_UINT32(57, r.p95Ms());  // ceil(57.0) = 57 -> sorted[56] = 57
}

void test_the_ring_keeps_only_the_newest_sixty_samples() {
  LatencyRing r;
  for (uint32_t i = 1; i <= 70; i++) r.add(i);
  TEST_ASSERT_EQUAL_UINT32(kLatencySamples, r.count());
  // 61..70 pushed 1..10 out: the ring now holds 11..70.
  TEST_ASSERT_EQUAL_UINT32(40, r.p50Ms());  // (40 + 41) / 2 = 40
  TEST_ASSERT_EQUAL_UINT32(67, r.p95Ms());  // 11 + 56
}

void test_insertion_order_does_not_change_the_percentiles() {
  uint32_t desc[10];
  uint32_t asc[10];
  for (int i = 0; i < 10; i++) {
    desc[i] = static_cast<uint32_t>(10 - i);  // 10..1
    asc[i] = static_cast<uint32_t>(i + 1);    // 1..10
  }
  TEST_ASSERT_EQUAL_UINT32(p50Of(asc, 10), p50Of(desc, 10));
  TEST_ASSERT_EQUAL_UINT32(p95Of(asc, 10), p95Of(desc, 10));
}

void test_reset_empties_the_ring() {
  LatencyRing r;
  r.add(5);
  r.add(9);
  r.reset();
  TEST_ASSERT_EQUAL_UINT32(0, r.count());
  TEST_ASSERT_EQUAL_UINT32(0, r.p50Ms());
  TEST_ASSERT_EQUAL_UINT32(0, r.p95Ms());
}

void test_extreme_values_do_not_overflow_the_average() {
  LatencyRing r;
  r.add(0xFFFFFFFFu);
  r.add(0xFFFFFFFFu);
  TEST_ASSERT_EQUAL_UINT32(0xFFFFFFFFu, r.p50Ms());
  r.reset();
  r.add(0);
  r.add(0xFFFFFFFFu);
  TEST_ASSERT_EQUAL_UINT32(0x7FFFFFFFu, r.p50Ms());  // (0 + 0xFFFFFFFF) / 2
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_no_samples_reports_zero_and_a_zero_count);
  RUN_TEST(test_a_single_sample_is_both_percentiles);
  RUN_TEST(test_an_odd_count_takes_the_middle_value);
  RUN_TEST(test_an_even_count_averages_the_two_middle_values);
  RUN_TEST(test_p95_is_the_nearest_rank_not_an_interpolation);
  RUN_TEST(test_a_full_sixty_sample_ring);
  RUN_TEST(test_the_ring_keeps_only_the_newest_sixty_samples);
  RUN_TEST(test_insertion_order_does_not_change_the_percentiles);
  RUN_TEST(test_reset_empties_the_ring);
  RUN_TEST(test_extreme_values_do_not_overflow_the_average);
  return UNITY_END();
}
