// readServerDetail() (src/core/hardwareapi_client.cpp) buffers a 4xx body only to quote the server's
// "detail"/"error" string. Which Content-Length is too big to buffer is a pure rule,
// fry::tooBigForServerDetail (lib/fry_core/reg_result.h): anything over 2048 bytes, and any
// negative size - HTTPClient reports -1 for a chunked body of unknown length, which getString()
// would buffer in full (round 2 F10). Boundaries pinned here: -1, 0, 2048, 2049.
#include <unity.h>

#include <climits>

#include "reg_result.h"

namespace {

void test_a_chunked_body_of_unknown_length_is_too_big() {
  TEST_ASSERT_TRUE(fry::tooBigForServerDetail(-1));
}

void test_any_negative_size_is_too_big() {
  TEST_ASSERT_TRUE(fry::tooBigForServerDetail(-2));
  TEST_ASSERT_TRUE(fry::tooBigForServerDetail(INT_MIN));
}

void test_an_empty_body_is_not_too_big() {
  TEST_ASSERT_FALSE(fry::tooBigForServerDetail(0));  // parsed (and rejected) as JSON, never buffered blind
}

void test_small_bodies_are_read() {
  TEST_ASSERT_FALSE(fry::tooBigForServerDetail(1));
  TEST_ASSERT_FALSE(fry::tooBigForServerDetail(2047));
}

void test_exactly_2048_bytes_is_still_read() {
  TEST_ASSERT_FALSE(fry::tooBigForServerDetail(2048));
}

void test_2049_bytes_is_too_big() {
  TEST_ASSERT_TRUE(fry::tooBigForServerDetail(2049));
  TEST_ASSERT_TRUE(fry::tooBigForServerDetail(INT_MAX));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_a_chunked_body_of_unknown_length_is_too_big);
  RUN_TEST(test_any_negative_size_is_too_big);
  RUN_TEST(test_an_empty_body_is_not_too_big);
  RUN_TEST(test_small_bodies_are_read);
  RUN_TEST(test_exactly_2048_bytes_is_still_read);
  RUN_TEST(test_2049_bytes_is_too_big);
  return UNITY_END();
}
