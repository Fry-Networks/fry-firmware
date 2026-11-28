// T-ESP: RFC3339 UTC formatting without libc strftime.
//
// strftime() was linked only by src/core/telemetry.cpp and dragged libc's timelocal.o (~551 B of DRAM .rodata) plus strftime.o (~89 B)
// into the ESP8266 image: ~640 B of static RAM that the OTA download's TLS session wants as heap. lib/fry_core/iso8601_utc.h formats the same
// "%Y-%m-%dT%H:%M:%SZ" text from epoch seconds with integer arithmetic. This test pins its output against the C library on the host
// (gmtime_r + strftime, the exact code it replaces) and pins that telemetry.cpp no longer calls strftime.
#include <unity.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <time.h>

#include "iso8601_utc.h"

namespace {

std::string viaLibc(int64_t secs) {
  time_t t = static_cast<time_t>(secs);
  struct tm tmv;
  gmtime_r(&t, &tmv);
  char buf[32];
  size_t n = strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tmv);
  return std::string(buf, n);
}

std::string viaFry(int64_t secs) {
  char buf[32];
  size_t n = fry::formatIso8601Utc(secs, buf, sizeof buf);
  return std::string(buf, n);
}

}  // namespace

void test_known_instants() {
  TEST_ASSERT_EQUAL_STRING("1970-01-01T00:00:00Z", viaFry(0).c_str());
  TEST_ASSERT_EQUAL_STRING("2000-02-29T12:34:56Z", viaFry(951827696).c_str());
  TEST_ASSERT_EQUAL_STRING("2038-01-19T03:14:07Z", viaFry(2147483647LL).c_str());
  TEST_ASSERT_EQUAL_STRING("2100-03-01T00:00:00Z", viaFry(4107542400LL).c_str());
}

void test_matches_libc_across_a_sweep() {
  // Leap days, century rules, month/year boundaries: step by a prime so every field wraps.
  for (int64_t s = 1600000000LL; s < 4200000000LL; s += 10000019LL) {
    TEST_ASSERT_EQUAL_STRING(viaLibc(s).c_str(), viaFry(s).c_str());
  }
  const int64_t edges[] = {1709164799LL, 1709164800LL, 1709251200LL, 951782399LL, 951782400LL, 4102444799LL, 4102444800LL, 1735689599LL, 1735689600LL};
  for (size_t i = 0; i < sizeof(edges) / sizeof(edges[0]); i++) {
    TEST_ASSERT_EQUAL_STRING(viaLibc(edges[i]).c_str(), viaFry(edges[i]).c_str());
  }
}

void test_buffer_too_small_is_refused() {
  char buf[20];  // needs 21 (20 chars + NUL)
  memset(buf, 'x', sizeof buf);
  TEST_ASSERT_EQUAL_UINT32(0, fry::formatIso8601Utc(1700000000LL, buf, sizeof buf));
  TEST_ASSERT_EQUAL_UINT32(0, fry::formatIso8601Utc(1700000000LL, nullptr, 32));
  char ok[21];
  TEST_ASSERT_EQUAL_UINT32(20, fry::formatIso8601Utc(1700000000LL, ok, sizeof ok));
  TEST_ASSERT_EQUAL_STRING("2023-11-14T22:13:20Z", ok);
}

void test_negative_is_refused() {
  char buf[32];
  TEST_ASSERT_EQUAL_UINT32(0, fry::formatIso8601Utc(-1, buf, sizeof buf));
}

void test_telemetry_no_longer_calls_strftime() {
  std::ifstream f("src/core/telemetry.cpp");
  if (!f) f.open("../src/core/telemetry.cpp");
  TEST_ASSERT_TRUE_MESSAGE(f.good(), "cannot read src/core/telemetry.cpp");
  std::stringstream ss;
  ss << f.rdbuf();
  const std::string src = ss.str();
  TEST_ASSERT_TRUE(src.find("strftime(") == std::string::npos);
  TEST_ASSERT_TRUE(src.find("formatIso8601Utc(") != std::string::npos);
  TEST_ASSERT_TRUE(src.find("iso8601_utc.h") != std::string::npos);
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_known_instants);
  RUN_TEST(test_matches_libc_across_a_sweep);
  RUN_TEST(test_buffer_too_small_is_refused);
  RUN_TEST(test_negative_is_refused);
  RUN_TEST(test_telemetry_no_longer_calls_strftime);
  return UNITY_END();
}
