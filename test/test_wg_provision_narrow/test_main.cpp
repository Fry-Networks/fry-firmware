// Route narrowing: a candidate block that contains the board's own STA address or gateway is
// narrowed to the sub-block that excludes them, and the result must stay inside the candidate.
#include <unity.h>

#include <cstring>

#include "wg_provision.h"

namespace {

constexpr uint32_t kSta1_50 = 0xC0A80132u;  // 192.168.1.50
constexpr uint32_t kGw1_1 = 0xC0A80101u;    // 192.168.1.1

bool contains(const fry::WgRoutePlan& plan, const char* cidr) {
  for (int i = 0; i < plan.allowedCount; i++) {
    if (strcmp(plan.allowedCidr[i], cidr) == 0) return true;
  }
  return false;
}

// true iff the plan's block i lies inside net/prefix and holds neither ip1 nor ip2
void expectInsideAndExcluding(const fry::WgRoutePlan& plan, uint32_t net, int prefix, uint32_t ip1,
                              uint32_t ip2) {
  TEST_ASSERT_TRUE(plan.ok);
  TEST_ASSERT_TRUE(plan.allowedCount >= 1);
  for (int i = 0; i < plan.allowedCount; i++) {
    uint32_t bnet;
    int bprefix;
    TEST_ASSERT_TRUE(fry::parseIpv4Cidr(plan.allowedCidr[i], &bnet, &bprefix));
    TEST_ASSERT_TRUE(bprefix >= prefix);
    TEST_ASSERT_EQUAL_UINT32(net, bnet & fry::prefixToMask(prefix));  // inside the candidate
    const uint32_t m = fry::prefixToMask(bprefix);
    TEST_ASSERT_TRUE((ip1 & m) != bnet);
    TEST_ASSERT_TRUE((ip2 & m) != bnet);
  }
}

void test_wide_candidate_narrows_to_largest_clean_half() {
  const char* allowed[] = {"192.168.0.0/16"};
  fry::WgRoutePlan plan = fry::planWgRoutes("10.13.13.2/24", allowed, 1, kSta1_50, 24, kGw1_1);
  expectInsideAndExcluding(plan, 0xC0A80000u, 16, kSta1_50, kGw1_1);
  TEST_ASSERT_FALSE(contains(plan, "10.13.13.0/24"));  // the candidate is kept, not the fallback
  TEST_ASSERT_EQUAL_INT(1, plan.allowedCount);
  TEST_ASSERT_EQUAL_STRING("192.168.128.0/17", plan.allowedCidr[0]);
}

void test_sta_in_lower_half_keeps_upper_half_not_a_host_route() {
  const char* allowed[] = {"192.168.0.0/16"};
  fry::WgRoutePlan plan = fry::planWgRoutes("10.13.13.2/24", allowed, 1, 0xC0A80032u /*192.168.0.50*/,
                                            24, 0xC0A80001u /*192.168.0.1*/);
  expectInsideAndExcluding(plan, 0xC0A80000u, 16, 0xC0A80032u, 0xC0A80001u);
  TEST_ASSERT_EQUAL_STRING("192.168.128.0/17", plan.allowedCidr[0]);
}

void test_sta_in_upper_half_keeps_lower_half() {
  const char* allowed[] = {"192.168.0.0/16"};
  fry::WgRoutePlan plan = fry::planWgRoutes("10.13.13.2/24", allowed, 1, 0xC0A8C805u /*192.168.200.5*/,
                                            24, 0xC0A8C801u /*192.168.200.1*/);
  expectInsideAndExcluding(plan, 0xC0A80000u, 16, 0xC0A8C805u, 0xC0A8C801u);
  TEST_ASSERT_EQUAL_STRING("192.168.0.0/17", plan.allowedCidr[0]);
}

void test_sta_only_overlap_narrows_away_from_sta() {
  // gateway sits outside the candidate; only the STA address collides
  const char* allowed[] = {"192.168.0.0/16"};
  fry::WgRoutePlan plan = fry::planWgRoutes("10.13.13.2/24", allowed, 1, kSta1_50, 24,
                                            0x0A000001u /*10.0.0.1*/);
  expectInsideAndExcluding(plan, 0xC0A80000u, 16, kSta1_50, 0x0A000001u);
  TEST_ASSERT_EQUAL_STRING("192.168.128.0/17", plan.allowedCidr[0]);
}

void test_gateway_only_overlap_narrows_away_from_gateway() {
  // STA address outside the candidate; only the gateway collides
  const char* allowed[] = {"192.168.0.0/16"};
  fry::WgRoutePlan plan = fry::planWgRoutes("10.13.13.2/24", allowed, 1, 0x0A000032u /*10.0.0.50*/, 24,
                                            kGw1_1);
  expectInsideAndExcluding(plan, 0xC0A80000u, 16, 0x0A000032u, kGw1_1);
  TEST_ASSERT_EQUAL_STRING("192.168.128.0/17", plan.allowedCidr[0]);
}

void test_no_overlap_candidate_is_unchanged() {
  const char* allowed[] = {"172.16.0.0/16"};
  fry::WgRoutePlan plan = fry::planWgRoutes("10.13.13.2/24", allowed, 1, kSta1_50, 24, kGw1_1);
  TEST_ASSERT_TRUE(plan.ok);
  TEST_ASSERT_EQUAL_INT(1, plan.allowedCount);
  TEST_ASSERT_EQUAL_STRING("172.16.0.0/16", plan.allowedCidr[0]);
}

void test_candidate_that_is_the_sta_host_is_dropped() {
  const char* allowed[] = {"192.168.1.50/32"};
  fry::WgRoutePlan plan = fry::planWgRoutes("10.13.13.2/24", allowed, 1, kSta1_50, 24, kGw1_1);
  TEST_ASSERT_TRUE(plan.ok);
  TEST_ASSERT_EQUAL_INT(1, plan.allowedCount);
  TEST_ASSERT_EQUAL_STRING("10.13.13.0/24", plan.allowedCidr[0]);  // fallback: nothing survived
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_wide_candidate_narrows_to_largest_clean_half);
  RUN_TEST(test_sta_in_lower_half_keeps_upper_half_not_a_host_route);
  RUN_TEST(test_sta_in_upper_half_keeps_lower_half);
  RUN_TEST(test_sta_only_overlap_narrows_away_from_sta);
  RUN_TEST(test_gateway_only_overlap_narrows_away_from_gateway);
  RUN_TEST(test_no_overlap_candidate_is_unchanged);
  RUN_TEST(test_candidate_that_is_the_sta_host_is_dropped);
  return UNITY_END();
}
