// lib/fry_core/relay_dns.h: the LRU + TTL cache in front of the relay's asynchronous resolver.
//
// What matters for the relay (src/esp32/vpn_wireguard.cpp needConnect): a repeat CONNECT to the
// same name must not start another lookup, a failed name must be refused for a while instead of
// hammering the resolver, an expired entry must never be served, the LRU must actually evict the
// least recently used name when the fixed table is full, and every time comparison must survive the
// 32-bit millisecond counter wrapping.
#include <unity.h>

#include <cstdint>

#include "relay_dns.h"

using fry_relay::DnsCache;
using fry_relay::kDnsCacheEntries;

namespace {

const uint32_t kIp1 = 0x0A0D0D01u;  // 10.13.13.1, host order (as fry::parseIpv4Cidr returns it)
const uint32_t kIp2 = 0x0A0D0D02u;
const uint32_t kTtl = 300000;
const uint32_t kFailTtl = 15000;

void test_a_stored_address_is_served_back() {
  DnsCache c;
  uint32_t ip = 0;
  TEST_ASSERT_FALSE(c.lookup("example.test", 1000, &ip));
  c.store("example.test", kIp1, 1000, kTtl);
  TEST_ASSERT_TRUE(c.lookup("example.test", 1000, &ip));
  TEST_ASSERT_EQUAL_UINT32(kIp1, ip);
  TEST_ASSERT_TRUE(c.lookup("example.test", 1000 + kTtl - 1, &ip));
  TEST_ASSERT_EQUAL_UINT32(kIp1, ip);
}

void test_an_expired_address_is_not_served() {
  DnsCache c;
  uint32_t ip = 0;
  c.store("example.test", kIp1, 1000, kTtl);
  TEST_ASSERT_FALSE(c.lookup("example.test", 1000 + kTtl, &ip));
  TEST_ASSERT_FALSE(c.lookup("example.test", 1000 + kTtl + 1, &ip));
  TEST_ASSERT_FALSE(c.blocked("example.test", 1000 + kTtl));
}

void test_a_failure_blocks_the_name_for_its_own_shorter_ttl() {
  DnsCache c;
  uint32_t ip = 0;
  c.storeFailure("broken.test", 500, kFailTtl);
  TEST_ASSERT_TRUE(c.blocked("broken.test", 500));
  TEST_ASSERT_TRUE(c.blocked("broken.test", 500 + kFailTtl - 1));
  TEST_ASSERT_FALSE(c.lookup("broken.test", 500, &ip));   // a negative entry is never an address
  TEST_ASSERT_FALSE(c.blocked("broken.test", 500 + kFailTtl));
  TEST_ASSERT_FALSE(c.blocked("never-seen.test", 500));   // no entry at all is not "blocked"
  TEST_ASSERT_FALSE(c.blocked("broken.test", 500 + kFailTtl));
}

void test_a_later_success_replaces_a_negative_entry() {
  DnsCache c;
  uint32_t ip = 0;
  c.storeFailure("flaky.test", 100, kFailTtl);
  TEST_ASSERT_TRUE(c.blocked("flaky.test", 100));
  c.store("flaky.test", kIp2, 200, kTtl);
  TEST_ASSERT_FALSE(c.blocked("flaky.test", 200));
  TEST_ASSERT_TRUE(c.lookup("flaky.test", 200, &ip));
  TEST_ASSERT_EQUAL_UINT32(kIp2, ip);
}

void test_names_match_case_insensitively() {
  DnsCache c;
  uint32_t ip = 0;
  c.store("Example.TEST", kIp1, 0, kTtl);
  TEST_ASSERT_TRUE(c.lookup("example.test", 0, &ip));
  TEST_ASSERT_EQUAL_UINT32(kIp1, ip);
  TEST_ASSERT_TRUE(c.lookup("EXAMPLE.test", 0, &ip));
  TEST_ASSERT_FALSE(c.blocked("example.test", 0));
  c.storeFailure("BROKEN.test", 0, kFailTtl);
  TEST_ASSERT_TRUE(c.blocked("broken.TEST", 0));
}

void test_a_zero_address_is_not_cached_as_a_success() {
  DnsCache c;
  uint32_t ip = 123;
  c.store("zero.test", 0, 0, kTtl);
  TEST_ASSERT_FALSE(c.lookup("zero.test", 0, &ip));
  TEST_ASSERT_FALSE(c.blocked("zero.test", 0));
  TEST_ASSERT_EQUAL_UINT32(123, ip);
}

void test_the_table_evicts_the_least_recently_used_name() {
  DnsCache c;
  uint32_t ip = 0;
  char name[8];
  for (int i = 0; i < kDnsCacheEntries; i++) {
    name[0] = static_cast<char>('a' + i);
    name[1] = 0;
    c.store(name, kIp1 + static_cast<uint32_t>(i), static_cast<uint32_t>(i), kTtl);
  }
  TEST_ASSERT_EQUAL_INT(kDnsCacheEntries, c.liveCount(10));
  // Touch the oldest entry, then add one more: the untouched oldest-but-one goes, not this one.
  TEST_ASSERT_TRUE(c.lookup("a", 10, &ip));
  c.store("z", kIp2, 11, kTtl);
  TEST_ASSERT_TRUE(c.lookup("a", 11, &ip));   // refreshed: kept
  TEST_ASSERT_FALSE(c.lookup("b", 11, &ip));  // least recently used: evicted
  TEST_ASSERT_TRUE(c.lookup("z", 11, &ip));
  TEST_ASSERT_EQUAL_INT(kDnsCacheEntries, c.liveCount(11));
}

void test_an_expired_entry_is_reused_before_a_live_one() {
  DnsCache c;
  uint32_t ip = 0;
  char name[8];
  for (int i = 0; i < kDnsCacheEntries; i++) {
    name[0] = static_cast<char>('a' + i);
    name[1] = 0;
    c.store(name, kIp1, 0, 1000);
  }
  // All of them expired at 1000: a new name takes one of those slots, none of the live ones.
  c.store("fresh", kIp2, 1500, kTtl);
  TEST_ASSERT_TRUE(c.lookup("fresh", 1500, &ip));
  TEST_ASSERT_EQUAL_INT(1, c.liveCount(1500));
}

void test_expiry_survives_the_millisecond_counter_wrapping() {
  DnsCache c;
  uint32_t ip = 0;
  const uint32_t now = 0xFFFFF000u;  // 4096 ms before the counter wraps to 0
  c.store("wrap.test", kIp1, now, 8000);
  TEST_ASSERT_TRUE(c.lookup("wrap.test", now + 4000, &ip));
  TEST_ASSERT_TRUE(c.lookup("wrap.test", 0x00000100u, &ip));  // past the wrap, still inside 8 s
  TEST_ASSERT_FALSE(c.lookup("wrap.test", 0x00001000u, &ip));  // 0x1000 - 0xFFFFF000 > 8 s
}

void test_reset_drops_everything() {
  DnsCache c;
  uint32_t ip = 0;
  c.store("a.test", kIp1, 0, kTtl);
  c.reset();
  TEST_ASSERT_FALSE(c.lookup("a.test", 0, &ip));
  TEST_ASSERT_EQUAL_INT(0, c.liveCount(0));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_a_stored_address_is_served_back);
  RUN_TEST(test_an_expired_address_is_not_served);
  RUN_TEST(test_a_failure_blocks_the_name_for_its_own_shorter_ttl);
  RUN_TEST(test_a_later_success_replaces_a_negative_entry);
  RUN_TEST(test_names_match_case_insensitively);
  RUN_TEST(test_a_zero_address_is_not_cached_as_a_success);
  RUN_TEST(test_the_table_evicts_the_least_recently_used_name);
  RUN_TEST(test_an_expired_entry_is_reused_before_a_live_one);
  RUN_TEST(test_expiry_survives_the_millisecond_counter_wrapping);
  RUN_TEST(test_reset_drops_everything);
  return UNITY_END();
}
