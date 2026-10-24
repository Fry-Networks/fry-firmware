// NvsAbsentCache (lib/fry_core/nvs_absent.h): the memory behind the NVS-open suppression in
// src/core/kv_store.h. Pins the rule that replaced the per-loop "nvs_open failed: NOT_FOUND" storm
// (4326 lines in 54 s, capture e32-a3b-224212): a namespace NVS has answered NOT_FOUND for is
// skipped on a read-only begin() until something proves it exists, and the memory is bounded.
#include <unity.h>

#include <cstdio>
#include <cstring>

#include "nvs_absent.h"

namespace {

void test_an_unknown_namespace_is_not_absent() {
  fry::NvsAbsentCache c;
  TEST_ASSERT_FALSE(c.isAbsent("fry_vpn"));
  TEST_ASSERT_EQUAL_INT(0, c.size());
}

void test_absent_is_remembered_until_the_namespace_appears() {
  fry::NvsAbsentCache c;
  c.noteAbsent("fry_vpn");
  TEST_ASSERT_TRUE(c.isAbsent("fry_vpn"));
  TEST_ASSERT_EQUAL_INT(1, c.size());
  // Idempotent: the same namespace twice is still one entry.
  c.noteAbsent("fry_vpn");
  TEST_ASSERT_EQUAL_INT(1, c.size());
  // Something wrote it (a writable begin that succeeded, putString, remove, clear): read it again.
  c.notePresent("fry_vpn");
  TEST_ASSERT_FALSE(c.isAbsent("fry_vpn"));
  TEST_ASSERT_EQUAL_INT(0, c.size());
}

void test_only_the_named_namespace_is_affected() {
  fry::NvsAbsentCache c;
  c.noteAbsent("fry_vpn");
  TEST_ASSERT_TRUE(c.isAbsent("fry_vpn"));
  TEST_ASSERT_FALSE(c.isAbsent("fry_wifi"));  // the namespace that does exist on every board
  c.notePresent("fry_wifi");                  // forgetting an absent-unknown name is a no-op
  TEST_ASSERT_TRUE(c.isAbsent("fry_vpn"));
  TEST_ASSERT_EQUAL_INT(1, c.size());
}

void test_the_cache_is_bounded_and_evicts_the_oldest() {
  fry::NvsAbsentCache c;
  char name[16];
  for (int i = 0; i < fry::NvsAbsentCache::kCapacity; i++) {
    std::snprintf(name, sizeof(name), "ns%d", i);
    c.noteAbsent(name);
  }
  TEST_ASSERT_EQUAL_INT(fry::NvsAbsentCache::kCapacity, c.size());
  TEST_ASSERT_TRUE(c.isAbsent("ns0"));
  // One more distinct namespace evicts the oldest slot, never grows past the capacity.
  c.noteAbsent("overflow");
  TEST_ASSERT_EQUAL_INT(fry::NvsAbsentCache::kCapacity, c.size());
  TEST_ASSERT_TRUE(c.isAbsent("overflow"));
  TEST_ASSERT_FALSE(c.isAbsent("ns0"));
  TEST_ASSERT_TRUE(c.isAbsent("ns1"));
}

void test_an_uncacheable_name_is_simply_not_cached() {
  fry::NvsAbsentCache c;
  c.noteAbsent("");  // empty: nothing to remember
  TEST_ASSERT_FALSE(c.isAbsent(""));
  TEST_ASSERT_EQUAL_INT(0, c.size());
  char longName[fry::NvsAbsentCache::kMaxNameLen + 8];
  std::memset(longName, 'x', sizeof(longName) - 1);
  longName[sizeof(longName) - 1] = '\0';
  c.noteAbsent(longName);  // longer than a slot: not cached, callers keep the old behaviour
  TEST_ASSERT_FALSE(c.isAbsent(longName));
  TEST_ASSERT_EQUAL_INT(0, c.size());
  c.noteAbsent(nullptr);  // must not crash
  TEST_ASSERT_EQUAL_INT(0, c.size());
}

void test_reset_clears_everything() {
  fry::NvsAbsentCache c;
  c.noteAbsent("fry_vpn");
  c.noteAbsent("fry_olostep");
  TEST_ASSERT_EQUAL_INT(2, c.size());
  c.reset();
  TEST_ASSERT_EQUAL_INT(0, c.size());
  TEST_ASSERT_FALSE(c.isAbsent("fry_vpn"));
  TEST_ASSERT_FALSE(c.isAbsent("fry_olostep"));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_an_unknown_namespace_is_not_absent);
  RUN_TEST(test_absent_is_remembered_until_the_namespace_appears);
  RUN_TEST(test_only_the_named_namespace_is_affected);
  RUN_TEST(test_the_cache_is_bounded_and_evicts_the_oldest);
  RUN_TEST(test_an_uncacheable_name_is_simply_not_cached);
  RUN_TEST(test_reset_clears_everything);
  return UNITY_END();
}
