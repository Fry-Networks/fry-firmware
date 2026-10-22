// The MFLN probe runs once per host per boot, not on every call.
//
// 217c2bb probed before every TLS call to an MFLN-capable peer. Each probe is a throwaway TLS session on
// BearSSL's default 16384+16384 buffers (~32 KB contiguous) and leaves a TIME_WAIT pcb behind. See
// lib/fry_core/mfln_cache.h for why only positive answers are remembered.
#include <unity.h>

#include <cstring>

#include "mfln_cache.h"

namespace {

struct Probe {
  int calls;
  bool answer;
  char lastHost[80];
};

bool probeFn(const char* host, void* ctx) {
  Probe* p = static_cast<Probe*>(ctx);
  p->calls++;
  strncpy(p->lastHost, host ? host : "(null)", sizeof p->lastHost - 1);
  p->lastHost[sizeof p->lastHost - 1] = '\0';
  return p->answer;
}

fry::MflnCache fresh() {
  fry::MflnCache c;
  memset(&c, 0, sizeof c);
  return c;
}

void test_a_host_that_honours_mfln_is_probed_once_per_boot() {
  fry::MflnCache cache = fresh();
  Probe p = {0, true, ""};
  for (int i = 0; i < 5; i++) {
    TEST_ASSERT_TRUE(fry::mflnHonours(cache, "hardwareapi.frynetworks.com", probeFn, &p));
  }
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, p.calls, "five calls to the same host must cost one probe");
}

void test_each_host_is_probed_on_its_own() {
  fry::MflnCache cache = fresh();
  Probe p = {0, true, ""};
  fry::mflnHonours(cache, "a.example.com", probeFn, &p);
  fry::mflnHonours(cache, "b.example.com", probeFn, &p);
  fry::mflnHonours(cache, "a.example.com", probeFn, &p);
  fry::mflnHonours(cache, "b.example.com", probeFn, &p);
  TEST_ASSERT_EQUAL_INT(2, p.calls);
}

void test_a_negative_answer_is_asked_again_because_it_may_be_a_failed_connect() {
  fry::MflnCache cache = fresh();
  Probe p = {0, false, ""};
  TEST_ASSERT_FALSE(fry::mflnHonours(cache, "flaky.example.com", probeFn, &p));
  TEST_ASSERT_FALSE(fry::mflnHonours(cache, "flaky.example.com", probeFn, &p));
  TEST_ASSERT_EQUAL_INT(2, p.calls);
  // ...and when the host then answers yes, that is remembered.
  p.answer = true;
  TEST_ASSERT_TRUE(fry::mflnHonours(cache, "flaky.example.com", probeFn, &p));
  TEST_ASSERT_TRUE(fry::mflnHonours(cache, "flaky.example.com", probeFn, &p));
  TEST_ASSERT_EQUAL_INT(3, p.calls);
}

void test_host_names_compare_case_insensitively() {
  fry::MflnCache cache = fresh();
  Probe p = {0, true, ""};
  fry::mflnHonours(cache, "HardwareAPI.FryNetworks.com", probeFn, &p);
  fry::mflnHonours(cache, "hardwareapi.frynetworks.com", probeFn, &p);
  TEST_ASSERT_EQUAL_INT(1, p.calls);
}

void test_a_cached_host_does_not_answer_for_a_different_one() {
  fry::MflnCache cache = fresh();
  Probe p = {0, true, ""};
  fry::mflnHonours(cache, "hardwareapi.frynetworks.com", probeFn, &p);
  p.answer = false;
  // A host that does NOT honour MFLN must never inherit another host's yes (512/512 against it soft-resets).
  TEST_ASSERT_FALSE(fry::mflnHonours(cache, "github.com", probeFn, &p));
  TEST_ASSERT_EQUAL_INT(2, p.calls);
  TEST_ASSERT_EQUAL_STRING("github.com", p.lastHost);
  TEST_ASSERT_FALSE(fry::mflnHonours(cache, "objects.githubusercontent.com", probeFn, &p));
  TEST_ASSERT_EQUAL_INT(3, p.calls);
}

void test_the_table_is_fixed_size_and_overwrites_the_oldest_host() {
  fry::MflnCache cache = fresh();
  Probe p = {0, true, ""};
  const char* hosts[] = {"h0.example.com", "h1.example.com", "h2.example.com", "h3.example.com",
                         "h4.example.com"};
  for (int i = 0; i < 5; i++) fry::mflnHonours(cache, hosts[i], probeFn, &p);
  TEST_ASSERT_EQUAL_INT(5, p.calls);
  // The four newest are still cached...
  for (int i = 1; i < 5; i++) fry::mflnHonours(cache, hosts[i], probeFn, &p);
  TEST_ASSERT_EQUAL_INT(5, p.calls);
  // ...the oldest was overwritten and is probed again.
  fry::mflnHonours(cache, hosts[0], probeFn, &p);
  TEST_ASSERT_EQUAL_INT(6, p.calls);
  static_assert(sizeof(fry::MflnCache) <= 48, "the per-boot table must stay a few dozen bytes of DRAM");
}

void test_null_and_empty_hosts_are_never_remembered() {
  fry::MflnCache cache = fresh();
  Probe p = {0, true, ""};
  TEST_ASSERT_TRUE(fry::mflnHonours(cache, "", probeFn, &p));
  TEST_ASSERT_TRUE(fry::mflnHonours(cache, "", probeFn, &p));
  TEST_ASSERT_TRUE(fry::mflnHonours(cache, nullptr, probeFn, &p));
  TEST_ASSERT_EQUAL_INT(3, p.calls);
  // and they did not poison a real host's slot
  fry::mflnHonours(cache, "real.example.com", probeFn, &p);
  TEST_ASSERT_EQUAL_INT(4, p.calls);
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_a_host_that_honours_mfln_is_probed_once_per_boot);
  RUN_TEST(test_each_host_is_probed_on_its_own);
  RUN_TEST(test_a_negative_answer_is_asked_again_because_it_may_be_a_failed_connect);
  RUN_TEST(test_host_names_compare_case_insensitively);
  RUN_TEST(test_a_cached_host_does_not_answer_for_a_different_one);
  RUN_TEST(test_the_table_is_fixed_size_and_overwrites_the_oldest_host);
  RUN_TEST(test_null_and_empty_hosts_are_never_remembered);
  return UNITY_END();
}
