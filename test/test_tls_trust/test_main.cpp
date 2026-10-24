// The ESP8266 TLS trust policy (lib/fry_core/tls_trust.*): the clock gate that decides whether a
// validated session may be opened at all, and the host -> root table that pins WHICH roots the
// build must carry (src/esp8266/tls_anchors.h). Pure: no board, no BearSSL.
//
// At HEAD (ce884b7) there is no such policy at all - the ESP8266 image ran sec.setInsecure() on
// every HTTPS call - so this file is the RED test for C1.
#include <unity.h>

#include <cstdint>
#include <cstring>

#include "tls_trust.h"

namespace {

void test_the_clock_gate_refuses_a_board_without_ntp() {
  // 1970 (what a board with no NTP reports) and 2000 are both below the floor.
  TEST_ASSERT_FALSE(fry::tlsClockUsable(0));
  TEST_ASSERT_FALSE(fry::tlsClockUsable(946684800u));    // 2000-01-01
  TEST_ASSERT_FALSE(fry::tlsClockUsable(1599999999u));   // one second below the floor
}

void test_the_clock_gate_accepts_a_plausible_time() {
  TEST_ASSERT_TRUE(fry::tlsClockUsable(1600000000u));  // the floor itself
  TEST_ASSERT_TRUE(fry::tlsClockUsable(1761250000u));  // 2025-10-23, a real capture
  TEST_ASSERT_TRUE(fry::tlsClockUsable(0xFFFFFFFFu));  // and it never rejects a large time
}

void test_the_host_table_covers_every_host_the_firmware_reaches() {
  fry::TlsRoot root = fry::TlsRoot::Count;
  TEST_ASSERT_TRUE(fry::tlsRootForHost("hardwareapi.frynetworks.com", &root));
  TEST_ASSERT_EQUAL(fry::TlsRoot::IsrgX2, root);
  TEST_ASSERT_TRUE(fry::tlsRootForHost("fry.farm", &root));
  TEST_ASSERT_EQUAL(fry::TlsRoot::IsrgX2, root);
  TEST_ASSERT_TRUE(fry::tlsRootForHost("dashboard.frynetworks.com", &root));
  TEST_ASSERT_EQUAL(fry::TlsRoot::IsrgX2, root);
  TEST_ASSERT_TRUE(fry::tlsRootForHost("github.com", &root));
  TEST_ASSERT_EQUAL(fry::TlsRoot::SectigoE46, root);
  TEST_ASSERT_TRUE(fry::tlsRootForHost("release-assets.githubusercontent.com", &root));
  TEST_ASSERT_EQUAL(fry::TlsRoot::IsrgX1, root);
  TEST_ASSERT_TRUE(fry::tlsRootForHost("objects.githubusercontent.com", &root));
  TEST_ASSERT_EQUAL(fry::TlsRoot::IsrgX1, root);
}

void test_no_anchor_is_carried_for_nothing() {
  size_t n = 0;
  const fry::TlsHostRoot* table = fry::tlsHostRootTable(&n);
  TEST_ASSERT_EQUAL_UINT32(6, n);
  TEST_ASSERT_NOT_NULL(table);
  // Every root in the compiled set must have at least one host, or its heap cost buys nothing.
  for (uint8_t r = 0; r < static_cast<uint8_t>(fry::TlsRoot::Count); r++) {
    bool used = false;
    for (size_t i = 0; i < n; i++) {
      if (static_cast<uint8_t>(table[i].root) == r) used = true;
    }
    TEST_ASSERT_TRUE(used);
  }
  // ... and every table entry must name a root inside the compiled set.
  for (size_t i = 0; i < n; i++) {
    TEST_ASSERT_TRUE(static_cast<uint8_t>(table[i].root) < static_cast<uint8_t>(fry::TlsRoot::Count));
    TEST_ASSERT_NOT_NULL(table[i].host);
  }
}

void test_an_unknown_host_is_not_in_the_table() {
  fry::TlsRoot root = fry::TlsRoot::Count;
  TEST_ASSERT_FALSE(fry::tlsRootForHost("example.com", &root));
  TEST_ASSERT_FALSE(fry::tlsRootForHost("hardwareapi.frynetworks.com.evil.example", &root));
  TEST_ASSERT_FALSE(fry::tlsRootForHost("GitHub.com", &root));   // exact match, not case-folded
  TEST_ASSERT_FALSE(fry::tlsRootForHost("", &root));
  TEST_ASSERT_FALSE(fry::tlsRootForHost(nullptr, &root));
}

void test_a_null_root_out_parameter_is_harmless() {
  TEST_ASSERT_TRUE(fry::tlsRootForHost("github.com", nullptr));
  TEST_ASSERT_FALSE(fry::tlsRootForHost("example.com", nullptr));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_clock_gate_refuses_a_board_without_ntp);
  RUN_TEST(test_the_clock_gate_accepts_a_plausible_time);
  RUN_TEST(test_the_host_table_covers_every_host_the_firmware_reaches);
  RUN_TEST(test_no_anchor_is_carried_for_nothing);
  RUN_TEST(test_an_unknown_host_is_not_in_the_table);
  RUN_TEST(test_a_null_root_out_parameter_is_harmless);
  return UNITY_END();
}
