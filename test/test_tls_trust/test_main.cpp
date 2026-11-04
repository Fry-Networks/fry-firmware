// fry::trustSetForHost / fry::tlsClockSane (lib/fry_core/tls_trust.*): which X.509 roots the ESP8266 loads for a
// host, and when the clock is good enough to validate a certificate. Unknown host => None => no connection.
#include <unity.h>

#include <cstdint>
#include <cstring>

#include "tls_trust.h"

namespace {

void test_hardwareapi_gets_the_isrg_root_ye_set() {
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TrustSet::Hwapi),
                        static_cast<int>(fry::trustSetForHost("hardwareapi.frynetworks.com")));
  TEST_ASSERT_EQUAL_UINT8(1, fry::trustSetCount(fry::TrustSet::Hwapi));
  TEST_ASSERT_EQUAL_STRING("HWAPI", fry::trustSetName(fry::TrustSet::Hwapi));
}

void test_the_second_api_host_gets_the_same_ye_set_by_exact_match() {
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TrustSet::Hwapi), static_cast<int>(fry::trustSetForHost("fry.farm")));
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TrustSet::Hwapi), static_cast<int>(fry::trustSetForHost("Fry.Farm:443")));
  const char* hosts[] = {"evil-fry.farm", "fry.farm.evil.org", "x.fry.farm", "xfry.farm", "fry.farmx", ".fry.farm"};
  for (const char* h : hosts) {
    TEST_ASSERT_EQUAL_INT_MESSAGE(static_cast<int>(fry::TrustSet::None), static_cast<int>(fry::trustSetForHost(h)), h);
  }
}

void test_a_host_outside_the_dns_charset_or_with_an_empty_label_is_none() {
  const char* hosts[] = {"evil.example?x.githubusercontent.com", "a@x.githubusercontent.com", "x#.githubusercontent.com",
                         "..githubusercontent.com", "github.com.", "x..githubusercontent.com", "x\\.githubusercontent.com",
                         "x .githubusercontent.com", "x/y.githubusercontent.com", "fry.farm.", "hardwareapi.frynetworks.com.",
                         "a.b.githubusercontent.com:443"};
  for (const char* h : hosts) {
    const fry::TrustSet got = fry::trustSetForHost(h);
    // the last entry is a legitimate nested name and must still be accepted
    const fry::TrustSet want = (std::strcmp(h, "a.b.githubusercontent.com:443") == 0) ? fry::TrustSet::GithubAssets : fry::TrustSet::None;
    TEST_ASSERT_EQUAL_INT_MESSAGE(static_cast<int>(want), static_cast<int>(got), h);
  }
}

void test_each_hop_of_a_release_download_gets_its_own_single_root_set() {
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TrustSet::GithubCom), static_cast<int>(fry::trustSetForHost("github.com")));
  const char* hosts[] = {"release-assets.githubusercontent.com", "objects.githubusercontent.com", "raw.githubusercontent.com"};
  for (const char* h : hosts) {
    TEST_ASSERT_EQUAL_INT_MESSAGE(static_cast<int>(fry::TrustSet::GithubAssets), static_cast<int>(fry::trustSetForHost(h)), h);
  }
  // one root each: a set is replaced between hops, never grown
  TEST_ASSERT_EQUAL_UINT8(1, fry::trustSetCount(fry::TrustSet::GithubCom));
  TEST_ASSERT_EQUAL_UINT8(1, fry::trustSetCount(fry::TrustSet::GithubAssets));
  TEST_ASSERT_EQUAL_STRING("GITHUB_COM", fry::trustSetName(fry::TrustSet::GithubCom));
  TEST_ASSERT_EQUAL_STRING("GITHUB_ASSETS", fry::trustSetName(fry::TrustSet::GithubAssets));
  TEST_ASSERT_NOT_EQUAL(static_cast<int>(fry::trustSetForHost("github.com")),
                        static_cast<int>(fry::trustSetForHost("objects.githubusercontent.com")));
}

void test_a_port_and_letter_case_do_not_change_the_answer() {
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TrustSet::Hwapi),
                        static_cast<int>(fry::trustSetForHost("HardwareAPI.FryNetworks.com:443")));
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TrustSet::GithubCom), static_cast<int>(fry::trustSetForHost("github.com:443")));
}

void test_everything_else_is_none() {
  const char* hosts[] = {"",
                         nullptr,
                         "evil-github.com",
                         "github.com.evil.org",
                         "xgithub.com",
                         "githubusercontent.com",
                         "evilgithubusercontent.com",
                         "hardwareapi.frynetworks.com.evil.org",
                         "xhardwareapi.frynetworks.com",
                         "dashboard.frynetworks.com",
                         "frynetworks.com",
                         "example.com",
                         "github.com:abc",
                         "10.0.0.5"};
  for (const char* h : hosts) {
    TEST_ASSERT_EQUAL_INT_MESSAGE(static_cast<int>(fry::TrustSet::None), static_cast<int>(fry::trustSetForHost(h)),
                                  h ? h : "(null)");
  }
  TEST_ASSERT_EQUAL_UINT8(0, fry::trustSetCount(fry::TrustSet::None));
}

void test_the_clock_is_sane_from_2026_01_01_utc() {
  TEST_ASSERT_FALSE(fry::tlsClockSane(0));
  TEST_ASSERT_FALSE(fry::tlsClockSane(946684800));    // 2000-01-01
  TEST_ASSERT_FALSE(fry::tlsClockSane(1767225599));   // 2025-12-31T23:59:59Z
  TEST_ASSERT_TRUE(fry::tlsClockSane(1767225600));    // 2026-01-01T00:00:00Z
  TEST_ASSERT_TRUE(fry::tlsClockSane(1793000000));
  TEST_ASSERT_FALSE(fry::tlsClockSane(-1));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_hardwareapi_gets_the_isrg_root_ye_set);
  RUN_TEST(test_the_second_api_host_gets_the_same_ye_set_by_exact_match);
  RUN_TEST(test_a_host_outside_the_dns_charset_or_with_an_empty_label_is_none);
  RUN_TEST(test_each_hop_of_a_release_download_gets_its_own_single_root_set);
  RUN_TEST(test_a_port_and_letter_case_do_not_change_the_answer);
  RUN_TEST(test_everything_else_is_none);
  RUN_TEST(test_the_clock_is_sane_from_2026_01_01_utc);
  return UNITY_END();
}
