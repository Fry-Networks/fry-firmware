// Outbound header-name validation and IPv6 egress ranges for lib/fry_core/olostep_guard.*.
#ifdef ARDUINO
#include <Arduino.h>
#endif
#include <unity.h>

#include <string>

#include "olostep_guard.h"

using namespace fry_olostep;

void setUp() {}
void tearDown() {}

// ---- header names: only RFC 9110 token characters may be emitted ----------------------------

static const OlostepJobClass kClasses[] = {OlostepJobClass::Unauthenticated,
                                           OlostepJobClass::AuthenticatedPartner,
                                           OlostepJobClass::Unknown};

void test_header_name_with_colon_or_space_dropped_for_every_class() {
  for (OlostepJobClass cls : kClasses) {
    HeaderMap in;
    in["Host: evil.com"] = "x";
    in["Content-Length:"] = "0";
    in["X-A B"] = "x";
    in["Accept"] = "text/html";
    in["X-Ok"] = "1";
    const HeaderMap out = olostep_sanitize_outbound_headers(in, cls);
    TEST_ASSERT_EQUAL(0, (int)out.count("host: evil.com"));
    TEST_ASSERT_EQUAL(0, (int)out.count("content-length:"));
    TEST_ASSERT_EQUAL(0, (int)out.count("x-a b"));
    TEST_ASSERT_EQUAL(1, (int)out.count("accept"));
    for (const auto& kv : out) {
      TEST_ASSERT_EQUAL(std::string::npos, kv.first.find(':'));
      TEST_ASSERT_EQUAL(std::string::npos, kv.first.find(' '));
    }
  }
}

void test_header_name_empty_or_non_ascii_dropped() {
  for (OlostepJobClass cls : kClasses) {
    HeaderMap in;
    in[""] = "x";
    in["   "] = "x";
    in["X-\xC3\xA9"] = "x";
    in["X-A\"B"] = "x";
    in["X-A(B)"] = "x";
    in["Accept"] = "text/html";
    const HeaderMap out = olostep_sanitize_outbound_headers(in, cls);
    TEST_ASSERT_EQUAL(1, (int)out.size());
    TEST_ASSERT_EQUAL(1, (int)out.count("accept"));
  }
}

void test_partner_header_names_with_every_tchar_kept() {
  HeaderMap in;
  in["X-Tchar!#$%&'*+.^_`|~09az"] = "v";
  const HeaderMap out = olostep_sanitize_outbound_headers(in, OlostepJobClass::AuthenticatedPartner);
  TEST_ASSERT_EQUAL(1, (int)out.size());
  TEST_ASSERT_EQUAL(1, (int)out.count("x-tchar!#$%&'*+.^_`|~09az"));
}

void test_partner_ordinary_header_still_kept() {
  HeaderMap in;
  in["X-Custom"] = "1";
  in["Authorization"] = "Bearer t";
  const HeaderMap out = olostep_sanitize_outbound_headers(in, OlostepJobClass::AuthenticatedPartner);
  TEST_ASSERT_EQUAL(2, (int)out.size());
}

// ---- IPv6 egress ----------------------------------------------------------------------------

void test_siit_embedded_private_v4_blocked() {
  TEST_ASSERT_FALSE(olostep_url_allowed("https://[::ffff:0:10.0.0.1]/"));
  TEST_ASSERT_FALSE(olostep_url_allowed("https://[::ffff:0:127.0.0.1]/"));
  TEST_ASSERT_FALSE(olostep_url_allowed("https://[::ffff:0:192.168.1.1]/"));
}

void test_siit_embedded_public_v4_allowed() {
  TEST_ASSERT_TRUE(olostep_url_allowed("https://[::ffff:0:8.8.8.8]/"));
}

void test_rest_of_zero_slash_8_blocked() {
  TEST_ASSERT_FALSE(olostep_url_allowed("https://[::2:0:0:1]/"));
  TEST_ASSERT_FALSE(olostep_url_allowed("https://[0:1::1]/"));
  TEST_ASSERT_FALSE(olostep_url_allowed("https://[ff:0:0:0:0:0:0:1]/"));
}

void test_nat64_well_known_prefix_still_judged_by_embedded_v4() {
  TEST_ASSERT_TRUE(olostep_url_allowed("https://[64:ff9b::8.8.8.8]/"));
  TEST_ASSERT_FALSE(olostep_url_allowed("https://[64:ff9b::10.0.0.1]/"));
}

void test_rfc9637_range_blocked_with_near_miss_allowed() {
  TEST_ASSERT_FALSE(olostep_url_allowed("https://[3fff::1]/"));
  TEST_ASSERT_FALSE(olostep_url_allowed("https://[3fff:0fff:ffff::1]/"));
  TEST_ASSERT_TRUE(olostep_url_allowed("https://[3fff:1000::1]/"));  // first address past 3fff::/20
  TEST_ASSERT_TRUE(olostep_url_allowed("https://[3ffe::1]/"));
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_header_name_with_colon_or_space_dropped_for_every_class);
  RUN_TEST(test_header_name_empty_or_non_ascii_dropped);
  RUN_TEST(test_partner_header_names_with_every_tchar_kept);
  RUN_TEST(test_partner_ordinary_header_still_kept);
  RUN_TEST(test_siit_embedded_private_v4_blocked);
  RUN_TEST(test_siit_embedded_public_v4_allowed);
  RUN_TEST(test_rest_of_zero_slash_8_blocked);
  RUN_TEST(test_nat64_well_known_prefix_still_judged_by_embedded_v4);
  RUN_TEST(test_rfc9637_range_blocked_with_near_miss_allowed);
  return UNITY_END();
}
