// Outbound header-name validation for lib/fry_core/olostep_guard.*.
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

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_header_name_with_colon_or_space_dropped_for_every_class);
  RUN_TEST(test_header_name_empty_or_non_ascii_dropped);
  RUN_TEST(test_partner_header_names_with_every_tchar_kept);
  RUN_TEST(test_partner_ordinary_header_still_kept);
  return UNITY_END();
}
