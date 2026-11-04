// fry::decideRedirect (lib/fry_core/ota_redirect.h): whether the firmware download (or its manifest) may take the next
// redirect hop. Every hop is re-checked; nothing falls back to an insecure connection.
#include <unity.h>

#include <cstdint>
#include <string>

#include "ota_redirect.h"

namespace {

using fry::RedirectDecision;

int d(RedirectDecision v) { return static_cast<int>(v); }

void test_a_final_response_is_not_a_redirect() {
  const int codes[] = {200, 204, 304, 404, 500, -1, 0};
  for (int c : codes) {
    TEST_ASSERT_EQUAL_INT(d(RedirectDecision::NotRedirect), d(fry::decideRedirect(c, 0, "https://github.com/x")));
  }
}

void test_the_release_chain_is_followed_hop_by_hop() {
  const int codes[] = {301, 302, 303, 307, 308};
  for (int c : codes) {
    TEST_ASSERT_EQUAL_INT(d(RedirectDecision::Follow), d(fry::decideRedirect(c, 0, "https://github.com/a/b/releases/download/v1/x.bin")));
  }
  TEST_ASSERT_EQUAL_INT(d(RedirectDecision::Follow),
                        d(fry::decideRedirect(302, 1, "https://release-assets.githubusercontent.com/x?sig=abc&se=1")));
  TEST_ASSERT_EQUAL_INT(d(RedirectDecision::Follow), d(fry::decideRedirect(302, 2, "HTTPS://Objects.GitHubUserContent.com:443/p")));
}

void test_a_hop_to_a_host_without_trust_anchors_is_refused() {
  const char* locs[] = {"https://example.com/x", "https://github.com.evil.org/x", "https://evil-github.com/x",
                        "https://githubusercontent.com/x", "https://user@github.com@evil.org/x", "https://github.com?x=1",
                        "https://10.0.0.5/x", "https://", "https:///path"};
  for (const char* l : locs) {
    TEST_ASSERT_EQUAL_INT_MESSAGE(d(RedirectDecision::UnknownHost), d(fry::decideRedirect(302, 0, l)), l);
  }
}

void test_more_than_five_hops_are_refused() {
  for (uint8_t hops = 0; hops < fry::kMaxRedirectHops; hops++) {
    TEST_ASSERT_EQUAL_INT(d(RedirectDecision::Follow), d(fry::decideRedirect(302, hops, "https://github.com/x")));
  }
  TEST_ASSERT_EQUAL_INT(d(RedirectDecision::TooMany), d(fry::decideRedirect(302, fry::kMaxRedirectHops, "https://github.com/x")));
  TEST_ASSERT_EQUAL_INT(d(RedirectDecision::TooMany), d(fry::decideRedirect(302, 6, "https://github.com/x")));
  TEST_ASSERT_EQUAL_UINT8(5, fry::kMaxRedirectHops);
}

void test_a_location_that_is_not_an_absolute_https_url_is_refused() {
  const char* locs[] = {"http://github.com/x", "HTTP://github.com/x", "//github.com/x", "/relative/path", "relative",
                        "ftp://github.com/x", "http://release-assets.githubusercontent.com/x", " https://github.com/x"};
  for (const char* l : locs) {
    TEST_ASSERT_EQUAL_INT_MESSAGE(d(RedirectDecision::NotHttps), d(fry::decideRedirect(302, 0, l)), l);
  }
}

void test_a_redirect_without_a_location_is_refused() {
  TEST_ASSERT_EQUAL_INT(d(RedirectDecision::NoLocation), d(fry::decideRedirect(302, 0, nullptr)));
  TEST_ASSERT_EQUAL_INT(d(RedirectDecision::NoLocation), d(fry::decideRedirect(302, 0, "")));
}

void test_an_overlong_host_part_is_refused_not_truncated() {
  const std::string loc = "https://" + std::string(200, 'a') + ".githubusercontent.com/x";
  TEST_ASSERT_EQUAL_INT(d(RedirectDecision::UnknownHost), d(fry::decideRedirect(302, 0, loc.c_str())));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_a_final_response_is_not_a_redirect);
  RUN_TEST(test_the_release_chain_is_followed_hop_by_hop);
  RUN_TEST(test_a_hop_to_a_host_without_trust_anchors_is_refused);
  RUN_TEST(test_more_than_five_hops_are_refused);
  RUN_TEST(test_a_location_that_is_not_an_absolute_https_url_is_refused);
  RUN_TEST(test_a_redirect_without_a_location_is_refused);
  RUN_TEST(test_an_overlong_host_part_is_refused_not_truncated);
  return UNITY_END();
}
