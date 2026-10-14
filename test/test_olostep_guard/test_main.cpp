// A1 (unauthenticated-only) and egress (SSRF) tests for lib/fry_core/olostep_guard.*.
//
// Every "rejected" test has a matching control that is PERMITTED, so none of them can pass
// vacuously. Removing an enforcement in olostep_guard.cpp must turn a named test below red.
#ifdef ARDUINO
#include <Arduino.h>
#endif
#include <unity.h>

#include <cstring>
#include <string>

#include "olostep_guard.h"
// The disclosure const lives in a src/ header that is a pure constant when FRY_HAS_OLOSTEP is 0.
#include "../../src/core/olostep_consent.h"

using namespace fry_olostep;

namespace {

Job plainJob() {
  Job j;
  j.method_endpoint = "https://example.com/page";
  j.method_headers["Accept"] = "text/html";
  return j;
}

void expectRejected(const Job& j) { TEST_ASSERT_FALSE(olostep_job_is_permitted(j)); }

bool hasCI(const std::string& hay, const char* needle) {
  std::string h = hay;
  for (char& c : h) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return h.find(needle) != std::string::npos;
}

}  // namespace

// ---- A1: jobs -------------------------------------------------------------------------------

void test_plain_fetch_permitted() { TEST_ASSERT_TRUE(olostep_job_is_permitted(plainJob())); }

void test_cookie_header_rejected() {
  Job j = plainJob();
  j.method_headers["Cookie"] = "a=b";
  expectRejected(j);
  Job k = plainJob();
  k.method_headers["cOoKiE"] = "a=b";
  expectRejected(k);
}

void test_authorization_header_rejected() {
  const char* names[] = {"Authorization", "Proxy-Authorization", "authorization", "Authentication",
                         "X-Auth-Token"};
  for (const char* n : names) {
    Job j = plainJob();
    j.method_headers[n] = "Bearer abc";
    expectRejected(j);
  }
}

void test_x_api_key_header_rejected() {
  const char* names[] = {"X-API-Key", "Api-Key", "Foo-Key", "X-Foo-Token", "Foo-Token", "x-api-key"};
  for (const char* n : names) {
    Job j = plainJob();
    j.method_headers[n] = "k";
    expectRejected(j);
  }
}

void test_session_id_rejected() {
  Job j = plainJob();
  j.session_id = "abc123";
  expectRejected(j);
}

void test_lease_node_rejected() {
  Job j = plainJob();
  j.lease_node = "node-7";
  expectRejected(j);
}

void test_each_partner_type_event_now_permitted() {
  const char* ev[] = {"copilot_batch", "chatgpt_batch", "gemini_batch", "perplexity_batch",
                      "rufus_batch",   "meta_batch",    "amazon_reviews", "meta_login",
                      "reset_meta",    "create_cplt_session"};
  for (const char* e : ev) {
    Job j = plainJob();
    j.type_event = e;
    TEST_ASSERT_TRUE_MESSAGE(olostep_job_is_permitted(j), e);
    Job bad = plainJob();
    bad.type_event = e;
    bad.method_endpoint = "https://192.168.1.1/";
    expectRejected(bad);  // SSRF still rejects every partner type
  }
  Job upper = plainJob();
  upper.type_event = "META_LOGIN";
  expectRejected(upper);  // case-sensitive: unrecognized -> fail closed
}

void test_unrecognized_type_event_rejected() {
  Job j = plainJob();
  j.type_event = "fetch";
  expectRejected(j);
  Job b = plainJob();
  b.type_event = "batch";
  TEST_ASSERT_TRUE(olostep_job_is_permitted(b));  // control
}

void test_each_action_field_rejected() {
  Job a = plainJob(); a.actions = "[{}]"; expectRejected(a);
  Job b = plainJob(); b.runScript = "x"; expectRejected(b);
  Job c = plainJob(); c.burkeObject = "{}"; expectRejected(c);
  Job d = plainJob(); d.cerealObject = "{}"; expectRejected(d);
  Job e = plainJob(); e.saveFile = "true"; expectRejected(e);
  Job f = plainJob(); f.htmlVisualizer = "true"; expectRejected(f);
}

// ---- A1: headers / responses / capability ---------------------------------------------------

void test_sanitize_drops_cookie_auth_apikey_keeps_ua_accept_referer() {
  HeaderMap in;
  in["Cookie"] = "a=b";
  in["Authorization"] = "Bearer x";
  in["X-API-Key"] = "k";
  in["User-Agent"] = "ua";
  in["accept"] = "text/html";
  in["REFERER"] = "https://example.com/";
  in["Accept-Language"] = "en";
  in["Accept-Encoding"] = "gzip";
  in["X-Custom"] = "nope";
  const HeaderMap out = olostep_sanitize_outbound_headers(in);
  TEST_ASSERT_EQUAL(5, (int)out.size());
  TEST_ASSERT_EQUAL(0, (int)out.count("Cookie"));
  TEST_ASSERT_EQUAL(0, (int)out.count("Authorization"));
  TEST_ASSERT_EQUAL(0, (int)out.count("X-API-Key"));
  TEST_ASSERT_EQUAL(0, (int)out.count("X-Custom"));
  TEST_ASSERT_EQUAL(1, (int)out.count("user-agent"));
  TEST_ASSERT_EQUAL(1, (int)out.count("accept"));
  TEST_ASSERT_EQUAL(1, (int)out.count("referer"));
}

void test_sanitize_never_emits_auth_on_adversarial_input() {
  const char* names[] = {"Cookie", "Cookie2", "Authorization", "Proxy-Authorization", "Authentication",
                         "Api-Key", "X-API-Key", "X-Auth-Token", "Foo-Token", "Foo-Key", " cookie ",
                         "X-Session", "Set-Cookie"};
  HeaderMap in;
  for (const char* n : names) in[n] = "v";
  TEST_ASSERT_EQUAL(0, (int)olostep_sanitize_outbound_headers(in).size());
}

void test_capability_query_has_ali_mli_burke() {
  const std::string q = olostep_ws_capability_query("dev-0123abcd", "0.4.37", "esp32");
  TEST_ASSERT_TRUE(q.find("ali=1") != std::string::npos);
  TEST_ASSERT_TRUE(q.find("mli=1") != std::string::npos);
  TEST_ASSERT_TRUE(q.find("burke=true") != std::string::npos);
  TEST_ASSERT_TRUE(q.find("device_id=dev-0123abcd") != std::string::npos);
  TEST_ASSERT_TRUE(q.find("version=0.4.37") != std::string::npos);
  TEST_ASSERT_TRUE(q.find("platform=esp32") != std::string::npos);
}

void test_set_cookie_dropped_from_response() {
  HeaderMap in;
  in["Set-Cookie"] = "sid=1";
  in["set-cookie2"] = "x";
  in["SET-COOKIE"] = "y";
  in["Content-Type"] = "text/html";
  const HeaderMap out = olostep_sanitize_response_headers(in);
  TEST_ASSERT_EQUAL(1, (int)out.size());
  TEST_ASSERT_EQUAL(1, (int)out.count("Content-Type"));
}

void test_response_is_clean_flags_set_cookie() {
  HeaderMap clean;
  clean["Content-Type"] = "text/html";
  TEST_ASSERT_TRUE(olostep_response_is_clean(clean));
  HeaderMap dirty = clean;
  dirty["Set-Cookie"] = "sid=1";
  TEST_ASSERT_FALSE(olostep_response_is_clean(dirty));
}

void test_disclosure_text_exact() {
  TEST_ASSERT_EQUAL_STRING(
      "When enabled, this device relays third-party web requests through your IP, including authenticated partner sessions. "
      "It is opt-in and reversible. It never uses your own accounts, sessions, or stored credentials.",
      OLOSTEP_OWNER_DISCLOSURE);
}

void test_feature_flag_defaults_off() { TEST_ASSERT_EQUAL(0, FRY_HAS_OLOSTEP); }

// ---- Egress / SSRF --------------------------------------------------------------------------

void test_url_metadata_ip_rejected() {
  TEST_ASSERT_FALSE(olostep_url_allowed("https://169.254.169.254/latest/meta-data/"));
}

void test_url_private_v4_rejected() {
  const char* bad[] = {"https://192.168.1.1/",   "https://10.0.0.1/",      "https://172.16.0.1/",
                       "https://172.31.255.255/", "https://127.0.0.1/",     "https://0.0.0.0/",
                       "https://100.64.0.1/",    "https://224.0.0.1/",     "https://240.0.0.1/",
                       "https://255.255.255.255/", "https://192.0.0.5/",   "https://198.18.0.1/",
                       "https://198.51.100.9/",  "https://203.0.113.9/"};
  for (const char* u : bad) TEST_ASSERT_FALSE_MESSAGE(olostep_url_allowed(u), u);
  // range-edge controls just outside the blocked ranges
  const char* ok[] = {"https://172.15.255.255/", "https://172.32.0.1/", "https://100.63.255.255/",
                      "https://100.128.0.1/",    "https://8.8.8.8/",    "https://198.20.0.1/"};
  for (const char* u : ok) TEST_ASSERT_TRUE_MESSAGE(olostep_url_allowed(u), u);
}

void test_url_private_v6_rejected() {
  const char* bad[] = {"https://[::1]/",         "https://[::]/",           "https://[fc00::1]/",
                       "https://[fd12::1]/",     "https://[fe80::1]/",      "https://[::ffff:127.0.0.1]/",
                       "https://[::ffff:10.0.0.1]/", "https://[ff02::1]/",  "https://[2001:db8::1]/",
                       "https://[::ffff:7f00:1]/", "https://[1::2::3]/",    "https://[zzzz::1]/"};
  for (const char* u : bad) TEST_ASSERT_FALSE_MESSAGE(olostep_url_allowed(u), u);
  TEST_ASSERT_TRUE(olostep_url_allowed("https://[2606:4700::1111]/"));
  TEST_ASSERT_TRUE(olostep_url_allowed("https://[2606:4700::1111]:8443/x"));
}

void test_url_http_rejected() {
  const char* bad[] = {"http://example.com/", "ftp://example.com/", "ws://example.com/",
                       "example.com/",        "//example.com/",     "HTTP://example.com/", "https:/example.com"};
  for (const char* u : bad) TEST_ASSERT_FALSE_MESSAGE(olostep_url_allowed(u), u);
  TEST_ASSERT_TRUE(olostep_url_allowed("HTTPS://example.com/"));
}

void test_url_internal_hostnames_rejected() {
  const char* bad[] = {"https://localhost/",      "https://LOCALHOST/",     "https://foo.localhost/",
                       "https://printer.local/",  "https://db.internal/",   "https://intranet/",
                       "https://localhost./",     "https://nas.lan/",       "https://x.home.arpa/",
                       "https://x.corp/",         "https://x.intranet/",    "https://x.localdomain/",
                       "https://a..b.com/",       "https://-.com/x y"};
  for (const char* u : bad) TEST_ASSERT_FALSE_MESSAGE(olostep_url_allowed(u), u);
}

void test_url_ip_encoding_bypass_rejected() {
  const char* bad[] = {"https://2130706433/",  "https://0x7f.0.0.1/", "https://0177.0.0.1/",
                       "https://127.1/",       "https://0x7f000001/", "https://1.2.3.4.5/",
                       "https://127.0.0.1.example.com@127.0.0.1/", "https://example.com@127.0.0.1/",
                       "https://127%2e0.0.1/", "https://[::1]%25eth0/"};
  for (const char* u : bad) TEST_ASSERT_FALSE_MESSAGE(olostep_url_allowed(u), u);
}

void test_url_userinfo_and_port_edge() {
  TEST_ASSERT_FALSE(olostep_url_allowed("https://user:pass@example.com/"));
  TEST_ASSERT_FALSE(olostep_url_allowed("https://user@example.com/"));
  TEST_ASSERT_FALSE(olostep_url_allowed("https://example.com:0/"));
  TEST_ASSERT_FALSE(olostep_url_allowed("https://example.com:99999/"));
  TEST_ASSERT_FALSE(olostep_url_allowed("https://example.com:80a/"));
  TEST_ASSERT_TRUE(olostep_url_allowed("https://example.com:8443/path"));
}

void test_url_public_https_allowed() {
  TEST_ASSERT_TRUE(olostep_url_allowed("https://example.com/path?q=1"));
  TEST_ASSERT_TRUE(olostep_url_allowed("https://8.8.8.8/"));
  TEST_ASSERT_TRUE(olostep_url_allowed("https://sub.example.co.uk:443/"));
  TEST_ASSERT_TRUE(olostep_url_allowed("https://example.com./"));
}

void test_ip_blocked_helpers_match_url_rules() {
  const uint8_t meta[4] = {169, 254, 169, 254};
  const uint8_t pub[4] = {8, 8, 8, 8};
  TEST_ASSERT_TRUE(olostep_ip_is_blocked_v4(meta));
  TEST_ASSERT_FALSE(olostep_ip_is_blocked_v4(pub));
  const uint8_t lo6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  const uint8_t pub6[16] = {0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11};
  TEST_ASSERT_TRUE(olostep_ip_is_blocked_v6(lo6));
  TEST_ASSERT_FALSE(olostep_ip_is_blocked_v6(pub6));
}

// ---- Egress at the job level ----------------------------------------------------------------

void test_job_lan_save_html_endpoint_rejected() {
  Job j = plainJob();
  j.save_html_endpoint = "https://192.168.1.5/x";
  expectRejected(j);
}

void test_job_lan_error_callback_endpoint_rejected() {
  Job j = plainJob();
  j.error_callback_endpoint = "https://10.0.0.7/err";
  expectRejected(j);
}

void test_job_lan_method_endpoint_rejected() {
  Job j = plainJob();
  j.method_endpoint = "https://192.168.0.1/admin";
  expectRejected(j);
}

void test_job_lan_alt_url_rejected() {
  Job j = plainJob();
  j.url = "https://169.254.169.254/latest/meta-data/";
  expectRejected(j);
}

void test_job_http_method_endpoint_rejected() {
  Job j = plainJob();
  j.method_endpoint = "http://example.com/";
  expectRejected(j);
}

void test_job_missing_method_endpoint_rejected() {
  Job j = plainJob();
  j.method_endpoint.clear();
  expectRejected(j);
}

void test_job_alt_url_alone_permitted() {
  Job j;
  j.url = "https://example.com/a";
  TEST_ASSERT_TRUE(olostep_job_is_permitted(j));
}

void test_job_with_public_callbacks_permitted() {
  Job j = plainJob();
  j.save_html_endpoint = "https://results.example.org/save";
  j.error_callback_endpoint = "https://results.example.org/err";
  TEST_ASSERT_TRUE(olostep_job_is_permitted(j));
}

// ---- Header-injection (CRLF) and canonical names ---------------------------------------------

void test_job_header_value_with_crlf_rejected() {
  Job j = plainJob();
  j.method_headers["Accept"] = "x\r\nCookie: x";
  expectRejected(j);
  Job k = plainJob();
  k.method_headers["Accept"] = "x\nAuthorization: Bearer t";
  expectRejected(k);
}

void test_job_useragent_with_crlf_rejected() {
  Job j = plainJob();
  j.userAgent = "ua\r\nAuthorization: Bearer t";
  expectRejected(j);
  Job ok = plainJob();
  ok.userAgent = "Mozilla/5.0 (X11; Linux x86_64)";
  TEST_ASSERT_TRUE(olostep_job_is_permitted(ok));  // control: a benign UA is fine
}

void test_job_control_chars_in_header_name_or_value_rejected() {
  const std::string bad[] = {std::string("a\0b", 3), std::string("a\x1f" "b"), std::string("a\x7f" "b"),
                             std::string("a\tb"), std::string("a\rb")};
  for (const std::string& v : bad) {
    Job j = plainJob();
    j.method_headers["Accept"] = v;  // value
    expectRejected(j);
    Job k = plainJob();
    k.method_headers[std::string("Acc") + v] = "text/html";  // name
    expectRejected(k);
  }
}

void test_sanitize_crlf_value_emits_no_cookie_or_newline() {
  HeaderMap in;
  in["Accept"] = "x\r\nCookie: y";
  in["User-Agent"] = "ua\r\nAuthorization: Bearer t";
  in["Referer"] = "https://example.com/";  // control: a clean header survives
  const HeaderMap out = olostep_sanitize_outbound_headers(in);
  TEST_ASSERT_EQUAL(1, (int)out.size());
  TEST_ASSERT_EQUAL(1, (int)out.count("referer"));
  for (const auto& kv : out) {
    TEST_ASSERT_TRUE(kv.first.find_first_of(std::string("\r\n\0", 3)) == std::string::npos);
    TEST_ASSERT_TRUE(kv.second.find_first_of(std::string("\r\n\0", 3)) == std::string::npos);
    TEST_ASSERT_FALSE(hasCI(kv.second, "cookie"));
  }
}

void test_sanitize_nul_and_control_chars_dropped() {
  HeaderMap in;
  in[std::string("Accept\0", 7)] = "text/html";                 // NUL in name
  in["Accept-Language"] = std::string("en\0us", 5);            // NUL in value
  in["Accept-Encoding"] = std::string("gzip\x1f");              // 0x1f in value
  in["User-Agent"] = std::string("ua\x7f");                     // DEL in value
  TEST_ASSERT_EQUAL(0, (int)olostep_sanitize_outbound_headers(in).size());
}

void test_sanitize_canonicalizes_name() {
  HeaderMap in;
  in[" Accept\t"] = "text/html";
  in["USER-AGENT"] = "ua";
  const HeaderMap out = olostep_sanitize_outbound_headers(in);
  TEST_ASSERT_EQUAL(2, (int)out.size());
  TEST_ASSERT_EQUAL(1, (int)out.count("accept"));
  TEST_ASSERT_EQUAL(1, (int)out.count("user-agent"));
  TEST_ASSERT_EQUAL(0, (int)out.count(" Accept\t"));
}

void test_url_documentation_and_teredo_ranges_rejected() {
  const char* bad[] = {"https://192.0.2.1/", "https://192.88.99.1/", "https://[2001::1]/",
                       "https://[2001:0:4136:e378:8000:63bf:3fff:fdd2]/", "https://[64:ff9b:1::1]/",
                       "https://[100::1]/"};
  for (const char* u : bad) TEST_ASSERT_FALSE_MESSAGE(olostep_url_allowed(u), u);
  // controls just outside the new ranges
  TEST_ASSERT_TRUE(olostep_url_allowed("https://192.0.3.1/"));
  TEST_ASSERT_TRUE(olostep_url_allowed("https://192.88.98.1/"));
  TEST_ASSERT_TRUE(olostep_url_allowed("https://[2001:4860:4860::8888]/"));
}

// ---- Class-aware handling -------------------------------------------------------------------

void test_classify_unauthenticated_types() {
  TEST_ASSERT_EQUAL(OlostepJobClass::Unauthenticated, olostep_classify_job(""));
  TEST_ASSERT_EQUAL(OlostepJobClass::Unauthenticated, olostep_classify_job("batch"));
}

void test_classify_authenticated_partner_types() {
  const char* ev[] = {"rufus_batch", "amazon_reviews", "meta_batch",  "copilot_batch",
                      "chatgpt_batch", "gemini_batch", "perplexity_batch", "meta_login",
                      "create_cplt_session", "reset_meta"};
  for (const char* e : ev) TEST_ASSERT_EQUAL_MESSAGE(OlostepJobClass::AuthenticatedPartner, olostep_classify_job(e), e);
}

void test_classify_unknown_type() {
  TEST_ASSERT_EQUAL(OlostepJobClass::Unknown, olostep_classify_job("random_thing"));
  TEST_ASSERT_EQUAL(OlostepJobClass::Unknown, olostep_classify_job("RUFUS_BATCH"));
  TEST_ASSERT_EQUAL(OlostepJobClass::Unknown, olostep_classify_job("foo"));
}

void test_authenticated_partner_job_with_session_id_accepted() {
  Job j = plainJob();
  j.type_event = "rufus_batch";
  j.session_id = "sess123";
  j.lease_node = "node-7";
  TEST_ASSERT_EQUAL(OlostepJobClass::AuthenticatedPartner, olostep_job_classify_and_permit(j));
}

void test_authenticated_partner_job_with_auth_headers_accepted() {
  Job j = plainJob();
  j.type_event = "rufus_batch";
  j.method_headers["cookie"] = "abc";
  j.method_headers["authorization"] = "Bearer xyz";
  TEST_ASSERT_EQUAL(OlostepJobClass::AuthenticatedPartner, olostep_job_classify_and_permit(j));
}

void test_unknown_type_event_rejected() {
  Job j = plainJob();
  j.type_event = "unknown_thing";
  TEST_ASSERT_EQUAL(OlostepJobClass::Unknown, olostep_job_classify_and_permit(j));
}

void test_unauthenticated_with_session_id_still_rejected() {
  Job j = plainJob();
  j.session_id = "sess123";
  TEST_ASSERT_EQUAL(OlostepJobClass::Unknown, olostep_job_classify_and_permit(j));
  Job ok = plainJob();
  TEST_ASSERT_EQUAL(OlostepJobClass::Unauthenticated, olostep_job_classify_and_permit(ok));  // control
}

void test_auth_headers_pass_through_for_partner() {
  HeaderMap in = {{"cookie", "abc"}, {"authorization", "Bearer xyz"}, {"accept", "text/html"}};
  const HeaderMap out = olostep_sanitize_outbound_headers(in, OlostepJobClass::AuthenticatedPartner);
  TEST_ASSERT_EQUAL(3, (int)out.size());
  TEST_ASSERT_EQUAL(1, (int)out.count("cookie"));
  TEST_ASSERT_EQUAL(1, (int)out.count("authorization"));
  TEST_ASSERT_EQUAL(1, (int)out.count("accept"));
}

void test_partner_sanitizer_strips_framing_headers() {
  HeaderMap in = {{"host", "evil.com"},          {"Content-Length", "999"}, {"connection", "keep-alive"},
                  {"transfer-encoding", "chunked"}, {" TE ", "trailers"},  {"upgrade", "websocket"},
                  {"keep-alive", "5"},           {"proxy-connection", "x"}, {"trailer", "x"},
                  {"cookie", "session=abc"},     {"accept", "text/html"}};
  const HeaderMap out = olostep_sanitize_outbound_headers(in, OlostepJobClass::AuthenticatedPartner);
  TEST_ASSERT_EQUAL(0, (int)out.count("host"));
  TEST_ASSERT_EQUAL(0, (int)out.count("content-length"));
  TEST_ASSERT_EQUAL(0, (int)out.count("connection"));
  TEST_ASSERT_EQUAL(0, (int)out.count("transfer-encoding"));
  TEST_ASSERT_EQUAL(0, (int)out.count("te"));
  TEST_ASSERT_EQUAL(0, (int)out.count("upgrade"));
  TEST_ASSERT_EQUAL(0, (int)out.count("keep-alive"));
  TEST_ASSERT_EQUAL(0, (int)out.count("proxy-connection"));
  TEST_ASSERT_EQUAL(0, (int)out.count("trailer"));
  TEST_ASSERT_EQUAL(1, (int)out.count("cookie"));
  TEST_ASSERT_EQUAL(1, (int)out.count("accept"));
  TEST_ASSERT_EQUAL(2, (int)out.size());
}

void test_auth_headers_stripped_for_unauthenticated() {
  HeaderMap in = {{"cookie", "abc"}, {"authorization", "Bearer xyz"}, {"accept", "text/html"}};
  const HeaderMap out = olostep_sanitize_outbound_headers(in, OlostepJobClass::Unauthenticated);
  TEST_ASSERT_EQUAL(0, (int)out.count("cookie"));
  TEST_ASSERT_EQUAL(0, (int)out.count("authorization"));
  TEST_ASSERT_EQUAL(1, (int)out.count("accept"));
}

void test_partner_job_ssrf_still_checked() {
  Job j = plainJob();
  j.type_event = "rufus_batch";
  j.method_endpoint = "https://192.168.1.1/path";
  TEST_ASSERT_EQUAL(OlostepJobClass::Unknown, olostep_job_classify_and_permit(j));
}

void test_partner_job_crlf_still_checked() {
  Job j = plainJob();
  j.type_event = "meta_batch";
  j.method_headers["Accept"] = "x\r\nCookie: y";
  TEST_ASSERT_EQUAL(OlostepJobClass::Unknown, olostep_job_classify_and_permit(j));
}

void test_partner_job_action_fields_still_rejected() {
  Job j = plainJob();
  j.type_event = "rufus_batch";
  j.actions = "[{\"click\":\".btn\"}]";
  TEST_ASSERT_EQUAL(OlostepJobClass::Unknown, olostep_job_classify_and_permit(j));
}

void test_disclosure_mentions_authenticated() {
  TEST_ASSERT_TRUE(strstr(OLOSTEP_OWNER_DISCLOSURE, "authenticated partner sessions") != nullptr);
}

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}

void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_plain_fetch_permitted);
  RUN_TEST(test_cookie_header_rejected);
  RUN_TEST(test_authorization_header_rejected);
  RUN_TEST(test_x_api_key_header_rejected);
  RUN_TEST(test_session_id_rejected);
  RUN_TEST(test_lease_node_rejected);
  RUN_TEST(test_each_partner_type_event_now_permitted);
  RUN_TEST(test_unrecognized_type_event_rejected);
  RUN_TEST(test_each_action_field_rejected);
  RUN_TEST(test_sanitize_drops_cookie_auth_apikey_keeps_ua_accept_referer);
  RUN_TEST(test_sanitize_never_emits_auth_on_adversarial_input);
  RUN_TEST(test_capability_query_has_ali_mli_burke);
  RUN_TEST(test_set_cookie_dropped_from_response);
  RUN_TEST(test_response_is_clean_flags_set_cookie);
  RUN_TEST(test_disclosure_text_exact);
  RUN_TEST(test_feature_flag_defaults_off);
  RUN_TEST(test_url_metadata_ip_rejected);
  RUN_TEST(test_url_private_v4_rejected);
  RUN_TEST(test_url_private_v6_rejected);
  RUN_TEST(test_url_http_rejected);
  RUN_TEST(test_url_internal_hostnames_rejected);
  RUN_TEST(test_url_ip_encoding_bypass_rejected);
  RUN_TEST(test_url_userinfo_and_port_edge);
  RUN_TEST(test_url_public_https_allowed);
  RUN_TEST(test_ip_blocked_helpers_match_url_rules);
  RUN_TEST(test_job_lan_save_html_endpoint_rejected);
  RUN_TEST(test_job_lan_error_callback_endpoint_rejected);
  RUN_TEST(test_job_lan_method_endpoint_rejected);
  RUN_TEST(test_job_lan_alt_url_rejected);
  RUN_TEST(test_job_http_method_endpoint_rejected);
  RUN_TEST(test_job_missing_method_endpoint_rejected);
  RUN_TEST(test_job_alt_url_alone_permitted);
  RUN_TEST(test_job_with_public_callbacks_permitted);
  RUN_TEST(test_job_header_value_with_crlf_rejected);
  RUN_TEST(test_job_useragent_with_crlf_rejected);
  RUN_TEST(test_job_control_chars_in_header_name_or_value_rejected);
  RUN_TEST(test_sanitize_crlf_value_emits_no_cookie_or_newline);
  RUN_TEST(test_sanitize_nul_and_control_chars_dropped);
  RUN_TEST(test_sanitize_canonicalizes_name);
  RUN_TEST(test_url_documentation_and_teredo_ranges_rejected);
  RUN_TEST(test_classify_unauthenticated_types);
  RUN_TEST(test_classify_authenticated_partner_types);
  RUN_TEST(test_classify_unknown_type);
  RUN_TEST(test_partner_sanitizer_strips_framing_headers);
  RUN_TEST(test_authenticated_partner_job_with_session_id_accepted);
  RUN_TEST(test_authenticated_partner_job_with_auth_headers_accepted);
  RUN_TEST(test_unknown_type_event_rejected);
  RUN_TEST(test_unauthenticated_with_session_id_still_rejected);
  RUN_TEST(test_auth_headers_pass_through_for_partner);
  RUN_TEST(test_auth_headers_stripped_for_unauthenticated);
  RUN_TEST(test_partner_job_ssrf_still_checked);
  RUN_TEST(test_partner_job_crlf_still_checked);
  RUN_TEST(test_partner_job_action_fields_still_rejected);
  RUN_TEST(test_disclosure_mentions_authenticated);
  return UNITY_END();
}
