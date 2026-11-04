// A redirect's Location rides the stack, not the heap, from the response until the next hop's heap sample. Source-text pins
// (ota_client.cpp and http_tls.cpp need the Arduino core, so they cannot be compiled natively):
//  - getFollowingHops hands each hop to beginNextHop, which copies the Location into a bounded stack buffer, refuses a longer
//    one (fail closed) and only then stops the session and rebuilds the client;
//  - the buffer lives in beginNextHop's frame alone, so it is gone before the next GET() runs the TLS handshake;
//  - the next hop begins from the C string, and beginHttpsUrl takes its heap sample before anything it allocates for the URL.
#include <unity.h>

#include <fstream>
#include <sstream>
#include <string>

namespace {

bool readFile(const std::string& path, std::string& out) {
  std::ifstream f(path.c_str(), std::ios::in | std::ios::binary);
  if (!f) return false;
  std::ostringstream ss;
  ss << f.rdbuf();
  out = ss.str();
  return !out.empty();
}

bool loadSource(const std::string& rel, std::string& out) {
  const std::string self = __FILE__;
  const std::string tail = "test/test_ota_hop_stack/test_main.cpp";
  if (self.size() >= tail.size() && self.compare(self.size() - tail.size(), tail.size(), tail) == 0 &&
      readFile(self.substr(0, self.size() - tail.size()) + rel, out))
    return true;
  for (const char* u : {"", "../", "../../", "../../../"}) {
    if (readFile(std::string(u) + rel, out)) return true;
  }
  return false;
}

std::string stripLineComments(const std::string& s) {
  std::string out;
  std::istringstream in(s);
  std::string line;
  while (std::getline(in, line)) {
    const size_t at = line.find("//");
    const bool urlColon = at != std::string::npos && at > 0 && line[at - 1] == ':';
    out += (at == std::string::npos || urlColon) ? line : line.substr(0, at);
    out += '\n';
  }
  return out;
}

std::string functionBody(const std::string& code, const std::string& sig) {
  const size_t at = code.find(sig);
  if (at == std::string::npos) return std::string();
  const size_t end = code.find("\n}\n", at);
  return code.substr(at, end == std::string::npos ? std::string::npos : end - at);
}

int countOf(const std::string& hay, const std::string& needle) {
  int n = 0;
  for (size_t p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + needle.size())) n++;
  return n;
}

std::string otaCode() {
  std::string s;
  loadSource("src/core/ota_client.cpp", s);
  return stripLineComments(s);
}

void test_the_location_is_copied_to_a_bounded_stack_buffer_before_the_session_is_stopped() {
  const std::string code = otaCode();
  TEST_ASSERT_TRUE(code.find("constexpr size_t kHopLocationMax = 1280;") != std::string::npos);
  const std::string fn = functionBody(code, "static bool beginNextHop(");
  TEST_ASSERT_FALSE(fn.empty());
  TEST_ASSERT_EQUAL_INT(1, countOf(fn, "char loc[kHopLocationMax + 1];"));
  const size_t drain = fn.find("drainUnread(sec);");
  const size_t refuse = fn.find("if (n > kHopLocationMax) {");
  const size_t copy = fn.find("memcpy(loc, got.c_str(), n + 1);");
  const size_t stop = fn.find("sec.stop();");
  const size_t rebuild = fn.find("rebuildHttpClient(http);");
  const size_t begin = fn.find("fry_http::beginHttpsUrl(http, sec, static_cast<const char*>(loc),");
  TEST_ASSERT_TRUE(drain != std::string::npos && refuse != std::string::npos && copy != std::string::npos);
  TEST_ASSERT_TRUE(drain < refuse && refuse < copy && copy < stop && stop < rebuild && rebuild < begin);
  TEST_ASSERT_TRUE_MESSAGE(fn.find("return false;", refuse) < copy, "a too-long Location ends the request before anything is copied");
  TEST_ASSERT_TRUE(fn.find("location too long") != std::string::npos);
  TEST_ASSERT_TRUE_MESSAGE(fn.find("String loc") == std::string::npos && fn.find("String(") == std::string::npos, "no heap copy");
  TEST_ASSERT_TRUE(fn.find("applyOtaClientSettings(http, timeoutMs);") > begin);
}

void test_the_buffer_is_in_the_helper_frame_only_and_the_loop_holds_no_string() {
  const std::string code = otaCode();
  TEST_ASSERT_EQUAL_INT(1, countOf(code, "char loc["));
  const std::string loop = functionBody(code, "static int getFollowingHops(");
  TEST_ASSERT_FALSE(loop.empty());
  TEST_ASSERT_TRUE(loop.find("beginNextHop(http, sec, manifest, refused, timeoutMs, blkBaseline)") != std::string::npos);
  TEST_ASSERT_TRUE_MESSAGE(loop.find("String") == std::string::npos, "the hop loop keeps no String across the hop");
  TEST_ASSERT_TRUE(loop.find("char ") == std::string::npos);
  const std::string helper = functionBody(code, "static bool beginNextHop(");
  TEST_ASSERT_TRUE_MESSAGE(helper.find("GET()") == std::string::npos, "no request runs under the buffer");
}

void test_begin_https_url_has_a_c_string_form_and_allocates_nothing_for_the_url_before_the_heap_sample() {
  std::string h;
  TEST_ASSERT_TRUE(loadSource("src/core/http_tls.h", h));
  TEST_ASSERT_TRUE(h.find("bool beginHttpsUrl(HTTPClient& http, WiFiClientSecure& sec, const char* url, bool mflnProbeWorthwhile, bool smallReply);") !=
                   std::string::npos);
  std::string tls;
  TEST_ASSERT_TRUE(loadSource("src/esp8266/http_tls.cpp", tls));
  const std::string t = stripLineComments(tls);
  const std::string sig = "bool beginHttpsUrl(HTTPClient& http, WiFiClientSecure& sec, const char* url, bool mflnProbeWorthwhile, bool smallReply) {";
  const size_t top = t.find(sig);
  TEST_ASSERT_TRUE(top != std::string::npos);
  const size_t sample = t.find("const fry::HeapSample heap{", top);
  TEST_ASSERT_TRUE(sample != std::string::npos);
  const std::string before = t.substr(top, sample - top);
  TEST_ASSERT_TRUE(before.find("HostName host;") != std::string::npos);
  TEST_ASSERT_TRUE_MESSAGE(before.find("String ") == std::string::npos, "no String is built before the heap sample");
  TEST_ASSERT_TRUE(before.find("extractHost(url, host.buf, sizeof(host.buf))") != std::string::npos);
  // The URL reaches the HTTP client (which builds its own Strings) only after the sample.
  TEST_ASSERT_TRUE(t.find("http.begin(sec, url)", sample) != std::string::npos);
  TEST_ASSERT_EQUAL_INT(1, countOf(t.substr(top), "http.begin(sec, url)"));
  // The String forms forward to it.
  TEST_ASSERT_TRUE(t.find("return beginHttpsUrl(http, sec, url.c_str(), mflnProbeWorthwhile, smallReply);") != std::string::npos);
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_location_is_copied_to_a_bounded_stack_buffer_before_the_session_is_stopped);
  RUN_TEST(test_the_buffer_is_in_the_helper_frame_only_and_the_loop_holds_no_string);
  RUN_TEST(test_begin_https_url_has_a_c_string_form_and_allocates_nothing_for_the_url_before_the_heap_sample);
  return UNITY_END();
}
