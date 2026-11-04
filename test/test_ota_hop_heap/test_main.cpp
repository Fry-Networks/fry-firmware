// A redirect hop must hand the heap back in one piece before the next session begins. Source-text pins (ota_client.cpp and
// http_tls.cpp need the Arduino core, so they cannot be compiled natively):
//  - between two hops the unread bytes are read (bounded in bytes and in time), the session is stopped, the Location is copied
//    AFTER the stop, the HTTP client is rebuilt so its old Strings are freed, and the next hop is begun from the copy;
//  - a rebuilt client gets back every setting the callers gave the first one;
//  - only a heap refusal marks the check "retry soon"; a clock, host or anchor failure takes the normal failure path.
#include <unity.h>

#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

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
  const std::string tail = "test/test_ota_hop_heap/test_main.cpp";
  std::vector<std::string> prefixes;
  if (self.size() >= tail.size() && self.compare(self.size() - tail.size(), tail.size(), tail) == 0) {
    prefixes.push_back(self.substr(0, self.size() - tail.size()));
  }
  const char* ups[] = {"", "../", "../../", "../../../", "../../../../"};
  for (const char* u : ups) prefixes.push_back(u);
  for (const std::string& p : prefixes) {
    if (readFile(p + rel, out)) return true;
  }
  return false;
}

int countOf(const std::string& hay, const std::string& needle) {
  int n = 0;
  for (size_t at = hay.find(needle); at != std::string::npos; at = hay.find(needle, at + needle.size())) n++;
  return n;
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

// The text of the function whose signature starts with `sig`, up to its closing brace at column 0.
std::string functionBody(const std::string& code, const std::string& sig) {
  const size_t at = code.find(sig);
  if (at == std::string::npos) return std::string();
  const size_t end = code.find("\n}\n", at);
  return code.substr(at, end == std::string::npos ? std::string::npos : end - at);
}

std::string otaCode() {
  std::string src;
  if (!loadSource("src/core/ota_client.cpp", src)) return std::string();
  return stripLineComments(src);
}

void test_a_hop_gives_the_heap_back_in_order_before_the_next_session_begins() {
  const std::string code = otaCode();
  TEST_ASSERT_FALSE_MESSAGE(code.empty(), "cannot read src/core/ota_client.cpp");
  const std::string loop = functionBody(code, "static int getFollowingHops(");
  const std::string body = functionBody(code, "static bool beginNextHop(");
  TEST_ASSERT_FALSE(loop.empty());
  TEST_ASSERT_FALSE(body.empty());
  TEST_ASSERT_TRUE(loop.find("fry::decideRedirect(") < loop.find("beginNextHop(http, sec, manifest, refused, timeoutMs)"));
  const size_t drain = body.find("drainUnread(sec);");
  const size_t copy = body.find("memcpy(loc, got.c_str(), n + 1);");
  const size_t stop = body.find("sec.stop();");
  const size_t rebuild = body.find("rebuildHttpClient(http);");
  const size_t begin = body.find("fry_http::beginHttpsUrl(http, sec, static_cast<const char*>(loc),");
  const size_t settings = body.find("applyOtaClientSettings(http, timeoutMs);");
  TEST_ASSERT_TRUE(drain != std::string::npos && stop != std::string::npos);
  TEST_ASSERT_TRUE(copy != std::string::npos && rebuild != std::string::npos && begin != std::string::npos);
  TEST_ASSERT_TRUE(settings != std::string::npos);
  TEST_ASSERT_TRUE_MESSAGE(drain < copy && copy < stop && stop < rebuild && rebuild < begin && begin < settings,
                           "read what is left, copy the Location to the stack, stop, rebuild the client, begin from the copy, settings");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(body, "getLocation(),"), "the next hop is begun from the copy, never from the client's own String");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(body, "String loc"), "the copy is on the stack (test_ota_hop_stack pins the bound)");
}

void test_the_unread_bytes_are_dropped_within_a_byte_count_and_a_time_bound() {
  const std::string code = otaCode();
  const std::string fn = functionBody(code, "static void drainUnread(");
  TEST_ASSERT_FALSE(fn.empty());
  const size_t w = fn.find("while (");
  TEST_ASSERT_TRUE(w != std::string::npos);
  const std::string cond = fn.substr(w, fn.find(')', fn.find("available()", w)) - w);
  TEST_ASSERT_TRUE_MESSAGE(cond.find("kHopDrainBytes") != std::string::npos, "bounded in bytes");
  TEST_ASSERT_TRUE_MESSAGE(cond.find("kHopDrainMs") != std::string::npos && cond.find("millis()") != std::string::npos, "bounded in time");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(fn, "delay("), "the drain never waits");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(code, "drainUnread(sec);"), "one use, in the hop loop");
  TEST_ASSERT_TRUE(code.find("constexpr uint32_t kHopDrainMs = 250;") != std::string::npos);
  TEST_ASSERT_TRUE(code.find("constexpr uint16_t kHopDrainBytes = 2048;") != std::string::npos);
}

void test_the_http_client_is_rebuilt_not_cleared_because_clear_keeps_the_string_buffers() {
  const std::string code = otaCode();
  const std::string fn = functionBody(code, "static void rebuildHttpClient(");
  TEST_ASSERT_FALSE(fn.empty());
  TEST_ASSERT_TRUE(fn.find("http.~HTTPClient();") != std::string::npos);
  TEST_ASSERT_TRUE(fn.find("new (&http) HTTPClient();") != std::string::npos);
  TEST_ASSERT_TRUE_MESSAGE(fn.find("http.~HTTPClient();") < fn.find("new (&http) HTTPClient();"), "destroy first");
  // ESP8266HTTPClient.cpp: end() = disconnect() + clear(); clear() = _headers.clear(); _location.clear(): lengths only.
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(fn, "http.end()"), "end() would leave the Location buffer allocated");
}

void test_a_rebuilt_client_gets_every_setting_the_callers_gave_the_first_one() {
  const std::string code = otaCode();
  const std::string fn = functionBody(code, "static void applyOtaClientSettings(");
  TEST_ASSERT_FALSE(fn.empty());
  TEST_ASSERT_TRUE(fn.find("http.setTimeout(timeoutMs);") != std::string::npos);
  TEST_ASSERT_TRUE(fn.find("http.setFollowRedirects(HTTPC_DISABLE_FOLLOW_REDIRECTS);") != std::string::npos);
  TEST_ASSERT_TRUE(fn.find("const bool keepAlive = fry::otaAsksForKeepAlive(/*isEsp8266=*/true, /*isHttps=*/true);") != std::string::npos);
  TEST_ASSERT_TRUE(fn.find("http.setReuse(keepAlive);") != std::string::npos);
  // The first client's keep-alive is chosen in otaBeginUrl from the same call.
  const std::string ob = functionBody(code, "bool otaBeginUrl(");
  TEST_ASSERT_TRUE(ob.find("http.setReuse(fry::otaAsksForKeepAlive(/*isEsp8266=*/true, /*isHttps=*/true));") != std::string::npos);
  // Both callers pass their timeout: the manifest the client's default, the download the 20 s it sets before its first GET.
  TEST_ASSERT_TRUE(code.find("constexpr uint16_t kManifestTimeoutMs = HTTPCLIENT_DEFAULT_TCP_TIMEOUT;") != std::string::npos);
  TEST_ASSERT_TRUE(code.find("constexpr uint16_t kDownloadTimeoutMs = 20000;") != std::string::npos);
  TEST_ASSERT_TRUE(code.find("http.setTimeout(20000);") != std::string::npos);
  TEST_ASSERT_EQUAL_INT(1, countOf(code, "/*manifest=*/false, s_heapRefused, kDownloadTimeoutMs)"));
  TEST_ASSERT_EQUAL_INT(1, countOf(code, "/*manifest=*/true, s_heapRefused, kManifestTimeoutMs)"));
  // Any other setter on the OTA client has to be added to applyOtaClientSettings first: the set below is what exists today.
  std::set<std::string> seen;
  for (const char* prefix : {"http.set", "http.add", "http.use", "http.collect"}) {
    for (size_t at = code.find(prefix); at != std::string::npos; at = code.find(prefix, at + 1)) {
      const size_t paren = code.find('(', at);
      seen.insert(code.substr(at, paren - at));
    }
  }
  const std::set<std::string> allowed = {"http.setTimeout", "http.setFollowRedirects", "http.setReuse", "http.setRedirectLimit"};
  for (const std::string& s : seen) {
    TEST_ASSERT_TRUE_MESSAGE(allowed.count(s) == 1, ("new HTTPClient setter, add it to applyOtaClientSettings: " + s).c_str());
  }
}

void test_only_a_heap_refusal_marks_the_check_retry_soon() {
  const std::string code = otaCode();
  // Every assignment is guarded by the flag, except the manifest's own gate (a heap gate, before any begin).
  TEST_ASSERT_EQUAL_INT(2, countOf(code, "fry_http::lastRefusalWasHeap()) s_heapRefused = true;"));
  TEST_ASSERT_EQUAL_INT(1, countOf(code, "if (fry_http::lastRefusalWasHeap()) refused = true;"));
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(code, "refused = true;\n"), "the hop helper sets nothing unguarded");
  std::string tls;
  TEST_ASSERT_TRUE(loadSource("src/esp8266/http_tls.cpp", tls));
  const std::string t = stripLineComments(tls);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(t, "s_lastRefusalHeap = true;"), "set only where planTls refuses");
  const size_t set = t.find("s_lastRefusalHeap = true;");
  const size_t refuse = t.find("case fry::TlsSizing::Refuse:");
  const size_t next = t.find("case fry::TlsSizing::Small:");
  TEST_ASSERT_TRUE(refuse != std::string::npos && next != std::string::npos && refuse < set && set < next);
  const size_t top = t.find("bool beginHttpsUrl(HTTPClient& http, WiFiClientSecure& sec, const char* url, bool mflnProbeWorthwhile, bool smallReply) {");
  TEST_ASSERT_TRUE(top != std::string::npos);
  TEST_ASSERT_TRUE_MESSAGE(t.find("s_lastRefusalHeap = false;", top) < t.find("fry::trustSetForHost(", top), "cleared on entry");
  std::string h;
  TEST_ASSERT_TRUE(loadSource("src/core/http_tls.h", h));
  TEST_ASSERT_TRUE(h.find("bool lastRefusalWasHeap();") != std::string::npos);
}

void test_the_trust_comments_and_the_layout_check_are_in_place() {
  std::string trust;
  TEST_ASSERT_TRUE(loadSource("lib/fry_core/tls_trust.h", trust));
  TEST_ASSERT_TRUE(trust.find("cross-signed forms") != std::string::npos);
  TEST_ASSERT_TRUE(trust.find("same name and key as the self-signed root") != std::string::npos);
  std::string tls;
  TEST_ASSERT_TRUE(loadSource("src/esp8266/http_tls.cpp", tls));
  const std::string code = stripLineComments(tls);
  TEST_ASSERT_TRUE_MESSAGE(code.find("stripDerCopies") == std::string::npos, "no heap list exists, so there are no DER copies to strip");
  const std::string fn = functionBody(code, "bool ensureTrustAnchors(fry::TrustSet want) {");
  TEST_ASSERT_FALSE(fn.empty());
  const size_t log = fn.find("anchor list layout unexpected");
  TEST_ASSERT_TRUE_MESSAGE(log != std::string::npos && fn.find("return false;", log) != std::string::npos, "a list that does not read back as expected fails closed");
  TEST_ASSERT_TRUE_MESSAGE(log < fn.find("gTrust.list = l;"), "and is never installed");
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_a_hop_gives_the_heap_back_in_order_before_the_next_session_begins);
  RUN_TEST(test_the_unread_bytes_are_dropped_within_a_byte_count_and_a_time_bound);
  RUN_TEST(test_the_http_client_is_rebuilt_not_cleared_because_clear_keeps_the_string_buffers);
  RUN_TEST(test_a_rebuilt_client_gets_every_setting_the_callers_gave_the_first_one);
  RUN_TEST(test_only_a_heap_refusal_marks_the_check_retry_soon);
  RUN_TEST(test_the_trust_comments_and_the_layout_check_are_in_place);
  return UNITY_END();
}
