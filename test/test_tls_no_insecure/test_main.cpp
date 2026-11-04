// The ESP8266 HTTPS path validates the served chain. Source-text pins (http_tls.cpp needs the Arduino core, so
// it cannot be compiled natively): no setInsecure() in any production source, the trust anchors are resident before
// the heap sample planTls() judges, a clock that is not sane ends the call before a connection exists, and the
// generated anchor header carries one root per set, the DER copies are freed before the list is installed, and the OTA
// redirects are followed by hand.
#include <unity.h>

#include <fstream>
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
  const std::string tail = "test/test_tls_no_insecure/test_main.cpp";
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

// Code only: drops // comments, so prose that names setInsecure() does not count as a call.
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

std::string productionFunction() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/esp8266/http_tls.cpp", src), "cannot read src/esp8266/http_tls.cpp");
  const std::string code = stripLineComments(src);
  const size_t at = code.find("bool beginHttpsUrl(HTTPClient& http, WiFiClientSecure& sec, const char* url, bool mflnProbeWorthwhile, bool smallReply) {");
  TEST_ASSERT_TRUE_MESSAGE(at != std::string::npos, "cannot find the 5-argument beginHttpsUrl(const char*)");
  return code.substr(at);
}

void test_no_production_source_calls_setInsecure_on_the_esp8266() {
  const char* files[] = {"src/esp8266/http_tls.cpp", "src/core/hardwareapi_client.cpp", "src/core/ota_client.cpp",
                         "src/core/telemetry.cpp", "src/main.cpp"};
  for (const char* rel : files) {
    std::string src;
    TEST_ASSERT_TRUE_MESSAGE(loadSource(rel, src), rel);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(stripLineComments(src), "setInsecure("), rel);
  }
}

void test_the_anchors_are_resident_before_the_heap_sample_and_installed_with_a_clock() {
  const std::string fn = productionFunction();
  const size_t anchors = fn.find("ensureTrustAnchors(");
  const size_t sample = fn.find("const fry::HeapSample heap{");
  const size_t plan = fn.find("fry::planTls(heap");
  TEST_ASSERT_TRUE_MESSAGE(anchors != std::string::npos && sample != std::string::npos && plan != std::string::npos,
                           "ensureTrustAnchors(), the HeapSample and planTls() must all be in beginHttpsUrl()");
  TEST_ASSERT_TRUE_MESSAGE(anchors < sample, "the anchor set must be built BEFORE the heap is sampled");
  TEST_ASSERT_EQUAL_INT(1, countOf(fn, "sec.setTrustAnchors(gTrust.list)"));
  TEST_ASSERT_EQUAL_INT(1, countOf(fn, "sec.setX509Time(now)"));
  TEST_ASSERT_TRUE_MESSAGE(fn.find("sec.setTrustAnchors(gTrust.list)") > plan, "installed after the plan chose the buffers");
}

void test_an_unsane_clock_or_an_unknown_host_ends_the_call_before_a_connection_exists() {
  const std::string fn = productionFunction();
  const size_t clock = fn.find("fry::tlsClockSane(");
  const size_t trust = fn.find("fry::trustSetForHost(");
  const size_t begin = fn.find("http.begin(sec, url)");
  TEST_ASSERT_TRUE_MESSAGE(clock != std::string::npos && trust != std::string::npos && begin != std::string::npos, "pieces present");
  TEST_ASSERT_TRUE(clock < begin && trust < begin);
  const size_t retAfterClock = fn.find("return false;", clock);
  const size_t retAfterTrust = fn.find("return false;", trust);
  TEST_ASSERT_TRUE_MESSAGE(retAfterClock < begin, "an unsane clock returns false");
  TEST_ASSERT_TRUE_MESSAGE(retAfterTrust < begin, "an unknown host returns false");
  std::string whole;
  TEST_ASSERT_TRUE(loadSource("src/esp8266/http_tls.cpp", whole));
  TEST_ASSERT_EQUAL_INT_MESSAGE(2, countOf(fn, "kickSntpIfNeeded();"), "SNTP is kicked from the clock check and from tlsStartDelayMs()");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(stripLineComments(whole), "fry::ntpRestartDue("), "rate-limited, in one helper, never in a loop");
}

void test_the_trust_line_is_logged_once_from_flash_before_planning() {
  const std::string fn = productionFunction();
  const std::string line = "tls: trust set=%s n=%u free=%u blk=%u";
  TEST_ASSERT_EQUAL_INT(1, countOf(fn, line));
  TEST_ASSERT_TRUE(fn.find(line) < fn.find("fry::planTls(heap"));
  const size_t at = fn.rfind("printf_P", fn.find(line));
  TEST_ASSERT_TRUE_MESSAGE(at != std::string::npos && fn.find(line) - at < 40, "printed with printf_P(PSTR(...))");
}

void test_the_generated_header_carries_one_root_in_each_of_three_sets() {
  std::string h;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/esp8266/tls_anchors.h", h), "cannot read src/esp8266/tls_anchors.h");
  const size_t ye = h.find("kTaHwapi[1]");
  const size_t com = h.find("kTaGithubCom[1]");
  const size_t assets = h.find("kTaGithubAssets[1]");
  const size_t fn = h.find("inline const BearSSL::X509List* anchorListFor(");
  TEST_ASSERT_TRUE(ye != std::string::npos && com != std::string::npos && assets != std::string::npos && fn != std::string::npos);
  TEST_ASSERT_TRUE(ye < com && com < assets && assets < fn);
  TEST_ASSERT_EQUAL_INT(1, countOf(h.substr(ye, com - ye), "unsigned char*>(kAnchorYeDn)"));
  TEST_ASSERT_EQUAL_INT(1, countOf(h.substr(com, assets - com), "unsigned char*>(kAnchorE46Dn)"));
  TEST_ASSERT_EQUAL_INT(1, countOf(h.substr(assets, fn - assets), "unsigned char*>(kAnchorYrDn)"));
  TEST_ASSERT_EQUAL_INT(0, countOf(h, "-----BEGIN CERTIFICATE-----"));
}

void test_the_anchors_are_flash_data_chosen_without_touching_the_heap() {
  std::string src;
  TEST_ASSERT_TRUE(loadSource("src/esp8266/http_tls.cpp", src));
  const std::string code = stripLineComments(src);
  const size_t at = code.find("bool ensureTrustAnchors(fry::TrustSet want) {");
  TEST_ASSERT_TRUE(at != std::string::npos);
  const std::string body = code.substr(at, code.find("\n}\n", at) - at);
  const size_t pick = body.find("fry::anchorListFor(want)");
  const size_t counted = body.find("getCount() != fry::trustSetCount(want)");
  const size_t kept = body.find("gTrust.list = l;");
  TEST_ASSERT_TRUE_MESSAGE(pick != std::string::npos && counted != std::string::npos && kept != std::string::npos,
                           "pick, count check and keep are all in ensureTrustAnchors()");
  TEST_ASSERT_TRUE(pick < counted && counted < kept);
  TEST_ASSERT_TRUE_MESSAGE(body.find("new ") == std::string::npos && body.find("delete ") == std::string::npos &&
                               body.find("stripDerCopies") == std::string::npos,
                           "no heap list and no DER strip");
}

// ---- the trust set is not resident between sessions (the heap stays whole for the OTA gate) ----

void test_the_release_is_defined_drops_the_selection_and_logs_from_flash() {
  std::string src;
  TEST_ASSERT_TRUE(loadSource("src/esp8266/http_tls.cpp", src));
  const std::string code = stripLineComments(src);
  const size_t at = code.find("void releaseTrustAnchors() {");
  TEST_ASSERT_TRUE_MESSAGE(at != std::string::npos, "fry_http::releaseTrustAnchors() must exist");
  const std::string body = code.substr(at, code.find("\n}\n", at) - at);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(body, "delete"), "flash data: nothing to free");
  TEST_ASSERT_EQUAL_INT(1, countOf(body, "gTrust.list = nullptr;"));
  TEST_ASSERT_EQUAL_INT(1, countOf(body, "tls: trust released free=%u blk=%u"));
  TEST_ASSERT_TRUE_MESSAGE(body.find("printf_P(PSTR(\"tls: trust released") != std::string::npos, "printed from flash");
  std::string h;
  TEST_ASSERT_TRUE(loadSource("src/core/http_tls.h", h));
  const size_t decl = h.find("void releaseTrustAnchors();");
  TEST_ASSERT_TRUE(decl != std::string::npos);
  TEST_ASSERT_TRUE_MESSAGE(h.rfind("#if defined(ARDUINO_ARCH_ESP8266)", decl) > h.rfind("#endif", decl) ||
                               h.rfind("#endif", decl) == std::string::npos,
                           "declared for the ESP8266 only");
}

void test_the_ota_check_releases_the_set_before_it_settles_and_after_the_manifest_session() {
  std::string src;
  TEST_ASSERT_TRUE(loadSource("src/core/ota_client.cpp", src));
  TEST_ASSERT_EQUAL_INT(2, countOf(src, "fry_http::releaseTrustAnchors();"));
  const size_t settle = src.find("  settleBeforeCheck();\n");
  const size_t rel = settle == std::string::npos ? std::string::npos : src.rfind("fry_http::releaseTrustAnchors();", settle);
  TEST_ASSERT_TRUE(rel != std::string::npos && settle != std::string::npos);
  TEST_ASSERT_TRUE_MESSAGE(rel < settle && settle - rel < 300, "released right before settleBeforeCheck()");
  TEST_ASSERT_TRUE_MESSAGE(src.rfind("#if defined(ARDUINO_ARCH_ESP8266)", rel) > src.rfind("#endif", rel), "ESP8266 only");
  // the manifest's last set is released at the top of the download, once the manifest's clients are destroyed and before the
  // download waits for its heap
  const size_t reset = src.find("  clients.reset();\n  return downloadAndApply(plan.url");
  const size_t dl = src.find("bool downloadAndApply(const String& url");
  const size_t second = src.find("fry_http::releaseTrustAnchors();", dl);
  const size_t settle2 = src.find("settleAfterManifest(s_blkAtCheckStart);", dl);
  TEST_ASSERT_TRUE(reset != std::string::npos && dl != std::string::npos && second != std::string::npos && settle2 != std::string::npos);
  TEST_ASSERT_TRUE_MESSAGE(second < settle2 && settle2 - second < 400, "released right before the download settles the heap");
}

void test_the_report_tick_releases_the_set_when_every_session_of_the_tick_is_over() {
  std::string src;
  TEST_ASSERT_TRUE(loadSource("src/core/hardwareapi_client.cpp", src));
  TEST_ASSERT_EQUAL_INT(1, countOf(src, "fry_http::releaseTrustAnchors();"));
  const size_t tick = src.find("void tick() {");
  const size_t end = src.find("\n}\n", tick);
  const size_t rel = src.find("fry_http::releaseTrustAnchors();", tick);
  TEST_ASSERT_TRUE(tick != std::string::npos && rel != std::string::npos && rel < end);
  TEST_ASSERT_TRUE_MESSAGE(rel > src.find("renewLease();", tick) && rel > src.find("fry_telemetry::tick();", tick) &&
                               rel > src.find("fry_ota::tick();", tick),
                           "after the OTA check, registration, telemetry and the PoC/lease sessions");
  TEST_ASSERT_TRUE_MESSAGE(src.rfind("#if defined(ARDUINO_ARCH_ESP8266)", rel) > src.rfind("#endif", rel), "ESP8266 only");
}


// ---- redirects: followed by hand, one anchor set and one heap check per hop ----

void test_every_https_get_of_the_ota_goes_through_the_hop_loop_and_the_client_does_not_follow() {
  std::string src;
  TEST_ASSERT_TRUE(loadSource("src/core/ota_client.cpp", src));
  const std::string code = stripLineComments(src);
  TEST_ASSERT_EQUAL_INT_MESSAGE(2, countOf(code, "= getFollowingHops(http, sec,"), "the manifest and the download");
  TEST_ASSERT_EQUAL_INT(1, countOf(code, "/*manifest=*/true, s_heapRefused"));
  const size_t at = code.find("static int getFollowingHops(");
  TEST_ASSERT_TRUE(at != std::string::npos);
  const std::string body = code.substr(at, code.find("\n}\n", at) - at);
  // each hop: decided, then handed to beginNextHop, which stops the old session and begins the next through beginHttpsUrl
  // (anchors + clock + heap floors)
  const size_t decide = body.find("fry::decideRedirect(");
  const size_t begin = body.find("beginNextHop(http, sec, manifest, refused, timeoutMs, blkBaseline)");
  TEST_ASSERT_TRUE(decide != std::string::npos && begin != std::string::npos);
  TEST_ASSERT_TRUE(decide < begin);
  const size_t hat = code.find("static bool beginNextHop(");
  TEST_ASSERT_TRUE(hat != std::string::npos);
  const std::string hop = code.substr(hat, code.find("\n}\n", hat) - hat);
  TEST_ASSERT_TRUE(hop.find("sec.stop();") < hop.find("fry_http::beginHttpsUrl(http, sec, static_cast<const char*>(loc),"));
  TEST_ASSERT_TRUE_MESSAGE(body.find("RedirectDecision::Follow") != std::string::npos, "only Follow continues");
  TEST_ASSERT_TRUE_MESSAGE(body.find("return -1;") < begin, "any other decision ends the request");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(hop, "applyOtaClientSettings(http, timeoutMs);"), "beginHttpsUrl re-enables following; off again per hop (test_ota_hop_heap pins the helper)");
  const size_t beginUrl = code.find("bool otaBeginUrl(");
  const std::string ob = code.substr(beginUrl, code.find("\n}\n", beginUrl) - beginUrl);
  TEST_ASSERT_TRUE(ob.find("http.setFollowRedirects(HTTPC_DISABLE_FOLLOW_REDIRECTS);") != std::string::npos);
  TEST_ASSERT_EQUAL_INT(0, countOf(body, "setInsecure"));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_no_production_source_calls_setInsecure_on_the_esp8266);
  RUN_TEST(test_the_anchors_are_resident_before_the_heap_sample_and_installed_with_a_clock);
  RUN_TEST(test_an_unsane_clock_or_an_unknown_host_ends_the_call_before_a_connection_exists);
  RUN_TEST(test_the_trust_line_is_logged_once_from_flash_before_planning);
  RUN_TEST(test_the_generated_header_carries_one_root_in_each_of_three_sets);
  RUN_TEST(test_the_anchors_are_flash_data_chosen_without_touching_the_heap);
  RUN_TEST(test_the_release_is_defined_drops_the_selection_and_logs_from_flash);
  RUN_TEST(test_the_ota_check_releases_the_set_before_it_settles_and_after_the_manifest_session);
  RUN_TEST(test_the_report_tick_releases_the_set_when_every_session_of_the_tick_is_over);
  RUN_TEST(test_every_https_get_of_the_ota_goes_through_the_hop_loop_and_the_client_does_not_follow);
  return UNITY_END();
}
