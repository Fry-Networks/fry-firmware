// The ESP8266 provisioning transport holds its objects only while it runs (src/esp8266/wifi_provisioning.cpp).
//
// The web server (272 B), the DNS catch-all (68 B) and the scan cache (24 entries, 480 B) were statics: 820 B of RAM that a board which joined with
// stored credentials never uses (init() is called only when the boot policy needs the transport) and that a board provisioned this boot no longer
// needs once the AP is torn down. The heap is [_heap_start, 0x3FFFC000): every static byte is a byte the image download's TLS session does not have.
// They are allocated in init() and given back in tick() when the AP is torn down (src/core/provisioning_transport.h: "Tears down the transport once no
// longer needed"), so at OTA time nothing of the transport is held: a provisioned board never allocated it, a freshly provisioned one freed it ten
// seconds (AP_TEARDOWN_MS) after it joined, long before the first check (which waits out the boot-time TIME_WAIT, ~120 s).
//
// The source needs the Arduino core, so these are source pins (same technique as test_ota_release / test_flash_strings).
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
  const std::string tail = "test/test_prov_heap/test_main.cpp";
  std::vector<std::string> prefixes;
  if (self.size() >= tail.size() && self.compare(self.size() - tail.size(), tail.size(), tail) == 0) {
    prefixes.push_back(self.substr(0, self.size() - tail.size()));
  }
  const char* ups[] = {"", "../", "../../", "../../../", "../../../../"};
  for (size_t i = 0; i < sizeof(ups) / sizeof(ups[0]); i++) prefixes.push_back(ups[i]);
  for (size_t i = 0; i < prefixes.size(); i++) {
    if (readFile(prefixes[i] + rel, out)) return true;
  }
  return false;
}

int countOf(const std::string& hay, const std::string& needle) {
  int n = 0;
  for (size_t pos = hay.find(needle); pos != std::string::npos; pos = hay.find(needle, pos + needle.size())) n++;
  return n;
}

const char* kFile = "src/esp8266/wifi_provisioning.cpp";

// The body of `name`'s function from its signature line to the next line that is just "}" at column 0.
bool functionBody(const std::string& src, const std::string& signature, std::string& body) {
  const size_t a = src.find(signature);
  if (a == std::string::npos) return false;
  const size_t b = src.find("\n}\n", a);
  if (b == std::string::npos) return false;
  body = src.substr(a, b - a);
  return true;
}

}  // namespace

void test_the_server_the_dns_and_the_scan_cache_are_no_longer_statics() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource(kFile, src), kFile);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(src, "ESP8266WebServer s_server(80);"), "the web server is not a static object");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(src, "DNSServer s_dns;"), "the DNS catch-all is not a static object");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(src, "ScanEntry s_scanCache[kMaxScanEntries];"), "the scan cache is not a static array");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "ESP8266WebServer* s_server = nullptr;"), "a pointer, null until init()");
  TEST_ASSERT_EQUAL_INT(1, countOf(src, "DNSServer* s_dns = nullptr;"));
  TEST_ASSERT_EQUAL_INT(1, countOf(src, "ScanEntry* s_scanCache = nullptr;"));
}

void test_init_allocates_them_without_throwing_and_before_it_uses_them() {
  std::string src, body;
  TEST_ASSERT_TRUE(loadSource(kFile, src));
  TEST_ASSERT_TRUE_MESSAGE(functionBody(src, "void init(const char* deviceName, const char* minerKey) {", body), "init() is there");
  TEST_ASSERT_EQUAL_INT(1, countOf(body, "new (std::nothrow) ScanEntry[kMaxScanEntries]"));
  TEST_ASSERT_EQUAL_INT(1, countOf(body, "new (std::nothrow) DNSServer"));
  TEST_ASSERT_EQUAL_INT(1, countOf(body, "new (std::nothrow) ESP8266WebServer(80)"));
  const size_t scanAlloc = body.find("new (std::nothrow) ScanEntry[kMaxScanEntries]");
  const size_t scan = body.find("cacheScan();");
  const size_t dnsAlloc = body.find("new (std::nothrow) DNSServer");
  const size_t ap = body.find("startAp();");
  const size_t srvAlloc = body.find("new (std::nothrow) ESP8266WebServer(80)");
  const size_t on = body.find("s_server->on(\"/\"");
  TEST_ASSERT_TRUE_MESSAGE(scanAlloc < scan, "the scan cache exists before the pre-scan fills it");
  TEST_ASSERT_TRUE_MESSAGE(dnsAlloc < ap, "the DNS server exists before startAp() starts it");
  TEST_ASSERT_TRUE_MESSAGE(srvAlloc < on, "the web server exists before its routes are registered");
  TEST_ASSERT_TRUE_MESSAGE(body.find("nullptr") != std::string::npos && body.find("return;") != std::string::npos,
                           "an allocation that fails leaves the transport off instead of dereferencing null");
}

void test_the_teardown_gives_all_three_back() {
  std::string src, body;
  TEST_ASSERT_TRUE(loadSource(kFile, src));
  TEST_ASSERT_TRUE_MESSAGE(functionBody(src, "void tick() {", body), "tick() is there");
  TEST_ASSERT_TRUE_MESSAGE(body.find("WiFi.softAPdisconnect(true);") != std::string::npos, "the AP teardown is in tick()");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(body, "delete s_server;"), "the web server is deleted at teardown");
  TEST_ASSERT_EQUAL_INT(1, countOf(body, "delete s_dns;"));
  TEST_ASSERT_EQUAL_INT(1, countOf(body, "delete[] s_scanCache;"));
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(body, "s_server = nullptr;"), "and nulled, so loop() stops serving");
  TEST_ASSERT_EQUAL_INT(1, countOf(body, "s_dns = nullptr;"));
  TEST_ASSERT_EQUAL_INT(1, countOf(body, "s_scanCache = nullptr;"));
  TEST_ASSERT_TRUE_MESSAGE(body.find("s_dns->stop();") != std::string::npos, "the DNS server is stopped before it is deleted");
  TEST_ASSERT_TRUE_MESSAGE(body.find("s_dns->stop();") < body.find("delete s_dns;"), "stop, then delete");
  TEST_ASSERT_TRUE_MESSAGE(body.find("s_server->close();") != std::string::npos && body.find("s_server->close();") < body.find("delete s_server;"),
                           "the listening socket is closed before the server is deleted");
}

void test_loop_and_the_handlers_tolerate_a_transport_that_was_never_started() {
  std::string src, body;
  TEST_ASSERT_TRUE(loadSource(kFile, src));
  // main.cpp calls fry_provisioning::loop() and tick() in the Ready phase of a board that never called init().
  TEST_ASSERT_TRUE_MESSAGE(functionBody(src, "void loop() {", body), "loop() is there");
  TEST_ASSERT_TRUE_MESSAGE(body.find("if (s_dns && s_apActive)") != std::string::npos || body.find("if (s_apActive && s_dns)") != std::string::npos,
                           "the DNS pump checks the pointer");
  TEST_ASSERT_TRUE_MESSAGE(body.find("if (s_server)") != std::string::npos, "handleClient() checks the pointer");
  std::string tick;
  TEST_ASSERT_TRUE(functionBody(src, "void tick() {", tick));
  TEST_ASSERT_TRUE_MESSAGE(tick.find("s_apActive") != std::string::npos, "tick() only acts on an active AP (a never-started transport has none)");
  std::string scan;
  TEST_ASSERT_TRUE(functionBody(src, "void handleScan() {", scan));
  TEST_ASSERT_TRUE_MESSAGE(scan.find("s_scanCache") != std::string::npos && scan.find("if (s_scanCache") != std::string::npos,
                           "/api/scan does not walk a cache that was given back");
  std::string cache;
  TEST_ASSERT_TRUE(functionBody(src, "void cacheScan() {", cache));
  TEST_ASSERT_TRUE_MESSAGE(cache.find("if (!s_scanCache)") != std::string::npos, "cacheScan() does nothing without its cache");
}

void test_every_use_of_the_server_and_the_dns_goes_through_the_pointer() {
  std::string src;
  TEST_ASSERT_TRUE(loadSource(kFile, src));
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(src, "s_server."), "every use goes through the pointer");
  TEST_ASSERT_EQUAL_INT(0, countOf(src, "s_dns."));
}

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_server_the_dns_and_the_scan_cache_are_no_longer_statics);
  RUN_TEST(test_init_allocates_them_without_throwing_and_before_it_uses_them);
  RUN_TEST(test_the_teardown_gives_all_three_back);
  RUN_TEST(test_loop_and_the_handlers_tolerate_a_transport_that_was_never_started);
  RUN_TEST(test_every_use_of_the_server_and_the_dns_goes_through_the_pointer);
  return UNITY_END();
}
