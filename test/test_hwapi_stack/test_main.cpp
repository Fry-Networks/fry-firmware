// registerInstallation() keeps its text buffers and its TLS clients off the 4 KB loop stack on the ESP8266.
//
// It sits on the deepest boot-time path: loop() -> fry_hwapi::tick() -> registerInstallation() -> the TLS connect below it, a few hundred
// bytes from the end of the cont stack. -fstack-usage at ebd99f1/40fafc8 gave it a 736 B frame; bench cf (free cont stack at the end of
// the registration interval) read 944 / 1152 / 1152 before the heartbeat heap fields and 736 with them (lo/c1-p5dl-162612.lines.txt), so the
// boot path was one 208 B step from the edge. What it holds across the connect is now in heap blocks, the technique ota_client.cpp's
// ManifestClients / DownloadWork use: the four char buffers for the whole call (RegText), the WiFiClientSecure + HTTPClient for one attempt
// (RegClients). The ESP32 branch keeps the original locals, so its image is unchanged.
//
// hardwareapi_client.cpp needs the Arduino core, so these are source pins (same technique as test_ota_release / test_ota_stack); the frame
// itself is read from a real -fstack-usage build (c1/logs/stackbudget-*.log).
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
  const std::string tail = "test/test_hwapi_stack/test_main.cpp";
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

// The text of registerInstallation(): from its signature to the next function.
bool registerInstallationBody(std::string& fn) {
  std::string src;
  if (!loadSource("src/core/hardwareapi_client.cpp", src)) return false;
  const size_t a = src.find("bool registerInstallation() {");
  const size_t b = src.find("int lastRegisterHttp()", a);
  if (a == std::string::npos || b == std::string::npos) return false;
  fn = src.substr(a, b - a);
  return true;
}

// True when `needle` occurs exactly once in `fn` and that occurrence is in the #else branch of an ARDUINO_ARCH_ESP8266 guard
// (the ESP32 side), not in the ESP8266 branch.
bool onlyOnTheEsp32Side(const std::string& fn, const std::string& needle) {
  if (countOf(fn, needle) != 1) return false;
  const size_t at = fn.find(needle);
  const size_t guard = fn.rfind("#if defined(ARDUINO_ARCH_ESP8266)", at);
  const size_t other = fn.rfind("#else", at);
  if (guard == std::string::npos || other == std::string::npos || guard > other) return false;
  return fn.find("#endif", other) > at;
}

void test_the_text_buffers_are_one_heap_block_on_esp8266() {
  std::string fn;
  TEST_ASSERT_TRUE_MESSAGE(registerInstallationBody(fn), "cannot find registerInstallation() in src/core/hardwareapi_client.cpp");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "std::unique_ptr<RegText> text(new (std::nothrow) RegText());"),
                                "the four char buffers come from one block, allocated once per call");
  TEST_ASSERT_TRUE_MESSAGE(onlyOnTheEsp32Side(fn, "char minerKey[40];"), "minerKey[40] stays a stack array only on the ESP32");
  TEST_ASSERT_TRUE_MESSAGE(onlyOnTheEsp32Side(fn, "char installId[40];"), "installId[40] stays a stack array only on the ESP32");
  TEST_ASSERT_TRUE_MESSAGE(onlyOnTheEsp32Side(fn, "char deviceName[32];"), "deviceName[32] stays a stack array only on the ESP32");
  TEST_ASSERT_TRUE_MESSAGE(onlyOnTheEsp32Side(fn, "char detail[128] = {0};"), "detail[128] stays a stack array only on the ESP32");
}

void test_the_tls_clients_are_one_heap_block_per_attempt_on_esp8266() {
  std::string fn;
  TEST_ASSERT_TRUE_MESSAGE(registerInstallationBody(fn), "cannot find registerInstallation() in src/core/hardwareapi_client.cpp");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "std::unique_ptr<RegClients> clients(new (std::nothrow) RegClients());"),
                                "one block per attempt, destroyed at the end of the attempt like the stack objects were");
  TEST_ASSERT_TRUE_MESSAGE(onlyOnTheEsp32Side(fn, "WiFiClientSecure sec;"), "the clients stay stack objects only on the ESP32");
  TEST_ASSERT_TRUE_MESSAGE(onlyOnTheEsp32Side(fn, "HTTPClient http;"), "...both of them");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "WiFiClientSecure& sec = clients->sec;"), "the rest of the attempt is unchanged: sec, http by reference");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "HTTPClient& http = clients->http;"), "...");
}

void test_the_blocks_are_declared_for_the_esp8266_only() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/core/hardwareapi_client.cpp", src), "cannot read src/core/hardwareapi_client.cpp");
  const size_t text = src.find("struct RegText {");
  const size_t clients = src.find("struct RegClients {");
  TEST_ASSERT_TRUE_MESSAGE(text != std::string::npos && clients != std::string::npos, "RegText and RegClients are defined");
  const size_t guard = src.rfind("#if defined(ARDUINO_ARCH_ESP8266)", text);
  TEST_ASSERT_TRUE_MESSAGE(guard != std::string::npos && src.find("#endif", guard) > clients,
                           "both inside one ARDUINO_ARCH_ESP8266 guard");
  TEST_ASSERT_TRUE_MESSAGE(countOf(src, "#include <memory>") == 1 && countOf(src, "#include <new>") == 1,
                           "<memory> and <new> come in for it, once each");
  const size_t mem = src.find("#include <memory>");
  const size_t memGuard = src.rfind("#if defined(ARDUINO_ARCH_ESP8266)", mem);
  TEST_ASSERT_TRUE_MESSAGE(memGuard != std::string::npos && src.find("#endif", memGuard) > mem, "...under the same guard");
}

void test_the_failure_to_allocate_ends_the_call_like_an_unreachable_server() {
  std::string fn;
  TEST_ASSERT_TRUE_MESSAGE(registerInstallationBody(fn), "cannot find registerInstallation() in src/core/hardwareapi_client.cpp");
  // Out of memory for the text block: nothing to register with, report it and let tick()'s schedule decide (return false, no state touched).
  const size_t t = fn.find("if (!text) {");
  TEST_ASSERT_TRUE_MESSAGE(t != std::string::npos && fn.find("return false;", t) < fn.find("fry_identity::ensureMinerKey", t),
                           "no text block: return false before anything is read or sent");
  // No client block for an attempt: leave the loop with code=-1 / Unreachable so the normal failure bookkeeping (backoff, log) runs.
  const size_t c = fn.find("if (!clients) {");
  TEST_ASSERT_TRUE_MESSAGE(c != std::string::npos && fn.find("break;", c) < fn.find("beginHttpsUrl", c),
                           "no client block: leave the attempt loop before the connect");
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_text_buffers_are_one_heap_block_on_esp8266);
  RUN_TEST(test_the_tls_clients_are_one_heap_block_per_attempt_on_esp8266);
  RUN_TEST(test_the_blocks_are_declared_for_the_esp8266_only);
  RUN_TEST(test_the_failure_to_allocate_ends_the_call_like_an_unreachable_server);
  return UNITY_END();
}
