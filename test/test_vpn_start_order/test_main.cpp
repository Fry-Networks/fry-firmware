// The ESP8266 starts its SOCKS5 endpoint BEFORE the boot registration (src/main.cpp attemptWifiConnect()).
//
// fry_vpn::init() (src/esp8266/vpn_socks5.cpp) makes two persistent allocations that are never freed: `new WiFiServer(port)` (operator new(32),
// a 40 B umm_malloc block) and the listening pcb WiFiServer::begin() creates (also 40 B). umm_malloc is best-fit, so each lands in the smallest
// free block that holds it. The boot registration (a TLS POST) leaves an island of lwIP blocks for up to 120 s (the TIME_WAIT pcb): a 192 B pcb,
// a 112 B pbuf, a 104 B hole at heap offset 12544 and a 24 B segment. Started right after the registration, as before, the first 40 B block went
// into that 104 B hole whenever the pbuf next to it had not been freed yet (dl-29 and dl-31 images; heapmap-A2 maps #7 -> #8 show the two blocks),
// which splits the contiguous tail the image download needs in two: the 40 B block at 12544 cost 7968 B of the largest block (settled 30072
// instead of 38040). Started before the registration there is no island yet, so both blocks land in the boot heap's lowest fitting hole, the
// same way on every boot. Nothing waits: the relay's tick() only runs in the Ready phase, which still comes after the registration.
//
// The ESP32 family keeps the original order (its heap has no such block). The source needs the Arduino core, so these are source pins (same
// technique as test_hwapi_register_once / test_prov_heap).
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
  const std::string tail = "test/test_vpn_start_order/test_main.cpp";
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

// The body of attemptWifiConnect(): from its signature to the next line that is just "}" at column 0.
bool attemptBody(std::string& body) {
  std::string src;
  if (!loadSource("src/main.cpp", src)) return false;
  const size_t a = src.find("void attemptWifiConnect() {");
  if (a == std::string::npos) return false;
  const size_t b = src.find("\n}\n", a);
  if (b == std::string::npos) return false;
  body = src.substr(a, b - a);
  return true;
}

const char* kVpn = "fry_trigger_start_vpn();";
const char* kReg = "fry_trigger_register_now();";
const char* kIf8266 = "#if defined(ARDUINO_ARCH_ESP8266)";
const char* kIfNot8266 = "#if !defined(ARDUINO_ARCH_ESP8266)";

}  // namespace

void setUp() {}
void tearDown() {}

void test_main_is_readable() {
  std::string body;
  TEST_ASSERT_TRUE_MESSAGE(attemptBody(body), "cannot read attemptWifiConnect() from src/main.cpp");
  TEST_ASSERT_TRUE(body.find(kReg) != std::string::npos);
}

// one start call per branch: the ESP8266 one before the registration, the other one after it
void test_vpn_start_appears_once_per_branch() {
  std::string body;
  TEST_ASSERT_TRUE(attemptBody(body));
  TEST_ASSERT_EQUAL_INT_MESSAGE(2, countOf(body, kVpn), "fry_trigger_start_vpn() must be called once per branch (ESP8266 first, others after the registration)");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(body, kReg), "the registration is called once");
}

void test_esp8266_starts_the_relay_before_the_registration() {
  std::string body;
  TEST_ASSERT_TRUE(attemptBody(body));
  const size_t reg = body.find(kReg);
  const size_t first = body.find(kVpn);
  TEST_ASSERT_TRUE(reg != std::string::npos && first != std::string::npos);
  TEST_ASSERT_TRUE_MESSAGE(first < reg, "the first fry_trigger_start_vpn() must come before fry_trigger_register_now()");
  // ... and that first call sits inside an ESP8266-only block that closes before the registration
  const size_t open = body.rfind(kIf8266, first);
  TEST_ASSERT_TRUE_MESSAGE(open != std::string::npos, "the early start must be guarded by #if defined(ARDUINO_ARCH_ESP8266)");
  const size_t close = body.find("#endif", first);
  TEST_ASSERT_TRUE(close != std::string::npos && close < reg);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(body.substr(open, first - open), "#endif"), "the ESP8266 guard must still be open at the start call");
}

void test_other_boards_keep_the_original_order() {
  std::string body;
  TEST_ASSERT_TRUE(attemptBody(body));
  const size_t reg = body.find(kReg);
  const size_t second = body.find(kVpn, body.find(kVpn) + 1);
  TEST_ASSERT_TRUE(reg != std::string::npos && second != std::string::npos);
  TEST_ASSERT_TRUE_MESSAGE(second > reg, "the non-ESP8266 start must still come after the registration");
  const size_t open = body.rfind(kIfNot8266, second);
  TEST_ASSERT_TRUE_MESSAGE(open != std::string::npos && open > reg, "the late start must be guarded by #if !defined(ARDUINO_ARCH_ESP8266)");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(body.substr(open, second - open), "#endif"), "the non-ESP8266 guard must still be open at the start call");
}

// the Olostep start stays where it was: once, after the registration and after both start calls
void test_olostep_start_keeps_its_place() {
  std::string body;
  TEST_ASSERT_TRUE(attemptBody(body));
  TEST_ASSERT_EQUAL_INT(1, countOf(body, "FRY_OLOSTEP_ON_READY()"));
  const size_t olo = body.find("FRY_OLOSTEP_ON_READY()");
  TEST_ASSERT_TRUE(olo > body.find(kReg));
  TEST_ASSERT_TRUE(olo > body.rfind(kVpn));
  TEST_ASSERT_TRUE_MESSAGE(body.find("setPhase(BootPhase::Ready);") > olo, "Ready is still set after everything started");
}

// the explanation stays with the code: it names the block the order avoids
void test_comment_names_the_reason() {
  std::string body;
  TEST_ASSERT_TRUE(attemptBody(body));
  TEST_ASSERT_TRUE_MESSAGE(body.find("40 B") != std::string::npos, "the comment must name the 40 B blocks");
  TEST_ASSERT_TRUE_MESSAGE(body.find("best-fit") != std::string::npos, "the comment must name best-fit");
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_main_is_readable);
  RUN_TEST(test_vpn_start_appears_once_per_branch);
  RUN_TEST(test_esp8266_starts_the_relay_before_the_registration);
  RUN_TEST(test_other_boards_keep_the_original_order);
  RUN_TEST(test_olostep_start_keeps_its_place);
  RUN_TEST(test_comment_names_the_reason);
  return UNITY_END();
}
