// The format strings and text pieces of the ESP8266 build that are not Serial prints stay in flash (lib/fry_core/flash_fmt.h).
//
// test_flash_strings pins the Serial text (src/core/flash_print.h). What is left in DRAM after it is the rest of our literals: snprintf
// formats, String pieces appended to a JSON body, strftime formats. The ESP8266 keeps a plain literal in DRAM and the heap is whatever
// static RAM leaves, so each byte here is a byte the image download's TLS session does not have. The call is FRY_SNPRINTF (lib/fry_core,
// shared with the ESP32 family and the host, where it expands to the snprintf it always was) or, in an ESP8266-only file, snprintf_P(PSTR()),
// `+= F("..")`, send_P. The output text does not change: the c1 string-table diff of the image and the literal multiset of each file are the
// proof, and the existing tests that read those texts are unchanged.
//
// The sources need the Arduino core, so these are source pins (same technique as test_flash_strings / test_ota_release).
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
  const std::string tail = "test/test_flash_text/test_main.cpp";
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

bool identChar(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'; }

// `name(` not preceded by an identifier character (so FRY_SNPRINTF( and snprintf_P( are not snprintf( ), skipping // comment lines.
int rawCalls(const std::string& src, const std::string& name) {
  const std::string call = name + "(";
  int n = 0;
  for (size_t pos = src.find(call); pos != std::string::npos; pos = src.find(call, pos + call.size())) {
    if (pos > 0 && identChar(src[pos - 1])) continue;
    const size_t ls = src.rfind('\n', pos);
    const size_t first = src.find_first_not_of(" \t", ls == std::string::npos ? 0 : ls + 1);
    if (first != std::string::npos && src.compare(first, 2, "//") == 0) continue;
    n++;
  }
  return n;
}

void expectNoRawCall(const char* rel, const char* name) {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource(rel, src), rel);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, rawCalls(src, name), rel);
}

// `<call>(<first arg>, "literal"`: a call whose SECOND argument is a string literal (the content type of ESP8266WebServer::send / send_P).
int callsWithLiteralSecondArg(const std::string& src, const std::string& call) {
  int n = 0;
  for (size_t pos = src.find(call); pos != std::string::npos; pos = src.find(call, pos + call.size())) {
    if (pos > 0 && identChar(src[pos - 1]) && src[pos - 1] != '.') continue;
    const size_t comma = src.find(',', pos);
    if (comma == std::string::npos) break;
    size_t i = comma + 1;
    while (i < src.size() && (src[i] == ' ' || src[i] == '\t' || src[i] == '\n' || src[i] == '\r')) i++;
    if (i < src.size() && src[i] == '"') n++;
  }
  return n;
}

void expectNoPiece(const char* rel, const char* piece) {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource(rel, src), rel);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(src, piece), piece);
}

}  // namespace

void test_the_macro_reads_its_format_from_flash_on_the_esp8266_and_keeps_snprintf_elsewhere() {
  std::string h;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("lib/fry_core/flash_fmt.h", h), "cannot read lib/fry_core/flash_fmt.h");
  const size_t esp8266 = h.find("#if defined(ARDUINO_ARCH_ESP8266)");
  const size_t other = h.find("#else");
  TEST_ASSERT_TRUE_MESSAGE(esp8266 != std::string::npos && other != std::string::npos && esp8266 < other, "ESP8266 branch, then the rest");
  const std::string a = h.substr(esp8266, other - esp8266);
  const std::string b = h.substr(other);
  TEST_ASSERT_EQUAL_INT(1, countOf(a, "#define FRY_SNPRINTF(out, n, fmt, ...) snprintf_P((out), (n), PSTR(fmt), ##__VA_ARGS__)"));
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(b, "#define FRY_SNPRINTF(out, n, fmt, ...) snprintf((out), (n), fmt, ##__VA_ARGS__)"),
                                "the ESP32 family and the host keep the call they had");
}

void test_telemetry_body_formats_from_flash() {
  expectNoRawCall("lib/fry_core/telemetry_body.cpp", "snprintf");
  std::string src;
  TEST_ASSERT_TRUE(loadSource("lib/fry_core/telemetry_body.cpp", src));
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "FRY_SNPRINTF("), "the one format of the telemetry body");
}

void test_wifi_provisioning_keeps_its_text_in_flash() {
  const char* f = "src/esp8266/wifi_provisioning.cpp";
  expectNoRawCall(f, "snprintf");
  expectNoPiece(f, "+= \"");               // String pieces: += F("..")
  expectNoPiece(f, "String out = \"");     // String out = F("..")
  std::string src;
  TEST_ASSERT_TRUE(loadSource(f, src));
  // out += cond ? F("true") : F("false") in the two JSON builders; the one left is the %s argument of the status snprintf (a RAM pointer).
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "? \"true\" : \"false\""), "only the %s argument of the status snprintf keeps its RAM literals");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, callsWithLiteralSecondArg(src, "s_server->send("), "send(): the content type is a temporary String from F(), not a RAM literal");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, callsWithLiteralSecondArg(src, "s_server->send_P("), "send_P(): PSTR() for the content type");
}

void test_fry_text_is_a_flash_string_on_the_esp8266_and_the_plain_pointer_elsewhere() {
  std::string h;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/core/flash_print.h", h), "cannot read src/core/flash_print.h");
  const size_t esp8266 = h.find("#if defined(ARDUINO_ARCH_ESP8266)");
  const size_t other = h.find("#else");
  TEST_ASSERT_TRUE_MESSAGE(esp8266 != std::string::npos && other != std::string::npos && esp8266 < other, "ESP8266 branch, then the rest");
  const std::string a = h.substr(esp8266, other - esp8266);
  const std::string b = h.substr(other);
  TEST_ASSERT_EQUAL_INT(1, countOf(a, "typedef const __FlashStringHelper* FryText;"));
  TEST_ASSERT_EQUAL_INT(1, countOf(a, "#define FRY_TEXT(text) F(text)"));
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(b, "typedef const char* FryText;"), "the ESP32 family keeps the const char* it passed");
  TEST_ASSERT_EQUAL_INT(1, countOf(b, "#define FRY_TEXT(text) text"));
}

void test_main_keeps_its_text_in_flash() {
  const char* f = "src/main.cpp";
  expectNoRawCall(f, "snprintf");
  expectNoPiece(f, "restartToApply(\"");        // restartToApply(FRY_TEXT("..")): the message is a flash string
  expectNoPiece(f, "restartToApply(const char*");
  std::string src;
  TEST_ASSERT_TRUE(loadSource(f, src));
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "void restartToApply(FryText why) {"), "the helper takes the text as FryText");
}

void test_telemetry_and_hardwareapi_keep_their_header_names_and_url_pieces_in_flash() {
  // Shared literals are merged by the linker, so the header names ("Content-Type", "application/json", "Authorization") only leave DRAM when
  // BOTH files give them up: one test, one commit. FRY_TEXT is the flash string on the ESP8266 and the plain literal on the ESP32 family.
  const char* files[] = {"src/core/telemetry.cpp", "src/core/hardwareapi_client.cpp"};
  for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
    expectNoPiece(files[i], "addHeader(\"");   // addHeader(FRY_TEXT("Name"), ..)
    expectNoPiece(files[i], "+ \"/");          // getApiBase() + FRY_TEXT("/path/")
  }
  std::string hw;
  TEST_ASSERT_TRUE(loadSource("src/core/hardwareapi_client.cpp", hw));
  TEST_ASSERT_TRUE_MESSAGE(countOf(hw, "FRY_TEXT(\"/installations/\")") == 3, "three uses of the installations path: register (twice) and the lease");
  TEST_ASSERT_TRUE(countOf(hw, "FRY_TEXT(\"Content-Type\"), FRY_TEXT(\"application/json\")") == 3);
  std::string tel;
  TEST_ASSERT_TRUE(loadSource("src/core/telemetry.cpp", tel));
  TEST_ASSERT_TRUE(countOf(tel, "FRY_TEXT(\"Authorization\")") == 1 && countOf(tel, "FRY_TEXT(\"Content-Type\"), FRY_TEXT(\"application/json\")") == 1);
}

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_macro_reads_its_format_from_flash_on_the_esp8266_and_keeps_snprintf_elsewhere);
  RUN_TEST(test_telemetry_body_formats_from_flash);
  RUN_TEST(test_wifi_provisioning_keeps_its_text_in_flash);
  RUN_TEST(test_fry_text_is_a_flash_string_on_the_esp8266_and_the_plain_pointer_elsewhere);
  RUN_TEST(test_main_keeps_its_text_in_flash);
  RUN_TEST(test_telemetry_and_hardwareapi_keep_their_header_names_and_url_pieces_in_flash);
  return UNITY_END();
}
