// The manifest's TLS session must be gone before the image download opens its own.
//
// ota_client.cpp checkNow() keeps its manifest `HTTPClient http; WiFiClientSecure sec;` in scope when it
// calls downloadAndApply(), which builds a second WiFiClientSecure. HTTPClient::end() only closes the
// TLS session (freeing BearSSL's context and the 16709 B + 597 B I/O buffers) when keep-alive reuse is
// off (ESP8266HTTPClient.cpp:218, framework-arduinoespressif8266 3.30102.0); the default is on and
// GitHub keeps the connection, so two ~21 KB sessions were live at once on a chip with ~80 KB heap.
#include <unity.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "ota_session.h"

namespace {

const bool kEsp8266 = true;
const bool kEsp32 = false;
const bool kHttps = true;
const bool kHttp = false;
const bool kServerKeepsAlive = true;
const bool kServerCloses = false;

void test_http_end_keeps_tls_open_only_when_both_sides_allow_reuse() {
  // Mirror of ESP8266HTTPClient::disconnect(): `_reuse && _canReuse`.
  TEST_ASSERT_TRUE(fry::httpEndLeavesTlsOpen(true, true));
  TEST_ASSERT_FALSE(fry::httpEndLeavesTlsOpen(true, false));
  TEST_ASSERT_FALSE(fry::httpEndLeavesTlsOpen(false, true));
  TEST_ASSERT_FALSE(fry::httpEndLeavesTlsOpen(false, false));
}

void test_esp8266_https_manifest_session_is_closed_when_the_download_opens() {
  // The defect: against a keep-alive server (GitHub) the manifest session was still open.
  TEST_ASSERT_EQUAL_UINT_MESSAGE(
      1, fry::tlsSessionsOpenWhenDownloadOpens(kEsp8266, kHttps, kServerKeepsAlive),
      "the manifest TLS session is still open while the download's session opens");
}

void test_esp8266_https_is_one_session_whatever_the_server_does() {
  TEST_ASSERT_EQUAL_UINT(1, fry::tlsSessionsOpenWhenDownloadOpens(kEsp8266, kHttps, kServerCloses));
  TEST_ASSERT_FALSE_MESSAGE(fry::otaAsksForKeepAlive(kEsp8266, kHttps),
                            "the OTA client must not ask HTTPClient to keep the TLS connection alive");
}

void test_esp32_and_plain_http_keep_their_existing_behaviour() {
  // ESP32 (mbedtls, 4+ x the heap) is not touched; a plain-http lab server has no TLS buffers to free.
  TEST_ASSERT_TRUE(fry::otaAsksForKeepAlive(kEsp32, kHttps));
  TEST_ASSERT_TRUE(fry::otaAsksForKeepAlive(kEsp8266, kHttp));
  TEST_ASSERT_TRUE(fry::otaAsksForKeepAlive(kEsp32, kHttp));
  TEST_ASSERT_EQUAL_UINT(1, fry::tlsSessionsOpenWhenDownloadOpens(kEsp8266, kHttp, kServerKeepsAlive));
}

// ---- the OTA client must actually apply the policy ---------------------------------------------
//
// The helpers above only matter if src/core/ota_client.cpp calls them. ota_client.cpp needs the
// Arduino core, so the native tests cannot run it; like test_relay_source_pin this reads the source.
// Wanted: exactly one `http.setReuse(fry::otaAsksForKeepAlive(...))` in code (not a comment or a
// string), inside an `#if defined(ARDUINO_ARCH_ESP8266)` branch (not its #else), so the ESP32 build
// never compiles it and its image is untouched.

// Blanks comments and the contents of string and character literals; newlines survive.
std::string blankNonCode(const std::string& s) {
  std::string out(s.size(), ' ');
  enum State { Code, LineComment, BlockComment, Str, Chr } st = Code;
  for (size_t i = 0; i < s.size(); i++) {
    const char c = s[i];
    const char n = i + 1 < s.size() ? s[i + 1] : '\0';
    if (c == '\n') out[i] = '\n';
    switch (st) {
      case Code:
        if (c == '/' && n == '/') {
          st = LineComment;
          i++;
        } else if (c == '/' && n == '*') {
          st = BlockComment;
          i++;
        } else if (c == '"') {
          st = Str;
          out[i] = '"';
        } else if (c == '\'') {
          st = Chr;
          out[i] = '\'';
        } else if (c != '\n') {
          out[i] = c;
        }
        break;
      case LineComment:
        if (c == '\n') st = Code;
        break;
      case BlockComment:
        if (c == '*' && n == '/') {
          st = Code;
          i++;
        }
        break;
      case Str:
      case Chr: {
        const char quote = st == Str ? '"' : '\'';
        if (c == '\\' && i + 1 < s.size()) {
          if (n == '\n') out[i + 1] = '\n';
          i++;
        } else if (c == quote) {
          st = Code;
          out[i] = quote;
        }
        break;
      }
    }
  }
  return out;
}

std::string squeeze(const std::string& line) {
  std::string o;
  for (size_t i = 0; i < line.size(); i++) {
    if (line[i] != ' ' && line[i] != '\t' && line[i] != '\r') o.push_back(line[i]);
  }
  return o;
}

// Number of policy calls found, and how many of them sit in an ESP8266-only branch.
struct PolicyCalls {
  int total;
  int onEsp8266Only;
};
PolicyCalls countPolicyCalls(const std::string& source) {
  const std::string code = blankNonCode(source);
  const std::string needle = "http.setReuse(fry::otaAsksForKeepAlive(";
  // One entry per open #if: true while inside the branch that is compiled only on ESP8266.
  std::vector<bool> stack;
  PolicyCalls r = {0, 0};
  std::string cur;
  for (size_t i = 0; i <= code.size(); i++) {
    if (i < code.size() && code[i] != '\n') {
      cur.push_back(code[i]);
      continue;
    }
    const std::string line = squeeze(cur);
    if (!line.empty() && line[0] == '#') {
      // Directive name from the unsqueezed text: squeezed, "#if defined(X)" would read as "#ifdef".
      size_t d = 0;
      while (d < cur.size() && (cur[d] == ' ' || cur[d] == '\t')) d++;
      d++;  // '#'
      while (d < cur.size() && (cur[d] == ' ' || cur[d] == '\t')) d++;
      size_t e = d;
      while (e < cur.size() && ((cur[e] >= 'a' && cur[e] <= 'z') || (cur[e] >= 'A' && cur[e] <= 'Z')))
        e++;
      const std::string name = cur.substr(d, e - d);
      const std::string rest = squeeze(cur.substr(e));
      if (name == "if") {
        const bool esp = rest == "defined(ARDUINO_ARCH_ESP8266)";
        stack.push_back(esp);
      } else if (name == "ifdef" || name == "ifndef") {
        stack.push_back(false);
      } else if ((name == "else" || name == "elif") && !stack.empty()) {
        stack.back() = false;  // the other branch of the condition
      } else if (name == "endif" && !stack.empty()) {
        stack.pop_back();
      }
      cur.clear();
      continue;
    }
    cur.clear();
    size_t pos = 0;
    // `line` has no blanks, so search the needle without them too.
    const std::string needleSq = squeeze(needle);
    while ((pos = line.find(needleSq, pos)) != std::string::npos) {
      r.total++;
      bool esp = false;
      for (size_t k = 0; k < stack.size(); k++) esp = esp || stack[k];
      if (esp) r.onEsp8266Only++;
      pos += needleSq.size();
    }
  }
  return r;
}

bool readFile(const std::string& path, std::string& out) {
  std::ifstream f(path.c_str(), std::ios::in | std::ios::binary);
  if (!f) return false;
  std::ostringstream ss;
  ss << f.rdbuf();
  out = ss.str();
  return !out.empty();
}

// src/core/ota_client.cpp, found relative to this test (the compiler's __FILE__ is absolute or
// relative to the project directory) or a few directories up from where the test runs.
bool loadOtaClient(std::string& out) {
  const std::string rel = "src/core/ota_client.cpp";
  const std::string self = __FILE__;
  const std::string tail = "test/test_ota_session/test_main.cpp";
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

void test_the_scanner_sees_a_guarded_call_and_rejects_the_rest() {
  // Controls: a pass on the real file must not come from a scanner that sees nothing.
  const std::string good =
      "bool otaBeginUrl() {\n#if defined(ARDUINO_ARCH_ESP8266)\n  http.setReuse(fry::otaAsksForKeepAlive(true, true));\n#endif\n}\n";
  PolicyCalls r = countPolicyCalls(good);
  TEST_ASSERT_EQUAL_INT(1, r.total);
  TEST_ASSERT_EQUAL_INT(1, r.onEsp8266Only);

  r = countPolicyCalls("bool otaBeginUrl() {\n  return true;\n}\n");
  TEST_ASSERT_EQUAL_INT(0, r.total);

  r = countPolicyCalls("void f() {\n  http.setReuse(fry::otaAsksForKeepAlive(true, true));\n}\n");
  TEST_ASSERT_EQUAL_INT(1, r.total);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, r.onEsp8266Only, "an unguarded call reaches the ESP32 build");

  r = countPolicyCalls(
      "#if defined(ARDUINO_ARCH_ESP8266)\n#else\n  http.setReuse(fry::otaAsksForKeepAlive(true, true));\n#endif\n");
  TEST_ASSERT_EQUAL_INT(1, r.total);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, r.onEsp8266Only, "the #else branch is the ESP32 one");

  r = countPolicyCalls(
      "// http.setReuse(fry::otaAsksForKeepAlive(true, true));\n/* http.setReuse(fry::otaAsksForKeepAlive(1,1)); */\n"
      "const char* s = \"http.setReuse(fry::otaAsksForKeepAlive(\";\n");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, r.total, "comments and strings are not code");
}

void test_ota_client_applies_the_keepalive_policy_on_esp8266_only() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadOtaClient(src), "cannot read src/core/ota_client.cpp");
  const PolicyCalls r = countPolicyCalls(src);
  TEST_ASSERT_EQUAL_INT_MESSAGE(
      1, r.total,
      "ota_client.cpp must call http.setReuse(fry::otaAsksForKeepAlive(...)) once, in otaBeginUrl, "
      "so neither the manifest session nor the download session outlives its http.end()");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, r.onEsp8266Only,
                                "the call must sit inside #if defined(ARDUINO_ARCH_ESP8266)");
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_http_end_keeps_tls_open_only_when_both_sides_allow_reuse);
  RUN_TEST(test_esp8266_https_manifest_session_is_closed_when_the_download_opens);
  RUN_TEST(test_esp8266_https_is_one_session_whatever_the_server_does);
  RUN_TEST(test_esp32_and_plain_http_keep_their_existing_behaviour);
  RUN_TEST(test_the_scanner_sees_a_guarded_call_and_rejects_the_rest);
  RUN_TEST(test_ota_client_applies_the_keepalive_policy_on_esp8266_only);
  return UNITY_END();
}
