// checkNow() must give back what the manifest check held before the image download opens its own TLS session.
//
// On ESP8266 the manifest HTTPClient + WiFiClientSecure + WiFiClient live in one heap block (`clients`), and the first
// WiFiClientSecure of a session mallocs BearSSL's 6200 B stack thunk. checkNow() used to hold all of that, and the manifest text
// (`body`, ~1 KB) and the URL, across the whole download: the download's heap gate and its begin-time floors
// (lib/fry_core/ota_heap_budget.h) were then measured against a heap that still carried them, and the manifest's thunk and clients
// sat in the middle of the region the 16 KB receive buffer needs. They are released first; the download builds its own.
//
// ota_client.cpp needs the Arduino core, so these are source pins (same technique as test_ota_stack / test_tls_medium).
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
  const std::string tail = "test/test_ota_release/test_main.cpp";
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

void test_the_manifest_clients_can_be_released_so_they_are_not_const() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/core/ota_client.cpp", src), "cannot read src/core/ota_client.cpp");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "std::unique_ptr<ManifestClients> clients(new (std::nothrow) ManifestClients());"),
                                "checkNow() holds the manifest clients in a unique_ptr it can reset");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(src, "const std::unique_ptr<ManifestClients>"),
                                "...which therefore must not be const");
}

void test_checkNow_releases_clients_body_and_url_before_it_calls_downloadAndApply() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/core/ota_client.cpp", src), "cannot read src/core/ota_client.cpp");
  const std::string release =
      "  if (!evaluateManifest(body, plan)) return false;\n"
      "  // The manifest check is over: give back what it held before the download opens its own session.\n"
      "  body = String();\n"
      "  manifestUrl = String();\n"
      "  clients.reset();\n"
      "  return downloadAndApply(plan.url, plan.sha, plan.version);\n";
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, release),
                                "evaluateManifest -> release body, url, clients (thunk with them) -> downloadAndApply");
  // Nothing may touch the references into `clients` after the reset.
  const size_t reset = src.find("  clients.reset();\n");
  const size_t dl = src.find("return downloadAndApply(plan.url", reset);
  TEST_ASSERT_TRUE(reset != std::string::npos && dl != std::string::npos && dl > reset);
  const std::string between = src.substr(reset, dl - reset);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(between, "http.") + countOf(between, "sec.") + countOf(between, "plain"),
                                "http, sec and plain are references into the released block");
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_manifest_clients_can_be_released_so_they_are_not_const);
  RUN_TEST(test_checkNow_releases_clients_body_and_url_before_it_calls_downloadAndApply);
  return UNITY_END();
}
