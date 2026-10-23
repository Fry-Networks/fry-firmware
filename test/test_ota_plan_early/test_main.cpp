// The OTA plan's strings are allocated before the manifest session opens, not while it is live (ESP8266).
//
// checkNow() on the ESP8266 hands the download three Strings (url, sha, version) that evaluateManifest() filled while the manifest
// session's clients were still alive, and they outlive clients.reset(). umm_malloc is best-fit and carves the low end of the block it picks,
// so a String born while the session's blocks are live sits ABOVE them; the session is freed, the String stays, and it splits the free
// region the download is about to need. Bench heap map (lo/c1-hmA-171604.lines.txt, c1/reports/heapmap-A-decode.txt, snapshot dl-begin t=361308):
// a 104 B and an 88 B block at offsets 27352 / 27456 cut the largest free block from 28280 to 14768 (free total 36456).
//
// The fix takes the capacity first (OtaPlan::reserveEarly(), before ManifestClients is allocated): those blocks then sit below whatever the
// session allocates, and the assignments in evaluateManifest() copy into capacity that is already there. The ESP32 keeps one function and
// no plan. ota_client.cpp needs the Arduino core, so these are source pins (same technique as test_ota_stack); the effect is read from the
// device heap map (c1/reports/plan-early-*.txt).
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
  const std::string tail = "test/test_ota_plan_early/test_main.cpp";
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

bool checkNowBody(std::string& fn) {
  std::string src;
  if (!loadSource("src/core/ota_client.cpp", src)) return false;
  const size_t a = src.find("bool checkNow() {");
  const size_t b = src.find("FRY_OTA_ESP8266_NOINLINE static bool evaluateManifest(const String& body, OtaPlan& plan) {", a);
  if (a == std::string::npos || b == std::string::npos) return false;
  fn = src.substr(a, b - a);
  return true;
}

void test_the_plan_is_reserved_before_the_manifest_clients_exist() {
  std::string fn;
  TEST_ASSERT_TRUE_MESSAGE(checkNowBody(fn), "cannot find checkNow() in src/core/ota_client.cpp");
  const size_t plan = fn.find("OtaPlan plan;");
  const size_t reserve = fn.find("plan.reserveEarly();");
  const size_t clients = fn.find("std::unique_ptr<ManifestClients> clients(new (std::nothrow) ManifestClients());");
  TEST_ASSERT_TRUE_MESSAGE(plan != std::string::npos && reserve != std::string::npos && clients != std::string::npos,
                           "checkNow() declares the plan, reserves it, and allocates the manifest clients");
  TEST_ASSERT_TRUE_MESSAGE(plan < reserve && reserve < clients, "plan, then its capacity, then the clients (and so the session)");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "OtaPlan plan;"), "one plan, not a second one declared after the session");
  const size_t connect = fn.find("otaBeginUrl(http, sec, plain, manifestUrl, /*smallReply=*/true)");
  TEST_ASSERT_TRUE_MESSAGE(connect != std::string::npos && reserve < connect, "...and before the connect");
}

void test_the_plan_is_only_on_the_esp8266() {
  std::string fn;
  TEST_ASSERT_TRUE_MESSAGE(checkNowBody(fn), "cannot find checkNow() in src/core/ota_client.cpp");
  const size_t plan = fn.find("OtaPlan plan;");
  TEST_ASSERT_TRUE_MESSAGE(plan != std::string::npos, "OtaPlan plan; is there");
  const size_t guard = fn.rfind("#if defined(ARDUINO_ARCH_ESP8266)", plan);
  const size_t other = fn.find("#else", guard);
  const size_t end = fn.find("#endif", guard);
  TEST_ASSERT_TRUE_MESSAGE(guard != std::string::npos && end != std::string::npos && end > plan && (other == std::string::npos || other > plan),
                           "inside an ESP8266 branch, so the ESP32 images do not change");
}

void test_the_plan_reserves_every_string_it_hands_to_the_download() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/core/ota_client.cpp", src), "cannot read src/core/ota_client.cpp");
  const size_t a = src.find("struct OtaPlan {");
  const size_t b = src.find("};", a);
  TEST_ASSERT_TRUE_MESSAGE(a != std::string::npos && b != std::string::npos, "cannot find struct OtaPlan");
  const std::string st = src.substr(a, b - a);
  TEST_ASSERT_TRUE_MESSAGE(st.find("void reserveEarly()") != std::string::npos, "OtaPlan::reserveEarly() exists");
  TEST_ASSERT_TRUE_MESSAGE(st.find("url.reserve(kUrlCap);") != std::string::npos, "url");
  TEST_ASSERT_TRUE_MESSAGE(st.find("sha.reserve(kShaCap);") != std::string::npos, "sha");
  TEST_ASSERT_TRUE_MESSAGE(st.find("version.reserve(kVersionCap);") != std::string::npos, "version");
  // A 64-character digest needs 65 bytes: capacity must cover it, or the copy in evaluateManifest() reallocates above the session.
  const size_t sha = st.find("kShaCap = ");
  TEST_ASSERT_TRUE_MESSAGE(sha != std::string::npos && std::atoi(st.c_str() + sha + 10) >= 64, "kShaCap holds a 64-character sha256");
  const size_t url = st.find("kUrlCap = ");
  TEST_ASSERT_TRUE_MESSAGE(url != std::string::npos && std::atoi(st.c_str() + url + 10) >= 112,
                           "kUrlCap holds a release-asset URL (the longest published ones are about 100 characters)");
}

// The assignments in evaluateManifest(): `plan.x = <const char*>;` copies into the capacity that is already there. A temporary String on the
// right (`plan.url = String(url)`, or a conditional of Strings) is MOVE-assigned in core 3.x: String::move() frees plan.url's reserved buffer
// and takes the temporary's, which was allocated while the manifest session was live, so the reservation is thrown away and the String is
// back above the session. The bench probe's forced-download branch did exactly that: it was the 104 B / 88 B survivor of the A and X1 heap
// maps (104 = a 90-character temporary, 88 = a 64-character one: capacity (n + 16) & ~15, plus the 4 B header, in 8 B blocks).
bool evaluateManifestBody(std::string& fn) {
  std::string src;
  if (!loadSource("src/core/ota_client.cpp", src)) return false;
  const size_t a = src.find("FRY_OTA_ESP8266_NOINLINE static bool evaluateManifest(const String& body, OtaPlan& plan) {");
  const size_t b = src.find("#if defined(ARDUINO_ARCH_ESP8266)", src.find("return downloadAndApply(url, sha, latest);", a));
  if (a == std::string::npos || b == std::string::npos) return false;
  fn = src.substr(a, b - a);
  return true;
}

void test_the_plan_is_filled_from_c_strings() {
  std::string fn;
  TEST_ASSERT_TRUE_MESSAGE(evaluateManifestBody(fn), "cannot find evaluateManifest() in src/core/ota_client.cpp");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "plan.url = url;"), "plan.url is copied from the manifest's const char*");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "plan.sha = sha;"), "plan.sha too");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "plan.version = latest;"), "plan.version too");
  TEST_ASSERT_EQUAL_INT_MESSAGE(3, countOf(fn, "plan."), "and nothing else touches the plan: no String temporaries, no std::move");
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_plan_is_reserved_before_the_manifest_clients_exist);
  RUN_TEST(test_the_plan_is_only_on_the_esp8266);
  RUN_TEST(test_the_plan_reserves_every_string_it_hands_to_the_download);
  RUN_TEST(test_the_plan_is_filled_from_c_strings);
  return UNITY_END();
}
