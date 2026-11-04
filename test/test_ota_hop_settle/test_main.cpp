// A followed redirect hop leaves nothing of the previous connection inside the region the next hop's floor sample measures.
// Source-text pins (ota_client.cpp needs the Arduino core): the order drain -> copy -> stop -> rebuild -> settle -> begin,
// a settle that is bounded and reuses fry::decideHeapSettle, and no abort anywhere in the hop path.
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
  const std::string tail = "test/test_ota_hop_settle/test_main.cpp";
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


void test_followed_hop_order_is_drain_copy_stop_rebuild_settle_begin() {
  const std::string fn = functionBody(otaCode(), "static bool beginNextHop(");
  TEST_ASSERT_FALSE(fn.empty());
  const size_t drain = fn.find("drainUnread(sec);");
  const size_t copy = fn.find("memcpy(loc, got.c_str(), n + 1);");
  const size_t stop = fn.find("sec.stop();");
  const size_t rebuild = fn.find("rebuildHttpClient(http);");
  const size_t settle = fn.find("settleAfterHop(blkBaseline)");
  const size_t begin = fn.find("fry_http::beginHttpsUrl(http, sec, static_cast<const char*>(loc),");
  TEST_ASSERT_TRUE(drain != std::string::npos && copy != std::string::npos);
  TEST_ASSERT_TRUE(stop != std::string::npos && rebuild != std::string::npos && settle != std::string::npos && begin != std::string::npos);
  TEST_ASSERT_TRUE(drain < copy && copy < stop && stop < rebuild && rebuild < settle && settle < begin);
  TEST_ASSERT_TRUE(fn.find("abort") == std::string::npos);
}

void test_no_abort_in_the_hop_path() {
  const std::string code = otaCode();
  TEST_ASSERT_EQUAL_INT(0, countOf(code, "sec.abort()") + countOf(code, "http.abort()") + countOf(code, "client.abort()"));
  const std::string loop = functionBody(code, "static int getFollowingHops(");
  TEST_ASSERT_FALSE(loop.empty());
  TEST_ASSERT_TRUE(loop.find("abort") == std::string::npos);
  const std::string fn = functionBody(code, "static bool beginNextHop(");
  TEST_ASSERT_FALSE(fn.empty());
  TEST_ASSERT_TRUE(fn.find("abort") == std::string::npos);
  // the too-long Location refusal returns before the connection is touched
  TEST_ASSERT_TRUE(fn.find("location too long") < fn.find("sec.stop();"));
}

void test_the_baseline_is_taken_once_before_the_first_request_and_passed_down() {
  const std::string loop = functionBody(otaCode(), "static int getFollowingHops(");
  const size_t base = loop.find("const uint32_t blkBaseline = fry::queryMaxFreeBlock();");
  const size_t get = loop.find("http.GET()", loop.find("for (;;)"));
  TEST_ASSERT_TRUE(base != std::string::npos && get != std::string::npos && base < get);
  TEST_ASSERT_TRUE(loop.find("beginNextHop(http, sec, manifest, refused, timeoutMs, blkBaseline)") != std::string::npos);
}

void test_the_settle_is_bounded_and_reuses_the_existing_decide_function() {
  const std::string fn = functionBody(otaCode(), "static unsigned long settleAfterHop(");
  TEST_ASSERT_FALSE(fn.empty());
  TEST_ASSERT_TRUE(fn.find("fry::decideHeapSettle(blk, blkBaseline, fry::kOtaSettleSlackBytes") != std::string::npos);
  TEST_ASSERT_TRUE(fn.find("fry::kOtaSettleMaxMs") != std::string::npos);
  TEST_ASSERT_TRUE(fn.find("delay(fry::kOtaSettlePollMs);") != std::string::npos);
  TEST_ASSERT_EQUAL_INT(1, countOf(fn, "while ("));
  // expiry only logs and returns: no early return or failure path, the floor check decides
  TEST_ASSERT_TRUE(fn.find("hop not settled") != std::string::npos);
  TEST_ASSERT_EQUAL_INT(1, countOf(fn, "return "));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_followed_hop_order_is_drain_copy_stop_rebuild_settle_begin);
  RUN_TEST(test_no_abort_in_the_hop_path);
  RUN_TEST(test_the_baseline_is_taken_once_before_the_first_request_and_passed_down);
  RUN_TEST(test_the_settle_is_bounded_and_reuses_the_existing_decide_function);
  return UNITY_END();
}
