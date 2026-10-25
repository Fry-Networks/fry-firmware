// Stale-token self-heal, the wiring (src/core/hardwareapi_client.cpp).
//
// hardwareapi_client.cpp needs the Arduino core, so this is a source pin (the technique of
// test_hwapi_stack / test_hwapi_register_once). It pins the properties review cares about:
// only the stale-token signature fires; the shadow pair exists before the live pair is cleared and
// a failed retry puts it back byte for byte; the retry is exactly one token-less POST; the heal is
// bounded to one per boot and one per 6 h; exactly one masked log line per heal; the FEM key, the
// wireguard config, apiBase, Wi-Fi and every fry_ota/rbk key are never touched.
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
  const std::string tail = "test/test_stale_token_heal_wiring/test_main.cpp";
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

// From `signature` to the first line that is exactly "}" at column 0 (the function's own close).
bool functionBody(const std::string& src, const std::string& signature, std::string& out) {
  const size_t a = src.find(signature);
  if (a == std::string::npos) return false;
  const size_t b = src.find("\n}\n", a);
  if (b == std::string::npos) return false;
  out = src.substr(a, b - a);
  return true;
}

bool between(const std::string& src, const std::string& from, const std::string& to, std::string& out) {
  const size_t a = src.find(from);
  if (a == std::string::npos) return false;
  const size_t b = src.find(to, a + from.size());
  if (b == std::string::npos) return false;
  out = src.substr(a, b - a);
  return true;
}

bool hwapi(std::string& src) { return loadSource("src/core/hardwareapi_client.cpp", src); }

// The whole self-heal block: the three NVS helpers plus healStaleTokenIfDue.
bool healBlock(std::string& out) {
  std::string src;
  if (!hwapi(src)) return false;
  return between(src, "bool stashTokenPair() {", "\n}  // namespace\n", out);
}

void test_only_the_stale_token_signature_can_reach_the_heal() {
  std::string heal;
  TEST_ASSERT_TRUE_MESSAGE(healBlock(heal), "cannot find the stale-token heal block");
  TEST_ASSERT_TRUE_MESSAGE(heal.find("!fry::isStaleTokenSignature(code, tokenSent)") != std::string::npos,
                           "the helper refuses anything but the signature");
  TEST_ASSERT_TRUE_MESSAGE(heal.find("if (!fry::healWindowOpen(s_staleTokenHealed, lastHeal, epochNow)) return false;") !=
                               std::string::npos,
                           "and anything outside the boot/6 h window");
  // One per boot, and the persisted epoch one per 6 h. Both are written BEFORE the pair is touched.
  std::string fn;
  TEST_ASSERT_TRUE(functionBody(heal, "bool healStaleTokenIfDue(", fn));
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "s_staleTokenHealed = true;"), "the per-boot bound is set exactly once");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "putUInt(\"healAt\", epochNow)"), "the 6 h bound is persisted exactly once");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "getUInt(\"healAt\", 0)"), "and read back before deciding");
  TEST_ASSERT_TRUE(fn.find("s_staleTokenHealed = true;") < fn.find("stashTokenPair()"));
  TEST_ASSERT_TRUE(fn.find("putUInt(\"healAt\", epochNow)") < fn.find("stashTokenPair()"));
}

void test_the_shadow_pair_is_written_before_the_live_pair_is_cleared() {
  std::string fn;
  TEST_ASSERT_TRUE(healBlock(fn));
  std::string body;
  TEST_ASSERT_TRUE(functionBody(fn, "bool healStaleTokenIfDue(", body));
  const size_t stash = body.find("stashTokenPair()");
  const size_t clear = body.find("fry_config::clearInstallation()");
  const size_t retry = body.find("http.POST(");
  TEST_ASSERT_TRUE_MESSAGE(stash != std::string::npos, "the pair is stashed first");
  TEST_ASSERT_TRUE_MESSAGE(clear != std::string::npos, "then the live pair is cleared");
  TEST_ASSERT_TRUE_MESSAGE(stash < clear, "shadow BEFORE clear: no path may leave the board with neither pair");
  TEST_ASSERT_TRUE(clear < retry);
  // clearInstallation() is the existing accessor: it removes fry/installId and fry/deviceToken and
  // nothing else (the FEM key, Wi-Fi, apiBase and the vpn/ota namespaces are not its business).
  std::string cfg;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/core/fry_config.cpp", cfg), "cannot read src/core/fry_config.cpp");
  std::string clearBody;
  TEST_ASSERT_TRUE(functionBody(cfg, "void clearInstallation() {", clearBody));
  TEST_ASSERT_EQUAL_INT(2, countOf(clearBody, "p.remove("));
  TEST_ASSERT_TRUE(clearBody.find("p.remove(\"installId\")") != std::string::npos);
  TEST_ASSERT_TRUE(clearBody.find("p.remove(\"deviceToken\")") != std::string::npos);
}

void test_a_failed_retry_restores_the_original_pair_byte_for_byte() {
  std::string src;
  TEST_ASSERT_TRUE(hwapi(src));
  std::string restore;
  TEST_ASSERT_TRUE(functionBody(src, "bool restoreTokenPair() {", restore));
  // Shadow read, then the live pair written back through the existing accessors (the very two
  // keys, no transformation anywhere), then the equality check, and only then the shadows go.
  const size_t readId = restore.find("r.getString(\"shadowInstallId\", \"\")");
  const size_t readTok = restore.find("r.getString(\"shadowDeviceToken\", \"\")");
  const size_t writeId = restore.find("fry_config::setInstallId(id.c_str())");
  const size_t writeTok = restore.find("fry_config::setDeviceToken(tok.c_str())");
  const size_t verify = restore.find("fry::pairsMatchByteForByte(");
  const size_t drop = restore.find("dropTokenPairShadow();");
  TEST_ASSERT_TRUE(readId != std::string::npos && readTok != std::string::npos);
  TEST_ASSERT_TRUE(writeId != std::string::npos && writeTok != std::string::npos);
  TEST_ASSERT_TRUE(readId < writeId && readTok < writeTok);
  TEST_ASSERT_TRUE_MESSAGE(verify != std::string::npos && drop != std::string::npos, "the restore is verified before the shadows go");
  TEST_ASSERT_TRUE_MESSAGE(verify < drop, "byte-for-byte equality is checked BEFORE the shadows are dropped");
  // A failed retry calls it: the failure branch is the only caller inside the heal.
  std::string body;
  TEST_ASSERT_TRUE(functionBody(src, "bool healStaleTokenIfDue(", body));
  const size_t fail = body.find("if (healCode < 200 || healCode >= 300) {");
  TEST_ASSERT_TRUE_MESSAGE(fail != std::string::npos, "any non-2xx retry is a failure");
  TEST_ASSERT_TRUE_MESSAGE(body.find("restoreTokenPair();", fail) != std::string::npos, "and restores the pair");
}

void test_the_retry_is_exactly_one_token_less_post() {
  std::string body;
  TEST_ASSERT_TRUE(healBlock(body));
  std::string fn;
  TEST_ASSERT_TRUE(functionBody(body, "bool healStaleTokenIfDue(", fn));
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "http.POST("), "ONE token-less retry, never a loop");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(fn, "addAuthHeader("),
                                "no Authorization header at all: clearing the token must not fall back to FRY_API_TOKEN");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "beginHttpsUrl("), "one attempt, no quick-retry loop");
  // The success path persists the fresh token, and only after the 2xx check.
  const size_t ok = fn.find("if (healCode < 200 || healCode >= 300) {");
  TEST_ASSERT_TRUE(ok != std::string::npos && fn.find("setDeviceToken(") > ok);
  // Exactly one log line, and it carries no token bytes (only present/none).
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "FRY_PRINTF("), "exactly one masked serial line per heal");
  TEST_ASSERT_TRUE(fn.find("token.length() > 0 ? \"present\" : \"none\"") != std::string::npos);
  const size_t print = fn.find("FRY_PRINTF(");
  const size_t printEnd = fn.find(");", print);
  TEST_ASSERT_TRUE(printEnd != std::string::npos);
  TEST_ASSERT_TRUE_MESSAGE(fn.substr(print, printEnd - print).find("token.c_str()") == std::string::npos,
                           "the token value is never printed");
}

void test_the_shadow_pair_survives_until_an_accepted_heartbeat_follows() {
  std::string src;
  TEST_ASSERT_TRUE(hwapi(src));
  std::string poc;
  TEST_ASSERT_TRUE(functionBody(src, "int putPoc() {", poc));
  const size_t end = poc.find("http.end();");
  const size_t drop = poc.find("if (code >= 200 && code < 300) dropTokenPairShadow();");
  TEST_ASSERT_TRUE_MESSAGE(end != std::string::npos && drop != std::string::npos,
                           "putPoc() drops the shadows only on an accepted heartbeat");
  TEST_ASSERT_TRUE(drop > end && drop < poc.find("fry_ota::noteHeartbeat(code, \"poc\")"));
  // The heal itself never drops them: only restoreTokenPair() (after a verified restore) does.
  std::string fn;
  TEST_ASSERT_TRUE(functionBody(src, "bool healStaleTokenIfDue(", fn));
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(fn, "dropTokenPairShadow()"),
                                "a successful heal keeps the shadows for the heartbeat that follows");
}

void test_nothing_outside_the_install_id_and_token_keys_is_written() {
  std::string heal;
  TEST_ASSERT_TRUE(healBlock(heal));
  // The only NVS keys the self-heal creates are the two shadows and fry/healAt; the live pair is
  // put back only through fry_config's own accessors (which write exactly installId/deviceToken).
  TEST_ASSERT_EQUAL_INT(1, countOf(heal, "putString(\"shadowInstallId\""));
  TEST_ASSERT_EQUAL_INT(1, countOf(heal, "putString(\"shadowDeviceToken\""));
  TEST_ASSERT_EQUAL_INT(1, countOf(heal, "fry_config::setInstallId("));
  TEST_ASSERT_EQUAL_INT_MESSAGE(2, countOf(heal, "fry_config::setDeviceToken("),
                                "the restore, and the fresh token of a successful heal");
  TEST_ASSERT_EQUAL_INT_MESSAGE(2, countOf(heal, "putString(\""),
                                "the only keys this block writes directly are the two shadows");
  TEST_ASSERT_EQUAL_INT(2, countOf(heal, "remove(\"shadow"));  // restore's verified drop + putPoc's drop
  // The FEM key, Wi-Fi, apiBase, the wireguard config and every fry_ota/rbk key are untouched.
  const char* forbidden[] = {"minerKey", "setMinerKey", "clearWifi", "setApiBase", "fry_vpn",
                             "fry_ota", "bootfails", "\"rbk\"", "setOtaPending", "ota_health"};
  for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); i++) {
    TEST_ASSERT_TRUE_MESSAGE(heal.find(forbidden[i]) == std::string::npos, forbidden[i]);
  }
}

void test_the_heal_is_reached_only_from_the_registration_4xx_branch() {
  std::string src;
  TEST_ASSERT_TRUE(hwapi(src));
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "healStaleTokenIfDue(http, sec, url"), "one call site in the whole client");
  std::string branch;
  TEST_ASSERT_TRUE_MESSAGE(between(src, "if (!fry::regClassRetryQuickly(cls)) {", "break;", branch),
                           "cannot find the registration 4xx branch");
  TEST_ASSERT_TRUE(branch.find("healStaleTokenIfDue(http, sec, url, installId, body, code, deviceTokenSent)") != std::string::npos);
  // And the signature's second half is the token that actually rode on the attempt.
  TEST_ASSERT_TRUE(src.find("const bool deviceTokenSent = fry_config::getDeviceToken().length() > 0;") != std::string::npos);
  std::string reg;
  TEST_ASSERT_TRUE(functionBody(src, "bool registerInstallation() {", reg));
  TEST_ASSERT_TRUE(reg.find("const bool deviceTokenSent") < reg.find("healStaleTokenIfDue("));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_only_the_stale_token_signature_can_reach_the_heal);
  RUN_TEST(test_the_shadow_pair_is_written_before_the_live_pair_is_cleared);
  RUN_TEST(test_a_failed_retry_restores_the_original_pair_byte_for_byte);
  RUN_TEST(test_the_retry_is_exactly_one_token_less_post);
  RUN_TEST(test_the_shadow_pair_survives_until_an_accepted_heartbeat_follows);
  RUN_TEST(test_nothing_outside_the_install_id_and_token_keys_is_written);
  RUN_TEST(test_the_heal_is_reached_only_from_the_registration_4xx_branch);
  return UNITY_END();
}
