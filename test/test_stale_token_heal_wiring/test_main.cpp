// Stale-token self-heal, the wiring (src/core/hardwareapi_client.cpp).
//
// hardwareapi_client.cpp needs the Arduino core, so this is a source pin (the technique of
// test_hwapi_stack / test_hwapi_register_once). It pins the properties review cares about:
// only the stale-token signature on a NON-default apiBase fires; the shadow pair fits NVS's 15-char
// key names and is proven by read-back before the live pair is cleared; a failed retry puts the
// pair back byte for byte; a crash mid-heal is recovered at boot before a new install id is minted;
// the retry is exactly one token-less POST; the heal is bounded to one per boot and one per 6 h;
// exactly one masked log line per heal; the FEM key, wireguard, apiBase, Wi-Fi and every
// fry_ota/rbk key are never touched.
#include <unity.h>

#include <cstring>
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

// The whole self-heal block: the NVS helpers plus healStaleTokenIfDue.
bool healBlock(std::string& out) {
  std::string src;
  if (!hwapi(src)) return false;
  return between(src, "const char* const kShadowId", "\n}  // namespace\n", out);
}

// Every NVS key name the self-heal block names literally: the two shadow constants, the healAt
// epoch, the namespace, and any accessor that still takes a literal.
std::vector<std::string> nvsKeyLiterals(const std::string& block) {
  const char* pats[] = {"begin(\"",        "putString(\"",   "getString(\"",  "remove(\"",
                        "getUInt(\"",      "putUInt(\"",    "isKey(\"",      "kShadowId = \"",
                        "kShadowToken = \""};
  std::vector<std::string> keys;
  for (size_t p = 0; p < sizeof(pats) / sizeof(pats[0]); p++) {
    const std::string pat = pats[p];
    for (size_t pos = block.find(pat); pos != std::string::npos; pos = block.find(pat, pos + pat.size())) {
      const size_t a = pos + pat.size();
      const size_t b = block.find('"', a);
      if (b == std::string::npos) continue;
      keys.push_back(block.substr(a, b - a));
    }
  }
  return keys;
}

bool hasKey(const std::vector<std::string>& v, const std::string& want) {
  for (size_t i = 0; i < v.size(); i++) {
    if (v[i] == want) return true;
  }
  return false;
}

void test_every_nvs_key_name_fits_the_platform_limit() {
  std::string heal;
  TEST_ASSERT_TRUE_MESSAGE(healBlock(heal), "cannot find the stale-token heal block");
  const std::vector<std::string> keys = nvsKeyLiterals(heal);
  // Control: the scan really found the keys (a vacuous pass would be worse than the defect).
  TEST_ASSERT_TRUE_MESSAGE(keys.size() >= 5, "the key scan found too few literals to be meaningful");
  TEST_ASSERT_TRUE(hasKey(keys, "shdwInstallId"));
  TEST_ASSERT_TRUE(hasKey(keys, "shdwDevToken"));
  TEST_ASSERT_TRUE(hasKey(keys, "healAt"));
  for (size_t i = 0; i < keys.size(); i++) {
    // NVS_KEY_NAME_MAX_SIZE is 16 INCLUDING the NUL: a 16-character name makes nvs_set_str fail and
    // the whole heal a silent no-op (the 17-char "shadowDeviceToken" did exactly that).
    TEST_ASSERT_TRUE_MESSAGE(keys[i].size() <= 15, keys[i].c_str());
    TEST_ASSERT_TRUE_MESSAGE(keys[i].size() > 0, "an empty NVS key name");
  }
  // The over-long names are gone for good.
  TEST_ASSERT_TRUE_MESSAGE(heal.find("shadowDeviceToken") == std::string::npos, "17 chars: NVS rejects it");
  TEST_ASSERT_TRUE_MESSAGE(heal.find("shadowInstallId") == std::string::npos, "15 chars but retired");
}

void test_the_stash_is_proven_by_read_back_before_anything_is_cleared() {
  std::string src;
  TEST_ASSERT_TRUE(hwapi(src));
  std::string stash;
  TEST_ASSERT_TRUE(functionBody(src, "bool stashTokenPair() {", stash));
  // Both live values must be present for a pair, then written, then READ BACK and compared.
  TEST_ASSERT_TRUE(stash.find("if (id.length() == 0 || tok.length() == 0) return false;") != std::string::npos);
  const size_t write = stash.find("w.putString(kShadowId, id)");
  const size_t reRead = stash.find("readTokenPairShadow(rid, rtok)");
  TEST_ASSERT_TRUE(write != std::string::npos && reRead != std::string::npos && write < reRead);
  TEST_ASSERT_TRUE(stash.find("rid.length() > 0 && rtok.length() > 0") != std::string::npos);
  TEST_ASSERT_TRUE(stash.find("fry::pairsMatchByteForByte(rid.c_str(), id.c_str())") != std::string::npos);
  TEST_ASSERT_TRUE(stash.find("fry::pairsMatchByteForByte(rtok.c_str(), tok.c_str())") != std::string::npos);
  // And nothing live is touched by the stash itself.
  TEST_ASSERT_TRUE(stash.find("clearInstallation") == std::string::npos);
  TEST_ASSERT_TRUE(stash.find("setInstallId") == std::string::npos);
}

void test_empty_shadows_are_never_treated_as_a_pair() {
  std::string src;
  TEST_ASSERT_TRUE(hwapi(src));
  std::string restore;
  TEST_ASSERT_TRUE(functionBody(src, "bool restoreTokenPair() {", restore));
  const size_t empty = restore.find("if (id.length() == 0 || tok.length() == 0) return false;");
  const size_t firstWrite = restore.find("fry_config::setInstallId(");
  TEST_ASSERT_TRUE_MESSAGE(empty != std::string::npos, "an empty shadow must be refused");
  TEST_ASSERT_TRUE_MESSAGE(empty < firstWrite, "refused BEFORE any live value is written");
  // The caller checks the restore's result and keeps the shadows when it fails.
  std::string heal;
  TEST_ASSERT_TRUE(functionBody(src, "bool healStaleTokenIfDue(", heal));
  const size_t fail = heal.find("if (healCode < 200 || healCode >= 300) {");
  TEST_ASSERT_TRUE(fail != std::string::npos);
  TEST_ASSERT_TRUE_MESSAGE(heal.find("if (!restoreTokenPair()) {", fail) != std::string::npos,
                           "the caller must check the restore's return");
}

void test_a_crash_mid_heal_is_recovered_at_boot_before_a_new_install_id() {
  std::string src;
  TEST_ASSERT_TRUE(hwapi(src));
  std::string rec;
  TEST_ASSERT_TRUE(functionBody(src, "void recoverOrphanedTokenPair() {", rec));
  // Live pair present -> the shadows are leftovers and go; live pair empty -> restore the pair.
  TEST_ASSERT_TRUE(rec.find("fry_config::getInstallId().length() > 0 || fry_config::getDeviceToken().length() > 0") !=
                   std::string::npos);
  TEST_ASSERT_TRUE(rec.find("dropTokenPairShadow();") != std::string::npos);
  TEST_ASSERT_TRUE(rec.find("restoreTokenPair();") != std::string::npos);
  TEST_ASSERT_TRUE_MESSAGE(rec.find("ensureInstallId") == std::string::npos, "recovery must not mint an install id");
  // Called from registerInstallation, and BEFORE the install id is minted.
  std::string reg;
  TEST_ASSERT_TRUE(functionBody(src, "bool registerInstallation() {", reg));
  const size_t call = reg.find("recoverOrphanedTokenPair();");
  const size_t mint = reg.find("fry_identity::ensureInstallId(installId, sizeof(installId));");
  TEST_ASSERT_TRUE_MESSAGE(call != std::string::npos, "registerInstallation() recovers an orphaned pair");
  TEST_ASSERT_TRUE_MESSAGE(mint != std::string::npos && call < mint, "recovery runs BEFORE a new install id is minted");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "recoverOrphanedTokenPair();"), "one boot recovery call site");
}

void test_only_the_stale_token_signature_on_a_custom_apibase_can_reach_the_heal() {
  std::string heal;
  TEST_ASSERT_TRUE(healBlock(heal));
  TEST_ASSERT_TRUE_MESSAGE(heal.find("!fry::isStaleTokenSignature(code, tokenSent)") != std::string::npos,
                           "the helper refuses anything but the signature");
  // A transient 404 from a public/proxy path must never reset a healthy installation: the fleet
  // default apiBase (where registration is open and a Bearer is simply ignored) never heals.
  TEST_ASSERT_TRUE_MESSAGE(heal.find("strcmp(fry_config::getApiBase().c_str(), HARDWAREAPI_BASE) == 0") != std::string::npos,
                           "the compiled default apiBase is excluded");
  TEST_ASSERT_TRUE(heal.find("if (!fry::healWindowOpen(s_staleTokenHealed, lastHeal, epochNow)) return false;") !=
                   std::string::npos);
  std::string fn;
  TEST_ASSERT_TRUE(functionBody(heal, "bool healStaleTokenIfDue(", fn));
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "s_staleTokenHealed = true;"), "the per-boot bound is set exactly once");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "putUInt(\"healAt\", epochNow)"), "the 6 h bound is persisted exactly once");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "getUInt(\"healAt\", 0)"), "and read back before deciding");
  // time(nullptr) == (time_t)-1 must not be cast to a plausible epoch.
  TEST_ASSERT_TRUE_MESSAGE(fn.find("nowT == static_cast<time_t>(-1) ? 0 : static_cast<uint32_t>(nowT)") != std::string::npos,
                           "a -1 clock reads as 0, which is implausible and never opens the window");
}

void test_the_shadow_pair_is_written_before_the_window_and_the_clear() {
  std::string src;
  TEST_ASSERT_TRUE(hwapi(src));
  std::string body;
  TEST_ASSERT_TRUE(functionBody(src, "bool healStaleTokenIfDue(", body));
  const size_t stash = body.find("if (!stashTokenPair()) return false;");
  const size_t healAt = body.find("putUInt(\"healAt\", epochNow)");
  const size_t clear = body.find("fry_config::clearInstallation()");
  const size_t retry = body.find("http.POST(");
  TEST_ASSERT_TRUE(stash != std::string::npos && healAt != std::string::npos);
  TEST_ASSERT_TRUE(clear != std::string::npos && retry != std::string::npos);
  TEST_ASSERT_TRUE_MESSAGE(stash < healAt, "stash BEFORE healAt: a failed stash must not burn the 6 h window");
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
  const size_t read = restore.find("readTokenPairShadow(id, tok)");
  const size_t writeId = restore.find("fry_config::setInstallId(id.c_str())");
  const size_t writeTok = restore.find("fry_config::setDeviceToken(tok.c_str())");
  const size_t verify = restore.find("fry::pairsMatchByteForByte(");
  const size_t drop = restore.find("dropTokenPairShadow();");
  TEST_ASSERT_TRUE(read != std::string::npos);
  TEST_ASSERT_TRUE(writeId != std::string::npos && writeTok != std::string::npos);
  TEST_ASSERT_TRUE(read < writeId && read < writeTok);
  TEST_ASSERT_TRUE_MESSAGE(verify != std::string::npos && drop != std::string::npos, "the restore is verified before the shadows go");
  TEST_ASSERT_TRUE_MESSAGE(verify < drop, "byte-for-byte equality is checked BEFORE the shadows are dropped");
  // A failed retry calls it: the failure branch is the only caller inside the heal.
  std::string body;
  TEST_ASSERT_TRUE(functionBody(src, "bool healStaleTokenIfDue(", body));
  const size_t fail = body.find("if (healCode < 200 || healCode >= 300) {");
  TEST_ASSERT_TRUE_MESSAGE(fail != std::string::npos, "any non-2xx retry is a failure");
  TEST_ASSERT_TRUE_MESSAGE(body.find("if (!restoreTokenPair()) {", fail) != std::string::npos, "and restores the pair");
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
  // Exactly one masked log line per heal, and it carries no token bytes (only present/none).
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "FRY_PRINTF("), "exactly one masked serial line per heal");
  TEST_ASSERT_TRUE(fn.find("token.length() > 0 ? \"present\" : \"none\"") != std::string::npos);
  const size_t print = fn.find("FRY_PRINTF(");
  const size_t printEnd = fn.find(");", print);
  TEST_ASSERT_TRUE(printEnd != std::string::npos);
  TEST_ASSERT_TRUE_MESSAGE(fn.substr(print, printEnd - print).find("token.c_str()") == std::string::npos,
                           "the token value is never printed");
  // The only other print is the no-secrets restore-failure line.
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "FRY_PRINTLN("), "one diagnostic line on a failed restore");
  TEST_ASSERT_TRUE(fn.find("shadows kept") != std::string::npos);
}

void test_the_shadow_pair_survives_until_an_accepted_heartbeat_follows_a_heal_this_boot() {
  std::string src;
  TEST_ASSERT_TRUE(hwapi(src));
  std::string poc;
  TEST_ASSERT_TRUE(functionBody(src, "int putPoc() {", poc));
  const size_t end = poc.find("http.end();");
  const size_t drop = poc.find("if (code >= 200 && code < 300 && s_staleTokenHealed) dropTokenPairShadow();");
  TEST_ASSERT_TRUE_MESSAGE(end != std::string::npos && drop != std::string::npos,
                           "putPoc() drops the shadows only after a heal this boot, on an accepted heartbeat");
  TEST_ASSERT_TRUE(drop > end && drop < poc.find("fry_ota::noteHeartbeat(code, \"poc\")"));
  // The heal itself never drops them: only restoreTokenPair() (after a verified restore) does.
  std::string fn;
  TEST_ASSERT_TRUE(functionBody(src, "bool healStaleTokenIfDue(", fn));
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(fn, "dropTokenPairShadow()"),
                                "a successful heal keeps the shadows for the heartbeat that follows");
}

void test_drop_erases_only_keys_that_exist() {
  std::string src;
  TEST_ASSERT_TRUE(hwapi(src));
  std::string drop;
  TEST_ASSERT_TRUE(functionBody(src, "void dropTokenPairShadow() {", drop));
  const size_t any = drop.find("bool any = r.isKey(kShadowId) || r.isKey(kShadowToken);");
  const size_t bail = drop.find("if (!any) return;");
  const size_t erase = drop.find("w.remove(");
  TEST_ASSERT_TRUE_MESSAGE(any != std::string::npos, "an existence check guards the erase");
  TEST_ASSERT_TRUE_MESSAGE(bail != std::string::npos && bail > any, "no erase when neither key exists");
  TEST_ASSERT_TRUE_MESSAGE(erase != std::string::npos && erase > bail, "the erase comes after the check");
}

void test_nothing_outside_the_identity_pair_is_written() {
  std::string heal;
  TEST_ASSERT_TRUE(healBlock(heal));
  // The only NVS keys the self-heal creates or erases are the two shadows and fry/healAt; the live
  // pair is put back only through fry_config's own accessors.
  TEST_ASSERT_EQUAL_INT(1, countOf(heal, "putString(kShadowId"));
  TEST_ASSERT_EQUAL_INT(1, countOf(heal, "putString(kShadowToken"));
  TEST_ASSERT_EQUAL_INT(1, countOf(heal, "fry_config::setInstallId("));
  TEST_ASSERT_EQUAL_INT_MESSAGE(2, countOf(heal, "fry_config::setDeviceToken("),
                                "the restore, and the fresh token of a successful heal");
  TEST_ASSERT_EQUAL_INT(2, countOf(heal, "w.remove("));  // both shadow keys, in one place
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
  RUN_TEST(test_every_nvs_key_name_fits_the_platform_limit);
  RUN_TEST(test_the_stash_is_proven_by_read_back_before_anything_is_cleared);
  RUN_TEST(test_empty_shadows_are_never_treated_as_a_pair);
  RUN_TEST(test_a_crash_mid_heal_is_recovered_at_boot_before_a_new_install_id);
  RUN_TEST(test_only_the_stale_token_signature_on_a_custom_apibase_can_reach_the_heal);
  RUN_TEST(test_the_shadow_pair_is_written_before_the_window_and_the_clear);
  RUN_TEST(test_a_failed_retry_restores_the_original_pair_byte_for_byte);
  RUN_TEST(test_the_retry_is_exactly_one_token_less_post);
  RUN_TEST(test_the_shadow_pair_survives_until_an_accepted_heartbeat_follows_a_heal_this_boot);
  RUN_TEST(test_drop_erases_only_keys_that_exist);
  RUN_TEST(test_nothing_outside_the_identity_pair_is_written);
  RUN_TEST(test_the_heal_is_reached_only_from_the_registration_4xx_branch);
  return UNITY_END();
}
