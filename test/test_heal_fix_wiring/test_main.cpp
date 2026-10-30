// Stale-token self-heal, the wiring: [SOURCE PINS] over the firmware sources.
//
// LABEL: every test here is a source pin (the technique of test_hwapi_stack and test_stale_token_heal_wiring). It is used ONLY
// where the behavior cannot run natively: NVS / LittleFS stores, the TLS socket, and the Arduino HTTPClient need the core,
// and there is no host build of src/core/hardwareapi_client.cpp. The decisions themselves are executed in test_heal_fix_rules.
// Each pin checks position and count, not just presence, and ends with a control so a vacuous pass is impossible.
//
// On main every test here FAILS (the text is absent). Synthetic names only: no token or key appears in this file.
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
  const std::string tail = "test/test_heal_fix_wiring/test_main.cpp";
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

bool hwapi(std::string& src) { return loadSource("src/core/hardwareapi_client.cpp", src); }

bool heal(std::string& fn) {
  std::string src;
  return hwapi(src) && functionBody(src, "bool healStaleTokenIfDue(", fn);
}

// The string literal assigned to `name` (`kShadowId = "..."`).
bool literalOf(const std::string& src, const std::string& name, std::string& out) {
  const std::string pat = name + " = \"";
  const size_t a = src.find(pat);
  if (a == std::string::npos) return false;
  const size_t b = src.find('"', a + pat.size());
  if (b == std::string::npos) return false;
  out = src.substr(a + pat.size(), b - a - pat.size());
  return true;
}

// ---- the shadow pair goes with the pair --------------------------------------------------------------------------------------------------------------

void test_a_factory_reset_and_a_new_owner_key_also_drop_the_shadow_pair() {
  std::string hw, cfg, miner;
  TEST_ASSERT_TRUE(hwapi(hw));
  TEST_ASSERT_TRUE(loadSource("src/core/fry_config.cpp", cfg));
  TEST_ASSERT_TRUE(loadSource("src/core/miner_key.cpp", miner));
  std::string idKey, tokKey;
  TEST_ASSERT_TRUE(literalOf(hw, "kShadowId", idKey) && literalOf(hw, "kShadowToken", tokKey));
  TEST_ASSERT_TRUE_MESSAGE(idKey == "shdwInstallId" && tokKey == "shdwDevToken", "the shadow key names the heal stashes under");

  // factoryReset(): both removes on the SAME handle `p` that removes installId/deviceToken (a second handle on the
  // ESP8266 JSON store would be overwritten by the first one's save), before that handle ends.
  std::string reset;
  TEST_ASSERT_TRUE(functionBody(cfg, "void factoryReset() {", reset));
  const size_t begin = reset.find("p.begin(\"fry\", false);");
  const size_t token = reset.find("p.remove(\"deviceToken\");");
  const size_t sId = reset.find("p.remove(\"" + idKey + "\");");
  const size_t sTok = reset.find("p.remove(\"" + tokKey + "\");");
  const size_t end = reset.find("p.end();");
  TEST_ASSERT_TRUE_MESSAGE(sId != std::string::npos && sTok != std::string::npos, "factoryReset removes both shadow keys");
  TEST_ASSERT_TRUE(begin != std::string::npos && token != std::string::npos && end != std::string::npos);
  TEST_ASSERT_TRUE(begin < token && token < sId && sId < end && sTok < end);

  // A new owner key: clearInstallation() is followed by clearIdentityShadows(), inside setOwnerKey.
  std::string owner;
  TEST_ASSERT_TRUE(functionBody(miner, "fry::KeyWriteVerdict setOwnerKey(", owner));
  const size_t clr = owner.find("fry_config::clearInstallation();");
  const size_t shd = owner.find("fry_config::clearIdentityShadows();");
  TEST_ASSERT_TRUE_MESSAGE(clr != std::string::npos && shd != std::string::npos && clr < shd,
                           "setOwnerKey drops the shadows right after clearing the pair");
  TEST_ASSERT_EQUAL_INT(1, countOf(miner, "clearIdentityShadows("));

  // clearIdentityShadows(): exactly the two shadow keys, declared in the header.
  std::string drop;
  TEST_ASSERT_TRUE(functionBody(cfg, "void clearIdentityShadows() {", drop));
  TEST_ASSERT_EQUAL_INT(2, countOf(drop, ".remove("));
  TEST_ASSERT_TRUE(drop.find("\"" + idKey + "\"") != std::string::npos && drop.find("\"" + tokKey + "\"") != std::string::npos);
  std::string h;
  TEST_ASSERT_TRUE(loadSource("src/core/fry_config.h", h));
  TEST_ASSERT_EQUAL_INT(1, countOf(h, "void clearIdentityShadows();"));

  // CONTROL: clearInstallation() still removes exactly installId and deviceToken. The heal calls it right after it
  // stashed the shadows, so it must never take them with it.
  std::string clear;
  TEST_ASSERT_TRUE(functionBody(cfg, "void clearInstallation() {", clear));
  TEST_ASSERT_EQUAL_INT(2, countOf(clear, "p.remove("));
  TEST_ASSERT_TRUE(clear.find("shdw") == std::string::npos);
}

// ---- boot recovery --------------------------------------------------------------------------------------------------------------

void test_boot_recovery_goes_through_the_complete_pair_rule() {
  std::string src, rec;
  TEST_ASSERT_TRUE(hwapi(src));
  TEST_ASSERT_TRUE(functionBody(src, "void recoverOrphanedTokenPair() {", rec));
  const size_t rule = rec.find("fry::recoveryFor(fry_config::getInstallId().length() > 0, fry_config::getDeviceToken().length() > 0)");
  const size_t drop = rec.find("dropTokenPairShadow();");
  const size_t restore = rec.rfind("restoreTokenPair();");
  TEST_ASSERT_TRUE_MESSAGE(rule != std::string::npos, "the drop is decided by fry::recoveryFor");
  TEST_ASSERT_TRUE_MESSAGE(rec.find("fry::PairRecovery::DropShadows) {") != std::string::npos, "and only DropShadows drops");
  TEST_ASSERT_TRUE(drop != std::string::npos && rule < drop);
  TEST_ASSERT_TRUE_MESSAGE(restore != std::string::npos && drop < restore, "every other state falls through to the restore");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(rec, "dropTokenPairShadow();"), "one drop, under the rule");
  TEST_ASSERT_TRUE_MESSAGE(rec.find("ensureInstallId") == std::string::npos, "recovery never mints an install id");
  // CONTROL: the old unconditional drop (`...length() > 0) {\n    dropTokenPairShadow();`) is gone.
  TEST_ASSERT_TRUE(rec.find("{\n    dropTokenPairShadow();") == std::string::npos);
}

// ---- the healAt stamp --------------------------------------------------------------------------------------------------------------

void test_the_heal_stamp_is_proven_by_read_back_before_the_live_pair_is_cleared() {
  std::string src, fn, reader;
  TEST_ASSERT_TRUE(hwapi(src));
  TEST_ASSERT_TRUE(heal(fn));
  TEST_ASSERT_TRUE(functionBody(src, "uint32_t readHealStamp() {", reader));
  TEST_ASSERT_TRUE_MESSAGE(reader.find("r.begin(\"fry\", true);") != std::string::npos &&
                               reader.find("r.getUInt(\"healAt\", 0)") != std::string::npos,
                           "the read-back goes through a fresh read-only handle");
  const size_t write = fn.find("w.putUInt(\"healAt\", epochNow);");
  const size_t wend = fn.find("w.end();", write);
  const size_t verify = fn.find("if (readHealStamp() != epochNow) return false;");
  const size_t clear = fn.find("fry_config::clearInstallation();");
  TEST_ASSERT_TRUE(write != std::string::npos && wend != std::string::npos && verify != std::string::npos && clear != std::string::npos);
  TEST_ASSERT_TRUE_MESSAGE(write < wend && wend < verify, "read back AFTER the handle that wrote it is closed");
  TEST_ASSERT_TRUE_MESSAGE(verify < clear, "an unproven stamp returns before anything is cleared");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "readHealStamp()"), "one read-back, in the heal");
}

// ---- the shadows' lifetime ---------------------------------------------------------------------------------------------------------------

void test_an_accepted_heartbeat_drops_the_shadows_only_for_a_complete_live_pair() {
  std::string src, drop;
  TEST_ASSERT_TRUE(hwapi(src));
  TEST_ASSERT_TRUE(functionBody(src, "void dropTokenPairShadow() {", drop));
  const size_t rule = drop.find("fry::recoveryFor(fry_config::getInstallId().length() > 0, fry_config::getDeviceToken().length() > 0) !=");
  const size_t bail = drop.find("fry::PairRecovery::DropShadows) {\n    return;\n  }");
  const size_t open = drop.find("KvStore r;");
  const size_t erase = drop.find("w.remove(");
  TEST_ASSERT_TRUE_MESSAGE(rule != std::string::npos && bail != std::string::npos && open != std::string::npos &&
                               erase != std::string::npos,
                           "the drop starts with the completeness rule");
  TEST_ASSERT_TRUE_MESSAGE(rule < bail && bail < open && open < erase, "the guard comes before any NVS access or erase");
  // CONTROL: every way to the erase goes through this one function (restore, boot recovery, the post-heal heartbeat), and
  // the existence check that keeps absent keys from being erased is still there, after the guard.
  TEST_ASSERT_EQUAL_INT_MESSAGE(3, countOf(src, "dropTokenPairShadow();"), "three callers, no unguarded erase elsewhere");
  TEST_ASSERT_EQUAL_INT(2, countOf(src, "w.remove(kShadow"));
  const size_t any = drop.find("bool any = r.isKey(kShadowId) || r.isKey(kShadowToken);");
  const size_t exists = drop.find("if (!any) return;");
  TEST_ASSERT_TRUE(any != std::string::npos && exists != std::string::npos && bail < any && any < exists);
  // The heartbeat caller still needs a 2xx and a heal this boot.
  TEST_ASSERT_TRUE(src.find("if (code >= 200 && code < 300 && s_staleTokenHealed) dropTokenPairShadow();") != std::string::npos);
}

void test_the_shadow_keys_are_read_only_when_they_exist() {
  std::string src, read;
  TEST_ASSERT_TRUE(hwapi(src));
  TEST_ASSERT_TRUE(functionBody(src, "void readTokenPairShadow(String& id, String& tok) {", read));
  const size_t idCheck = read.find("r.isKey(kShadowId) ? r.getString(kShadowId, \"\") : String();");
  const size_t tokCheck = read.find("r.isKey(kShadowToken) ? r.getString(kShadowToken, \"\") : String();");
  TEST_ASSERT_TRUE_MESSAGE(idCheck != std::string::npos && tokCheck != std::string::npos,
                           "each read is behind an isKey on the same key (no NVS error line for an absent key)");
  TEST_ASSERT_EQUAL_INT(2, countOf(read, "getString("));
  TEST_ASSERT_EQUAL_INT(2, countOf(read, "isKey("));
  // CONTROL: still one read-only handle, closed after both reads.
  const size_t begin = read.find("r.begin(\"fry\", true);");
  const size_t end = read.find("r.end();");
  TEST_ASSERT_TRUE(begin != std::string::npos && end != std::string::npos && begin < idCheck && tokCheck < end);
}

// ---- the clock reading --------------------------------------------------------------------------------------------------------------

void test_an_unusable_clock_reading_takes_the_no_clock_path() {
  std::string fn;
  TEST_ASSERT_TRUE(heal(fn));
  const size_t read = fn.find("time_t nowT = time(nullptr);");
  const size_t gate = fn.find("if (!fry::healTimeUsable(static_cast<int64_t>(nowT))) nowT = static_cast<time_t>(-1);");
  const size_t cast = fn.find("const uint32_t epochNow = nowT == static_cast<time_t>(-1) ? 0 : static_cast<uint32_t>(nowT);");
  TEST_ASSERT_TRUE_MESSAGE(read != std::string::npos && gate != std::string::npos && cast != std::string::npos,
                           "the reading is range-checked as int64_t and mapped to the -1 sentinel");
  TEST_ASSERT_TRUE_MESSAGE(read < gate && gate < cast, "checked BEFORE the cast to uint32_t");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "static_cast<uint32_t>(nowT)"), "the only cast of the reading");
  // The window itself is checked with that epoch, unchanged.
  TEST_ASSERT_TRUE(fn.find("if (!fry::healWindowOpen(s_staleTokenHealed, lastHeal, epochNow)) return false;") != std::string::npos);
}

// ---- the kept-alive connection --------------------------------------------------------------------------------------------------------------

void test_the_404s_connection_is_closed_before_the_retry_connects() {
  std::string fn;
  TEST_ASSERT_TRUE(heal(fn));
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "sec.stop();"), "one explicit close of the TLS client");
  const size_t stop = fn.find("sec.stop();");
  const size_t begin = fn.find("beginHttpsUrl(");
  const size_t post = fn.find("http.POST(");
  TEST_ASSERT_TRUE(begin != std::string::npos && post != std::string::npos);
  TEST_ASSERT_TRUE_MESSAGE(stop < begin && begin < post, "closed before the retry begins, so it cannot reuse the kept-alive socket");
  // CONTROL: still exactly one retry, and the clients the heal uses are the caller's, not new ones.
  TEST_ASSERT_EQUAL_INT(1, countOf(fn, "http.POST("));
  TEST_ASSERT_EQUAL_INT(0, countOf(fn, "WiFiClientSecure sec"));
}

// ---- the retry's reply ---------------------------------------------------------------------------------------------------------

void test_the_retry_body_is_bounded_and_a_tokenless_2xx_restores_the_pair() {
  std::string src, fn, reader;
  TEST_ASSERT_TRUE(hwapi(src));
  TEST_ASSERT_TRUE(heal(fn));
  TEST_ASSERT_TRUE(functionBody(src, "String readHealToken(HTTPClient& http) {", reader));
  const size_t guard = reader.find("if (!fry::healReplyReadable(http.getSize())) return String();");
  const size_t read = reader.find("http.getString()");
  TEST_ASSERT_TRUE_MESSAGE(guard != std::string::npos && read != std::string::npos && guard < read,
                           "the body is read only after the length rule allowed it");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(reader, "getString()"), "the only body read of the retry");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(fn, "getString()"), "the heal itself never reads a body unbounded");
  TEST_ASSERT_TRUE(src.find("__attribute__((noinline)) String readHealToken(HTTPClient& http) {") != std::string::npos);

  // The helper is called only for a 2xx, and an unusable token turns the attempt into the failure the pinned
  // `if (healCode < 200 || healCode >= 300)` restores from.
  const size_t is2xx = fn.find("if (healCode >= 200 && healCode < 300) {");
  const size_t call = fn.find("token = readHealToken(http);");
  const size_t usable = fn.find("if (!fry::healTokenUsable(token.length())) healCode = -1;");
  const size_t failure = fn.find("if (healCode < 200 || healCode >= 300) {");
  const size_t restore = fn.find("if (!restoreTokenPair()) {", failure);
  TEST_ASSERT_TRUE(is2xx != std::string::npos && call != std::string::npos && usable != std::string::npos &&
                   failure != std::string::npos && restore != std::string::npos);
  TEST_ASSERT_TRUE_MESSAGE(is2xx < call && call < usable && usable < failure && failure < restore,
                           "2xx, read, token check, THEN the failure branch that restores");
  // The success path still persists the token only after that branch.
  const size_t persist = fn.find("fry_config::setDeviceToken(token.c_str())");
  TEST_ASSERT_TRUE(persist != std::string::npos && persist > failure);
}

// ---- the per-boot latch --------------------------------------------------------------------------------------------------------------

void test_the_latch_records_when_it_was_set_and_is_released_after_the_window() {
  std::string src, fn;
  TEST_ASSERT_TRUE(hwapi(src));
  TEST_ASSERT_TRUE(heal(fn));
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "unsigned long s_staleTokenHealedAtMs = 0;"), "one timestamp, at file scope");
  const size_t release = fn.find("if (s_staleTokenHealed && fry::healLatchExpired(static_cast<uint32_t>(millis() - s_staleTokenHealedAtMs))) {");
  const size_t gate = fn.find("if (s_staleTokenHealed || !fry::isStaleTokenSignature(code, tokenSent)) return false;");
  const size_t burn = fn.find("s_staleTokenHealed = true;");
  const size_t stamp = fn.find("s_staleTokenHealedAtMs = millis();");
  TEST_ASSERT_TRUE(release != std::string::npos && gate != std::string::npos && burn != std::string::npos && stamp != std::string::npos);
  TEST_ASSERT_TRUE_MESSAGE(release < gate, "the release runs BEFORE the latch is consulted");
  TEST_ASSERT_TRUE_MESSAGE(burn < stamp, "the burn time is taken where the latch is set");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "s_staleTokenHealed = true;"), "set exactly once, as shipped");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(fn, "s_staleTokenHealed = false;"), "cleared exactly once, in the release");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "\n    s_staleTokenHealed = false;"), "and nowhere else in the client (the declaration is the other `= false`)");
  // CONTROL (shipped bounds kept): the persisted 6 h window still gates every attempt, after the release.
  const size_t window = fn.find("fry::healWindowOpen(s_staleTokenHealed, lastHeal, epochNow)");
  TEST_ASSERT_TRUE(window != std::string::npos && window > release);
  TEST_ASSERT_TRUE(fn.find("strcmp(fry_config::getApiBase().c_str(), HARDWAREAPI_BASE) == 0") != std::string::npos);
}

// ---- redirects ------------------------------------------------------------------------------------------------------------

void test_no_authenticated_request_follows_a_redirect() {
  std::string src;
  TEST_ASSERT_TRUE(hwapi(src));
  const std::string begin = "fry_http::beginHttpsUrl(";
  const int sites = countOf(src, begin);
  TEST_ASSERT_EQUAL_INT_MESSAGE(5, sites, "register, heal, lease, PoC heartbeat, versions: all five requests of this client");
  TEST_ASSERT_EQUAL_INT_MESSAGE(sites, countOf(src, "noRedirects(http);"), "a noRedirects(http) call after every begin");
  // Each begin is followed by noRedirects BEFORE the first thing that sends: the POST/PUT/GET/sendRequest of that request.
  size_t at = 0;
  int checked = 0;
  while ((at = src.find(begin, at)) != std::string::npos) {
    const size_t nr = src.find("noRedirects(http);", at);
    size_t send = std::string::npos;
    const char* senders[] = {"http.POST(", "http.PUT(", "http.GET(", "http.sendRequest("};
    for (size_t i = 0; i < sizeof(senders) / sizeof(senders[0]); i++) {
      const size_t s = src.find(senders[i], at);
      if (s != std::string::npos && (send == std::string::npos || s < send)) send = s;
    }
    TEST_ASSERT_TRUE(nr != std::string::npos && send != std::string::npos);
    TEST_ASSERT_TRUE_MESSAGE(nr < send, "redirects are off before the request goes out");
    TEST_ASSERT_TRUE_MESSAGE(nr - at < 160, "and it is the statement right after the begin");
    checked++;
    at += begin.size();
  }
  TEST_ASSERT_EQUAL_INT(sites, checked);

  // The one definition turns following OFF, and no mode that follows is used anywhere in this client.
  TEST_ASSERT_TRUE(src.find("void noRedirects(HTTPClient& http) { http.setFollowRedirects(HTTPC_DISABLE_FOLLOW_REDIRECTS); }") != std::string::npos);
  TEST_ASSERT_EQUAL_INT(1, countOf(src, "HTTPC_DISABLE_FOLLOW_REDIRECTS"));
  TEST_ASSERT_EQUAL_INT(0, countOf(src, "HTTPC_FORCE_FOLLOW_REDIRECTS"));
  TEST_ASSERT_EQUAL_INT(0, countOf(src, "HTTPC_STRICT_FOLLOW_REDIRECTS"));
  TEST_ASSERT_EQUAL_INT(0, countOf(src, "setRedirectLimit"));

  // CONTROL: the shared helper keeps following redirects for the OTA download (a GitHub asset is two hops); this fix
  // lives in the hardwareapi client only.
  std::string esp32, esp8266;
  TEST_ASSERT_TRUE(loadSource("src/esp32/http_tls.cpp", esp32) && loadSource("src/esp8266/http_tls.cpp", esp8266));
  TEST_ASSERT_TRUE(esp32.find("HTTPC_FORCE_FOLLOW_REDIRECTS") != std::string::npos);
  TEST_ASSERT_TRUE(esp8266.find("HTTPC_FORCE_FOLLOW_REDIRECTS") != std::string::npos);
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_a_factory_reset_and_a_new_owner_key_also_drop_the_shadow_pair);
  RUN_TEST(test_boot_recovery_goes_through_the_complete_pair_rule);
  RUN_TEST(test_the_heal_stamp_is_proven_by_read_back_before_the_live_pair_is_cleared);
  RUN_TEST(test_an_accepted_heartbeat_drops_the_shadows_only_for_a_complete_live_pair);
  RUN_TEST(test_the_shadow_keys_are_read_only_when_they_exist);
  RUN_TEST(test_an_unusable_clock_reading_takes_the_no_clock_path);
  RUN_TEST(test_the_404s_connection_is_closed_before_the_retry_connects);
  RUN_TEST(test_the_retry_body_is_bounded_and_a_tokenless_2xx_restores_the_pair);
  RUN_TEST(test_the_latch_records_when_it_was_set_and_is_released_after_the_window);
  RUN_TEST(test_no_authenticated_request_follows_a_redirect);
  return UNITY_END();
}
