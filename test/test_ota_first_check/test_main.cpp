// The first manifest check does not start while the boot's asynchronous heap event can still land inside it (ESP8266).
//
// A persistent 504 B block is allocated 7770..7779 ms after the Wi-Fi connect (five bench captures). A check that is running then has its
// BearSSL thunk in the 4120 hole, so the block lands mid-heap (offset 26600 in the sw9 capture) and the largest free block stays at 17256
// until the next reboot: every later manifest check is refused. On the tip the first check started as soon as the TIME_WAIT hold let it
// (the registration's pcb was not yet in TIME_WAIT at 8.3 s: tw=0), plus R1's 1.2 s start wait: a check from 9.5 s to about 14.5 s, which
// covers the event at 14.35 s. lib/fry_core/ota_first_check.h has the whole story; this test pins
//   * the decision and its constants,
//   * a replay of the sw9 boot (and slower ones) under the tip's policy (control: it is caught) and under the new one (it is not),
//   * that src/core/ota_client.cpp tick() asks before the FIRST check, only there, before the TIME_WAIT hold.
#include <unity.h>

#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "ota_first_check.h"
#include "ota_timewait.h"

namespace {

// ---- measured facts the replay rests on -----------------------------------------------------------------------------------------
const uint32_t kEventAfterConnectMs = 7775;  // block seen 7770, 7771, 7773, 7776, 7779 ms after the connect (hmX1, x2, x2b, x3a, x3t2)
const uint32_t kCheckSpanMs = 5000;          // sw9: hop 1 starts at t=9621, the last hop's connect ends at 13559, GET and body follow
const uint32_t kStartSettleMs = 1164;        // sw9: "ota: start settled 1164 ms" (R1's wait, base 0)
const uint32_t kLoopMs = 100;                // the loop looks again about every 100 ms while a check is due

// Where the first check starts under the policy of the tip: tick()'s first call decides (no gate), the hold passes at once when no pcb is
// in TIME_WAIT yet (sw9: tw=0 at up=8319), then R1's start wait.
uint32_t startUnderTip(uint32_t firstTickMs) { return firstTickMs + kStartSettleMs; }

// The same under this fix: tick() returns until otaFirstCheckWaitMs() says 0, looked at every loop pass; the hold is not modelled (it can
// only delay the check further).
uint32_t startUnderFix(uint32_t firstTickMs) {
  uint32_t t = firstTickMs;
  while (fry::otaFirstCheckWaitMs(t, firstTickMs) != 0) t += kLoopMs;
  return t + kStartSettleMs;
}

// A check that runs from `start` for kCheckSpanMs is caught when the event falls inside it.
bool caught(uint32_t connectMs, uint32_t startMs) {
  const uint32_t event = connectMs + kEventAfterConnectMs;
  return startMs <= event && event <= startMs + kCheckSpanMs;
}

struct Boot {
  const char* what;
  uint32_t connectMs;
  uint32_t firstTickMs;  // tick() is only reached after the connect
};
const Boot kBoots[] = {
    {"sw9: connect 6.6 s, first tick 8.3 s", 6600, 8319},
    {"x3t2: connect 6.575 s, first tick 8.3 s", 6575, 8300},
    {"first tick right at the connect", 6575, 6575},
    {"first tick 3 s after the connect", 6600, 9600},
    {"slow DHCP: connect 15 s", 15000, 16500},
    {"slow DHCP: connect 25 s", 25000, 26500},
    {"very slow: connect 40 s", 40000, 41500},
};

void test_it_waits_until_20_s_of_uptime_after_an_early_first_tick() {
  TEST_ASSERT_EQUAL_UINT32(11700, fry::otaFirstCheckWaitMs(8300, 8300));
  TEST_ASSERT_EQUAL_UINT32(1, fry::otaFirstCheckWaitMs(19999, 8300));
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(0, fry::otaFirstCheckWaitMs(20000, 8300), "20 s of uptime is enough after an early first tick");
  TEST_ASSERT_EQUAL_UINT32(0, fry::otaFirstCheckWaitMs(500000, 8300));
}

void test_it_waits_10_s_after_the_first_tick_when_that_is_later_than_20_s() {
  TEST_ASSERT_EQUAL_UINT32(10000, fry::otaFirstCheckWaitMs(26500, 26500));
  TEST_ASSERT_EQUAL_UINT32(1, fry::otaFirstCheckWaitMs(36499, 26500));
  TEST_ASSERT_EQUAL_UINT32(0, fry::otaFirstCheckWaitMs(36500, 26500));
  // 20 s of uptime alone would let a boot whose first tick came at 26.5 s check at once.
  TEST_ASSERT_TRUE(fry::otaFirstCheckWaitMs(27000, 26500) > 0);
}

void test_the_constants_the_replay_rests_on() {
  TEST_ASSERT_EQUAL_UINT32(20000, fry::kOtaFirstCheckMinUptimeMs);
  TEST_ASSERT_EQUAL_UINT32(10000, fry::kOtaFirstCheckAfterFirstTickMs);
  // The wait after the first tick covers the measured event with room.
  TEST_ASSERT_TRUE(fry::kOtaFirstCheckAfterFirstTickMs >= 7779 + 2000);
  // The first check is held for the TIME_WAIT pcbs afterwards anyway; 20 s must stay far below that bound.
  TEST_ASSERT_TRUE(fry::kOtaFirstCheckMinUptimeMs < fry::kOtaTimeWaitMaxHoldMs);
}

void test_the_tip_policy_is_caught_by_the_event_on_the_sw9_boot() {
  // Control: the replay must be able to see the race, or "not caught" below proves nothing.
  const Boot& b = kBoots[0];
  const uint32_t start = startUnderTip(b.firstTickMs);
  TEST_ASSERT_EQUAL_UINT32(9483, start);
  TEST_ASSERT_TRUE_MESSAGE(caught(b.connectMs, start), "the tip's first check (9.5 s .. 14.5 s) contains the event at 14.4 s");
  // The window of starts that lose: from event - span (9.3 s) to the event (14.35 s).
  TEST_ASSERT_FALSE(caught(6575, 7800));  // the older unheld check at 7.8 s ended before the event
  TEST_ASSERT_FALSE(caught(6575, 9300));
  TEST_ASSERT_TRUE(caught(6575, 9355));
  TEST_ASSERT_TRUE(caught(6575, 14350));
  TEST_ASSERT_FALSE(caught(6575, 14351));
}

void test_the_tip_policy_is_caught_when_the_first_tick_comes_1_to_3_s_after_the_connect() {
  // kBoots[0], [1], [3]: the check starts 9.5 s .. 10.8 s after boot, inside the window of starts that lose.
  TEST_ASSERT_TRUE(caught(kBoots[0].connectMs, startUnderTip(kBoots[0].firstTickMs)));
  TEST_ASSERT_TRUE(caught(kBoots[1].connectMs, startUnderTip(kBoots[1].firstTickMs)));
  TEST_ASSERT_TRUE(caught(kBoots[3].connectMs, startUnderTip(kBoots[3].firstTickMs)));
  // Control: a first tick right at the connect starts the check at 7.7 s, which ends before the event, like the older 7.8 s check.
  TEST_ASSERT_FALSE(caught(kBoots[2].connectMs, startUnderTip(kBoots[2].firstTickMs)));
}

void test_under_the_fix_no_modelled_boot_starts_a_check_the_event_can_land_in() {
  for (const Boot& b : kBoots) {
    const uint32_t start = startUnderFix(b.firstTickMs);
    TEST_ASSERT_FALSE_MESSAGE(caught(b.connectMs, start), b.what);
    TEST_ASSERT_TRUE_MESSAGE(start > b.connectMs + kEventAfterConnectMs, b.what);  // the event is over before the check starts
    TEST_ASSERT_TRUE_MESSAGE(start >= fry::kOtaFirstCheckMinUptimeMs, b.what);
  }
}

void test_a_boot_that_connects_late_is_not_caught_by_the_20_s_floor_alone() {
  // Why the floor is relative to the first tick as well: with a 20 s floor only, the 15 s connect would start its check at 21.2 s, inside
  // 22.8 s +- 5 s.
  const Boot& slow = kBoots[4];
  const uint32_t startFloorOnly = (slow.firstTickMs > 20000 ? slow.firstTickMs : 20000) + kStartSettleMs;
  TEST_ASSERT_TRUE_MESSAGE(caught(slow.connectMs, startFloorOnly), "control: a 20 s floor alone is caught on the slow-DHCP boot");
  TEST_ASSERT_FALSE(caught(slow.connectMs, startUnderFix(slow.firstTickMs)));
}

// ---- tick() must ask before the FIRST check, and only there ------------------------------------------------------------------------
//
// ota_client.cpp needs the Arduino core, so the native tests cannot run it; like test_ota_timewait this reads the source. Wanted: in tick()'s
// first-check branch (`if (!s_firstCheckDone) {`), inside `#if defined(ARDUINO_ARCH_ESP8266)`, a call to fry::otaFirstCheckWaitMs that comes
// before holdForTimeWait(now) and before s_firstCheckDone = true; none anywhere else in tick().

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

// The text from `open` (the first occurrence in `code`, at or after `from`) to its matching closing brace, inclusive; npos start when absent.
bool braceBlock(const std::string& code, const std::string& open, size_t from, size_t& begin, size_t& end) {
  begin = code.find(open, from);
  if (begin == std::string::npos) return false;
  size_t i = code.find('{', begin);
  if (i == std::string::npos) return false;
  int depth = 0;
  for (; i < code.size(); i++) {
    if (code[i] == '{') depth++;
    if (code[i] == '}' && --depth == 0) {
      end = i + 1;
      return true;
    }
  }
  return false;
}

// True when `pos` (an offset into `code`) lies inside the branch that is compiled only on ESP8266 (#if defined(ARDUINO_ARCH_ESP8266), not its #else).
bool onEsp8266Only(const std::string& code, size_t pos) {
  std::vector<bool> stack;
  size_t line = 0;
  while (line <= pos && line < code.size()) {
    size_t nl = code.find('\n', line);
    if (nl == std::string::npos) nl = code.size();
    std::string text;
    for (size_t k = line; k < nl; k++) {
      if (code[k] != ' ' && code[k] != '\t' && code[k] != '\r') text.push_back(code[k]);
    }
    if (!text.empty() && text[0] == '#') {
      if (text.compare(0, 3, "#if") == 0) {
        stack.push_back(text == "#ifdefined(ARDUINO_ARCH_ESP8266)");
      } else if ((text.compare(0, 5, "#else") == 0 || text.compare(0, 5, "#elif") == 0) && !stack.empty()) {
        stack.back() = false;
      } else if (text.compare(0, 6, "#endif") == 0 && !stack.empty()) {
        stack.pop_back();
      }
    }
    line = nl + 1;
  }
  bool esp = false;
  for (size_t k = 0; k < stack.size(); k++) esp = esp || stack[k];
  return esp;
}

size_t countOf(const std::string& hay, const std::string& needle) {
  size_t n = 0, pos = 0;
  while ((pos = hay.find(needle, pos)) != std::string::npos) {
    n++;
    pos += needle.size();
  }
  return n;
}

bool readFile(const std::string& path, std::string& out) {
  std::ifstream f(path.c_str(), std::ios::in | std::ios::binary);
  if (!f) return false;
  std::ostringstream ss;
  ss << f.rdbuf();
  out = ss.str();
  return !out.empty();
}

// A file of the project, found relative to this test (the compiler's __FILE__ is absolute or relative to the project directory) or a few
// directories up from where the test runs.
bool loadRel(const std::string& rel, std::string& out) {
  const std::string self = __FILE__;
  const std::string tail = "test/test_ota_first_check/test_main.cpp";
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

bool loadOtaClient(std::string& out) { return loadRel("src/core/ota_client.cpp", out); }

const char* const kGate = "otaFirstCheckWaitMs(";

// Assignments `name=` in squeezed code, not comparisons `name==`.
int assignmentsTo(const std::string& sq, const std::string& name) {
  int n = 0;
  const std::string needle = name + "=";
  for (size_t pos = sq.find(needle); pos != std::string::npos; pos = sq.find(needle, pos + 1)) {
    const size_t next = pos + needle.size();
    if (next >= sq.size() || sq[next] != '=') n++;
  }
  return n;
}

std::string squeeze(const std::string& line) {
  std::string o;
  for (size_t i = 0; i < line.size(); i++) {
    if (line[i] != ' ' && line[i] != '\t' && line[i] != '\r' && line[i] != '\n') o.push_back(line[i]);
  }
  return o;
}

// What the pins check, as a function of the source text, so the controls can feed it known-good and known-bad text.
struct Verdict {
  bool tickFound;
  bool branchFound;
  int gateInBranch;
  int gateOutsideBranch;
  bool gateOnEsp8266Only;
  bool gateBeforeHold;
  bool holdBeforeFirstDone;
  bool recordsFirstTickBeforeGate;  // `if (s_lastCheckMs == 0) s_lastCheckMs = now;` once, before the gate
  bool argumentsAreNowAndFirstTick;
};
Verdict inspect(const std::string& source) {
  Verdict v = {false, false, 0, 0, false, false, false, false, false};
  const std::string code = blankNonCode(source);
  size_t tb, te;
  if (!braceBlock(code, "void tick() {", 0, tb, te)) return v;
  v.tickFound = true;
  const std::string tick = code.substr(tb, te - tb);
  size_t bb, be;
  if (!braceBlock(tick, "if (!s_firstCheckDone) {", 0, bb, be)) return v;
  v.branchFound = true;
  const std::string branch = tick.substr(bb, be - bb);
  v.gateInBranch = static_cast<int>(countOf(branch, kGate));
  v.gateOutsideBranch = static_cast<int>(countOf(tick, kGate)) - v.gateInBranch;
  const size_t g = branch.find(kGate);
  const size_t h = branch.find("holdForTimeWait(now)");
  const size_t f = branch.find("s_firstCheckDone = true;");
  if (g != std::string::npos) v.gateOnEsp8266Only = onEsp8266Only(code, tb + bb + g);
  v.gateBeforeHold = g != std::string::npos && h != std::string::npos && g < h;
  v.holdBeforeFirstDone = h != std::string::npos && f != std::string::npos && h < f;
  const std::string sq = squeeze(branch);
  const std::string record = "if(s_lastCheckMs==0)s_lastCheckMs=now;";
  const std::string call = "otaFirstCheckWaitMs(static_cast<uint32_t>(now),static_cast<uint32_t>(s_lastCheckMs))!=0)return;";
  const size_t r = sq.find(record), c = sq.find(kGate);
  // Before the gate s_lastCheckMs is assigned exactly once, by the record (the later `s_lastCheckMs = now;` of the check itself is another matter).
  const std::string beforeGate = c == std::string::npos ? sq : sq.substr(0, c);
  v.recordsFirstTickBeforeGate = r != std::string::npos && c != std::string::npos && r < c && countOf(beforeGate, record) == 1 &&
                                 assignmentsTo(beforeGate, "s_lastCheckMs") == 1;
  v.argumentsAreNowAndFirstTick = sq.find(call) != std::string::npos;
  return v;
}

// `s` with the first occurrence of `from` replaced by `to` (the controls edit a known-good text; an edit that matches nothing fails loudly).
std::string edit(std::string s, const std::string& from, const std::string& to) {
  const size_t at = s.find(from);
  TEST_ASSERT_TRUE_MESSAGE(at != std::string::npos, "control text edit did not match");
  s.replace(at, from.size(), to);
  return s;
}

void test_the_scanner_tells_a_gated_first_check_from_an_ungated_one() {
  // Controls: a pass on the real file must not come from a scanner that sees nothing.
  const std::string gate = "    if (fry::otaFirstCheckWaitMs(static_cast<uint32_t>(now), static_cast<uint32_t>(s_lastCheckMs)) != 0) return;\n";
  const std::string ifEsp = "#if defined(ARDUINO_ARCH_ESP8266)\n";
  const std::string good =
      "void tick() {\n  unsigned long now = millis();\n  if (!s_firstCheckDone) {\n" + ifEsp +
      "    if (s_lastCheckMs == 0) s_lastCheckMs = now;\n" + gate +
      "    if (holdForTimeWait(now)) return;\n#endif\n"
      "    s_firstCheckDone = true;\n    checkNow();\n    return;\n  }\n  if (now - s_lastCheckMs < X) return;\n  checkNow();\n}\n";
  Verdict v = inspect(good);
  TEST_ASSERT_TRUE(v.tickFound && v.branchFound);
  TEST_ASSERT_EQUAL_INT(1, v.gateInBranch);
  TEST_ASSERT_EQUAL_INT(0, v.gateOutsideBranch);
  TEST_ASSERT_TRUE(v.gateOnEsp8266Only);
  TEST_ASSERT_TRUE(v.gateBeforeHold);
  TEST_ASSERT_TRUE(v.holdBeforeFirstDone);
  TEST_ASSERT_TRUE(v.recordsFirstTickBeforeGate);
  TEST_ASSERT_TRUE(v.argumentsAreNowAndFirstTick);

  // The first tick re-recorded on every call (the wait would never end); the gate fed `now` twice.
  v = inspect(edit(good, "if (s_lastCheckMs == 0) s_lastCheckMs = now;", "s_lastCheckMs = now;"));
  TEST_ASSERT_FALSE_MESSAGE(v.recordsFirstTickBeforeGate, "an unconditional s_lastCheckMs = now would restart the wait on every pass");
  v = inspect(edit(good, "static_cast<uint32_t>(s_lastCheckMs)", "static_cast<uint32_t>(now)"));
  TEST_ASSERT_FALSE(v.argumentsAreNowAndFirstTick);
  v = inspect(edit(good, "if (s_lastCheckMs == 0) s_lastCheckMs = now;\n", ""));
  TEST_ASSERT_FALSE_MESSAGE(v.recordsFirstTickBeforeGate, "the first tick must be recorded");

  // The tip's tick(): no gate at all.
  v = inspect(edit(good, gate, ""));
  TEST_ASSERT_TRUE(v.branchFound);
  TEST_ASSERT_EQUAL_INT(0, v.gateInBranch);
  TEST_ASSERT_FALSE(v.gateBeforeHold);

  // The gate after the hold.
  v = inspect(edit(edit(good, gate, ""), "#endif\n    s_firstCheckDone", gate + "#endif\n    s_firstCheckDone"));
  TEST_ASSERT_EQUAL_INT(1, v.gateInBranch);
  TEST_ASSERT_FALSE_MESSAGE(v.gateBeforeHold, "a gate after the hold is not before it");

  // The gate outside the ESP8266 branch.
  v = inspect(edit(edit(good, ifEsp, ""), "#endif\n    s_firstCheckDone", "    s_firstCheckDone"));
  TEST_ASSERT_FALSE_MESSAGE(v.gateOnEsp8266Only, "an unguarded gate reaches the ESP32 build");

  // The gate also on the scheduled path.
  v = inspect(edit(good, "  checkNow();\n}\n", gate + "  checkNow();\n}\n"));
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, v.gateOutsideBranch, "a gate on the scheduled path is counted");

  // Comments and strings are not code.
  v = inspect("void tick() {\n  if (!s_firstCheckDone) {\n    // otaFirstCheckWaitMs(now)\n    const char* s = \"otaFirstCheckWaitMs(\";\n  }\n}\n");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, v.gateInBranch, "comments and strings are not code");
}

void test_tick_asks_before_the_first_check_on_esp8266_only() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadOtaClient(src), "cannot read src/core/ota_client.cpp");
  const Verdict v = inspect(src);
  TEST_ASSERT_TRUE_MESSAGE(v.tickFound, "cannot find tick() in ota_client.cpp");
  TEST_ASSERT_TRUE_MESSAGE(v.branchFound, "cannot find the first-check branch of tick()");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, v.gateInBranch, "tick()'s first-check branch must call fry::otaFirstCheckWaitMs once");
  TEST_ASSERT_TRUE_MESSAGE(v.gateOnEsp8266Only, "the gate must sit inside #if defined(ARDUINO_ARCH_ESP8266)");
  TEST_ASSERT_TRUE_MESSAGE(v.gateBeforeHold, "the gate must come before holdForTimeWait(now)");
  TEST_ASSERT_TRUE_MESSAGE(v.holdBeforeFirstDone, "holdForTimeWait(now) must still come before s_firstCheckDone = true");
  TEST_ASSERT_TRUE_MESSAGE(v.recordsFirstTickBeforeGate, "tick() must record millis() once, at its first call, before the gate");
  TEST_ASSERT_TRUE_MESSAGE(v.argumentsAreNowAndFirstTick, "the gate must be asked with (now, the recorded first tick)");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, v.gateOutsideBranch, "only the first check waits; the scheduled path must not call the gate");
}

void test_ota_client_includes_the_gate_and_the_header_is_empty_off_esp8266() {
  std::string src;
  TEST_ASSERT_TRUE(loadOtaClient(src));
  TEST_ASSERT_TRUE_MESSAGE(src.find("#include \"ota_first_check.h\"") != std::string::npos, "ota_client.cpp must include ota_first_check.h");
  // Like ota_timewait.h, the header guards its own content: the ESP32/C3/S3 translation unit that includes it stays empty.
  std::string hdr;
  TEST_ASSERT_TRUE_MESSAGE(loadRel("lib/fry_core/ota_first_check.h", hdr), "cannot read lib/fry_core/ota_first_check.h");
  TEST_ASSERT_TRUE_MESSAGE(hdr.find("#if !defined(ARDUINO) || defined(ARDUINO_ARCH_ESP8266)") != std::string::npos,
                           "the header's content must be ESP8266 / host only");
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_it_waits_until_20_s_of_uptime_after_an_early_first_tick);
  RUN_TEST(test_it_waits_10_s_after_the_first_tick_when_that_is_later_than_20_s);
  RUN_TEST(test_the_constants_the_replay_rests_on);
  RUN_TEST(test_the_tip_policy_is_caught_by_the_event_on_the_sw9_boot);
  RUN_TEST(test_the_tip_policy_is_caught_when_the_first_tick_comes_1_to_3_s_after_the_connect);
  RUN_TEST(test_under_the_fix_no_modelled_boot_starts_a_check_the_event_can_land_in);
  RUN_TEST(test_a_boot_that_connects_late_is_not_caught_by_the_20_s_floor_alone);
  RUN_TEST(test_the_scanner_tells_a_gated_first_check_from_an_ungated_one);
  RUN_TEST(test_tick_asks_before_the_first_check_on_esp8266_only);
  RUN_TEST(test_ota_client_includes_the_gate_and_the_header_is_empty_off_esp8266);
  return UNITY_END();
}
