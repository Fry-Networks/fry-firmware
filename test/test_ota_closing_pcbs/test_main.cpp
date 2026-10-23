// The hold in front of an OTA check counts pcbs this side is still CLOSING, not only TIME_WAIT ones (ESP8266).
//
// The boot registration's TLS connection is closed at about 8.2 s. For a while its pcb is in FIN_WAIT_1 / FIN_WAIT_2 and only then in
// TIME_WAIT; the sw9 capture has tw=0 at up=8319 and tw=1 at t=9520. holdForTimeWait counted tcp_tw_pcbs only, so at 8.3 s it saw nothing
// to wait for and the first check started with the registration's pcb in the middle of the free heap. lib/fry_core/ota_timewait.h has the
// story; this test pins
//   * which lwIP states count as closing (and that CLOSE_WAIT, TIME_WAIT and the live states do not),
//   * a replay of that boot with the tip's count (control: proceeds at 8.3 s) and with the closing states added (holds), and the bound,
//   * that holdForTimeWait() in src/core/ota_client.cpp asks countClosingPcbs() as well and feeds the SUM to the decision, and that
//     countClosingPcbs() walks tcp_active_pcbs with the predicate.
#include <unity.h>

#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "ota_timewait.h"

namespace {

// lwIP tcpbase.h: CLOSED 0, LISTEN 1, SYN_SENT 2, SYN_RCVD 3, ESTABLISHED 4, FIN_WAIT_1 5, FIN_WAIT_2 6, CLOSE_WAIT 7, CLOSING 8, LAST_ACK 9, TIME_WAIT 10.
const uint8_t kFinWait1 = 5, kFinWait2 = 6, kCloseWait = 7, kClosing = 8, kLastAck = 9, kTimeWait = 10;

void test_the_four_closing_states_count_and_no_other_state_does() {
  for (unsigned s = 0; s <= 10; s++) {
    const bool want = s == kFinWait1 || s == kFinWait2 || s == kClosing || s == kLastAck;
    TEST_ASSERT_EQUAL_INT_MESSAGE(want ? 1 : 0, fry::tcpStateIsClosing(static_cast<uint8_t>(s)) ? 1 : 0, "tcp_state value");
  }
  TEST_ASSERT_FALSE_MESSAGE(fry::tcpStateIsClosing(kCloseWait), "CLOSE_WAIT: the peer closed first, the application owns the connection");
  TEST_ASSERT_FALSE_MESSAGE(fry::tcpStateIsClosing(kTimeWait), "TIME_WAIT pcbs are counted from tcp_tw_pcbs; counting them here too would double them");
  TEST_ASSERT_FALSE(fry::tcpStateIsClosing(200));
}

void test_the_state_numbers_are_lwips() {
  TEST_ASSERT_EQUAL_UINT8(5, fry::kTcpStateFinWait1);
  TEST_ASSERT_EQUAL_UINT8(6, fry::kTcpStateFinWait2);
  TEST_ASSERT_EQUAL_UINT8(8, fry::kTcpStateClosing);
  TEST_ASSERT_EQUAL_UINT8(9, fry::kTcpStateLastAck);
}

// ---- the sw9 boot ---------------------------------------------------------------------------------------------------------------------
// The registration's connection: closed by this side at 8200 (FIN_WAIT_1), the peer ACKs at 8240 (FIN_WAIT_2), the peer's FIN arrives before
// 9520 (modelled at 9400): TIME_WAIT for kTcpTimeWaitMs. One pcb throughout.
const uint32_t kCloseAt = 8200, kAckAt = 8240, kPeerFinAt = 9400;

uint32_t timeWaitPcbs(uint32_t t) { return t >= kPeerFinAt && t < kPeerFinAt + fry::kTcpTimeWaitMs ? 1u : 0u; }
uint32_t closingPcbs(uint32_t t) {
  if (t < kCloseAt || t >= kPeerFinAt) return 0;
  return fry::tcpStateIsClosing(t < kAckAt ? kFinWait1 : kFinWait2) ? 1u : 0u;
}

void test_the_tip_count_proceeds_at_8_3_s_with_the_registration_pcb_closing() {
  // Control: the replay must show the gap, or "holds" below proves nothing. tw=0 at up=8319 in the sw9 capture.
  TEST_ASSERT_EQUAL_UINT32(0, timeWaitPcbs(8319));
  TEST_ASSERT_EQUAL_UINT32(1, closingPcbs(8319));
  TEST_ASSERT_EQUAL_INT_MESSAGE(static_cast<int>(fry::TwHold::Proceed),
                                static_cast<int>(fry::decideTimeWaitHold(timeWaitPcbs(8319), 0, fry::kOtaTimeWaitMaxHoldMs)),
                                "counting TIME_WAIT only, the first check starts at 8.3 s with a pcb still closing");
  TEST_ASSERT_EQUAL_UINT32(1, timeWaitPcbs(9520));  // tw=1 1.2 s later, as captured
}

void test_counting_the_closing_states_holds_the_check_through_the_gap() {
  for (uint32_t t = kCloseAt; t < kPeerFinAt + 1000; t += 100) {
    const uint32_t pcbs = timeWaitPcbs(t) + closingPcbs(t);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1, pcbs, "one pcb is always counted from the close to the end of TIME_WAIT: no gap");
    const uint32_t held = t > 8319 ? t - 8319 : 0;  // the check became due at 8319
    TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TwHold::Hold),
                          static_cast<int>(fry::decideTimeWaitHold(pcbs, held, fry::kOtaTimeWaitMaxHoldMs)));
  }
}

void test_the_check_is_released_when_the_pcb_expires_inside_the_bound() {
  const uint32_t due = 8319;
  uint32_t t = due, pcbs = 0;
  for (;; t += 100) {
    pcbs = timeWaitPcbs(t) + closingPcbs(t);
    if (fry::decideTimeWaitHold(pcbs, t - due, fry::kOtaTimeWaitMaxHoldMs) == fry::TwHold::Proceed) break;
    TEST_ASSERT_TRUE_MESSAGE(t - due < fry::kOtaTimeWaitMaxHoldMs, "never released");
  }
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(0, pcbs, "released by the pcb expiring, not by the bound");
  TEST_ASSERT_TRUE(t >= kPeerFinAt + fry::kTcpTimeWaitMs);
}

void test_a_pcb_stuck_in_a_closing_state_cannot_starve_the_check() {
  // The bound is unchanged: a pcb that stays in LAST_ACK / FIN_WAIT forever releases the check at kOtaTimeWaitMaxHoldMs.
  uint32_t t = 0;
  for (;; t += 100) {
    if (fry::decideTimeWaitHold(1, t, fry::kOtaTimeWaitMaxHoldMs) == fry::TwHold::Proceed) break;
    TEST_ASSERT_TRUE_MESSAGE(t <= fry::kOtaTimeWaitMaxHoldMs, "starved past the bound");
  }
  TEST_ASSERT_EQUAL_UINT32(fry::kOtaTimeWaitMaxHoldMs, t);
}

// ---- the sources --------------------------------------------------------------------------------------------------------------------
// Like test_ota_timewait this reads the source (ota_client.cpp needs the Arduino core; lwIP is not available natively).

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
    if (line[i] != ' ' && line[i] != '\t' && line[i] != '\r' && line[i] != '\n') o.push_back(line[i]);
  }
  return o;
}

size_t countOf(const std::string& hay, const std::string& needle) {
  size_t n = 0, pos = 0;
  while ((pos = hay.find(needle, pos)) != std::string::npos) {
    n++;
    pos += needle.size();
  }
  return n;
}

// The squeezed code of the function whose header is `open` (first occurrence), from its '{' to the matching '}'. Empty when absent.
std::string functionCode(const std::string& source, const std::string& open) {
  const std::string code = blankNonCode(source);
  const size_t begin = code.find(open);
  if (begin == std::string::npos) return "";
  size_t i = code.find('{', begin);
  if (i == std::string::npos) return "";
  const size_t start = i;
  int depth = 0;
  for (; i < code.size(); i++) {
    if (code[i] == '{') depth++;
    if (code[i] == '}' && --depth == 0) return squeeze(code.substr(start, i + 1 - start));
  }
  return "";
}

bool readFile(const std::string& path, std::string& out) {
  std::ifstream f(path.c_str(), std::ios::in | std::ios::binary);
  if (!f) return false;
  std::ostringstream ss;
  ss << f.rdbuf();
  out = ss.str();
  return !out.empty();
}

bool loadRel(const std::string& rel, std::string& out) {
  const std::string self = __FILE__;
  const std::string tail = "test/test_ota_closing_pcbs/test_main.cpp";
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

struct HoldVerdict {
  bool found;
  int closingCalls;
  int timeWaitCalls;
  bool decisionTakesTheSum;
};
HoldVerdict inspectHold(const std::string& source) {
  HoldVerdict v = {false, 0, 0, false};
  const std::string body = functionCode(source, "static bool holdForTimeWait(unsigned long now)");
  if (body.empty()) return v;
  v.found = true;
  v.closingCalls = static_cast<int>(countOf(body, "fry::countClosingPcbs()"));
  v.timeWaitCalls = static_cast<int>(countOf(body, "fry::countTimeWaitPcbs()"));
  v.decisionTakesTheSum = body.find("fry::decideTimeWaitHold(tw+closing,heldMs,fry::kOtaTimeWaitMaxHoldMs)") != std::string::npos;
  return v;
}

std::string edit(std::string s, const std::string& from, const std::string& to) {
  const size_t at = s.find(from);
  TEST_ASSERT_TRUE_MESSAGE(at != std::string::npos, "control text edit did not match");
  s.replace(at, from.size(), to);
  return s;
}

void test_the_hold_scanner_tells_the_counting_apart() {
  // Controls: a pass on the real file must not come from a scanner that sees nothing.
  const std::string good =
      "static bool holdForTimeWait(unsigned long now) {\n  const uint32_t tw = fry::countTimeWaitPcbs();\n"
      "  const uint32_t closing = fry::countClosingPcbs();\n  const uint32_t heldMs = 0;\n"
      "  if (fry::decideTimeWaitHold(tw + closing, heldMs, fry::kOtaTimeWaitMaxHoldMs) == fry::TwHold::Hold) return true;\n  return false;\n}\n";
  HoldVerdict v = inspectHold(good);
  TEST_ASSERT_TRUE(v.found);
  TEST_ASSERT_EQUAL_INT(1, v.closingCalls);
  TEST_ASSERT_EQUAL_INT(1, v.timeWaitCalls);
  TEST_ASSERT_TRUE(v.decisionTakesTheSum);

  // The tip: TIME_WAIT only.
  v = inspectHold(edit(edit(good, "  const uint32_t closing = fry::countClosingPcbs();\n", ""), "tw + closing", "tw"));
  TEST_ASSERT_EQUAL_INT(0, v.closingCalls);
  TEST_ASSERT_FALSE(v.decisionTakesTheSum);
  // Counted but not fed to the decision.
  v = inspectHold(edit(good, "tw + closing", "tw"));
  TEST_ASSERT_EQUAL_INT(1, v.closingCalls);
  TEST_ASSERT_FALSE_MESSAGE(v.decisionTakesTheSum, "a count that the decision does not see changes nothing");
  // Closing states only (the TIME_WAIT list dropped).
  v = inspectHold(edit(good, "  const uint32_t tw = fry::countTimeWaitPcbs();\n", "  const uint32_t tw = 0;\n"));
  TEST_ASSERT_EQUAL_INT(0, v.timeWaitCalls);
  // Comments and strings are not code.
  v = inspectHold("static bool holdForTimeWait(unsigned long now) {\n  // fry::countClosingPcbs()\n  const char* s = \"fry::countClosingPcbs()\";\n}\n");
  TEST_ASSERT_EQUAL_INT(0, v.closingCalls);
}

void test_holdForTimeWait_counts_the_closing_states_and_feeds_the_sum_to_the_decision() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadRel("src/core/ota_client.cpp", src), "cannot read src/core/ota_client.cpp");
  const HoldVerdict v = inspectHold(src);
  TEST_ASSERT_TRUE_MESSAGE(v.found, "cannot find holdForTimeWait in ota_client.cpp");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, v.closingCalls, "holdForTimeWait must call fry::countClosingPcbs() once");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, v.timeWaitCalls, "holdForTimeWait must still call fry::countTimeWaitPcbs() once");
  TEST_ASSERT_TRUE_MESSAGE(v.decisionTakesTheSum, "the decision must be taken on tw + closing");
}

void test_countClosingPcbs_walks_the_active_list_with_the_predicate() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadRel("lib/fry_core/ota_timewait.cpp", src), "cannot read lib/fry_core/ota_timewait.cpp");
  const std::string body = functionCode(src, "uint32_t countClosingPcbs()");
  TEST_ASSERT_FALSE_MESSAGE(body.empty(), "cannot find countClosingPcbs in ota_timewait.cpp");
  TEST_ASSERT_TRUE_MESSAGE(body.find("tcp_active_pcbs") != std::string::npos, "it must walk lwIP's tcp_active_pcbs");
  TEST_ASSERT_TRUE_MESSAGE(body.find("tcpStateIsClosing(static_cast<uint8_t>(p->state))") != std::string::npos,
                           "it must count only pcbs for which tcpStateIsClosing(state) holds");
  TEST_ASSERT_TRUE_MESSAGE(body.find("tcp_tw_pcbs") == std::string::npos, "the TIME_WAIT list is countTimeWaitPcbs' business");
  // The enum check that keeps the constants honest on the real build.
  TEST_ASSERT_TRUE_MESSAGE(squeeze(blankNonCode(src)).find("static_assert(FIN_WAIT_1==kTcpStateFinWait1") != std::string::npos,
                           "the constants must be static_asserted against lwIP's enum");
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_four_closing_states_count_and_no_other_state_does);
  RUN_TEST(test_the_state_numbers_are_lwips);
  RUN_TEST(test_the_tip_count_proceeds_at_8_3_s_with_the_registration_pcb_closing);
  RUN_TEST(test_counting_the_closing_states_holds_the_check_through_the_gap);
  RUN_TEST(test_the_check_is_released_when_the_pcb_expires_inside_the_bound);
  RUN_TEST(test_a_pcb_stuck_in_a_closing_state_cannot_starve_the_check);
  RUN_TEST(test_the_hold_scanner_tells_the_counting_apart);
  RUN_TEST(test_holdForTimeWait_counts_the_closing_states_and_feeds_the_sum_to_the_decision);
  RUN_TEST(test_countClosingPcbs_walks_the_active_list_with_the_predicate);
  return UNITY_END();
}
