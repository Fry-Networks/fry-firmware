// An OTA check is held back while lwIP still has closed connections in TIME_WAIT (bounded).
//
// Measured on the bench ESP8266: the boot-time TLS calls leave two pcbs in TIME_WAIT until t~128 s; while
// they exist the largest free block is 28536 B, afterwards 36320 B (+7784) with the TOTAL free heap moving
// only +408. The boot check (t~8 s) and any check within two minutes of other TLS traffic therefore sees a
// heap smaller than the same heap a moment later. lib/fry_core/ota_timewait.h has the whole story; this
// test pins the decision (hold, release on expiry, release at the bound), the constants it rests on, and
// that src/core/ota_client.cpp tick() really asks before it runs a check.
#include <unity.h>

#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "ota_timewait.h"

namespace {

const uint32_t kMax = fry::kOtaTimeWaitMaxHoldMs;

void test_a_due_check_is_held_while_pcbs_remain_and_the_bound_is_not_reached() {
  TEST_ASSERT_EQUAL_INT_MESSAGE(static_cast<int>(fry::TwHold::Hold),
                                static_cast<int>(fry::decideTimeWaitHold(2, 0, kMax)),
                                "two TIME_WAIT pcbs, check just became due: it must wait");
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TwHold::Hold),
                        static_cast<int>(fry::decideTimeWaitHold(1, kMax - 1, kMax)));
}

void test_it_proceeds_when_no_pcb_is_left() {
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TwHold::Proceed),
                        static_cast<int>(fry::decideTimeWaitHold(0, 0, kMax)));
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TwHold::Proceed),
                        static_cast<int>(fry::decideTimeWaitHold(0, 50000, kMax)));
}

void test_the_hold_is_bounded_whatever_remains() {
  TEST_ASSERT_EQUAL_INT_MESSAGE(static_cast<int>(fry::TwHold::Proceed),
                                static_cast<int>(fry::decideTimeWaitHold(3, kMax, kMax)),
                                "at the bound the check runs even with pcbs left");
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TwHold::Proceed),
                        static_cast<int>(fry::decideTimeWaitHold(3, kMax + 1, kMax)));
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::TwHold::Proceed),
                        static_cast<int>(fry::decideTimeWaitHold(3, UINT32_MAX, kMax)));
}

void test_the_boot_pcbs_expire_inside_the_bound_so_the_check_is_released_by_expiry() {
  // Two pcbs closed at t=7 s (the hardwareapi calls) live kTcpTimeWaitMs; the first check is due at t=8 s
  // and the loop looks again every 100 ms. Measured: tw=2 until t~128 s.
  const uint32_t closedAt = 7000, dueAt = 8000;
  uint32_t t = dueAt;
  uint32_t tw = 2;
  for (;; t += 100) {
    tw = t < closedAt + fry::kTcpTimeWaitMs ? 2u : 0u;
    if (fry::decideTimeWaitHold(tw, t - dueAt, kMax) == fry::TwHold::Proceed) break;
    TEST_ASSERT_TRUE_MESSAGE(t - dueAt < kMax, "never released: the bound did not stop the hold");
  }
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, tw, "released by the pcbs expiring, not by hitting the bound");
  TEST_ASSERT_TRUE(t >= closedAt + fry::kTcpTimeWaitMs);
  TEST_ASSERT_TRUE_MESSAGE(t - dueAt < kMax, "released inside the bound");
}

void test_traffic_that_keeps_a_pcb_alive_cannot_starve_the_check() {
  uint32_t t = 0;
  for (;; t += 100) {
    if (fry::decideTimeWaitHold(1, t, kMax) == fry::TwHold::Proceed) break;
    TEST_ASSERT_TRUE_MESSAGE(t <= kMax, "starved past the bound");
  }
  TEST_ASSERT_EQUAL_UINT(kMax, t);
}

void test_the_constants_the_bound_rests_on() {
  // lwip2 tcp_priv.h: TCP_MSL 60000 ms; a closed pcb lingers 2 x MSL.
  TEST_ASSERT_EQUAL_UINT(60000, fry::kTcpMslMs);
  TEST_ASSERT_EQUAL_UINT(120000, fry::kTcpTimeWaitMs);
  // The bound must outlast one TIME_WAIT window with room for the slow timer's granularity...
  TEST_ASSERT_TRUE(fry::kOtaTimeWaitMaxHoldMs >= fry::kTcpTimeWaitMs + 2 * fry::kTcpSlowTimerMs);
  // ...but not by a whole second window: a hold that long would be two bursts of traffic, not one.
  TEST_ASSERT_TRUE(fry::kOtaTimeWaitMaxHoldMs < 2 * fry::kTcpTimeWaitMs);
}

// ---- tick() must ask before it runs a check -----------------------------------------------------
//
// ota_client.cpp needs the Arduino core, so the native tests cannot run it; like test_relay_source_pin
// and test_ota_session this reads the source. Wanted: `holdForTimeWait(now)` called exactly twice in code
// (the first-check path and the scheduled path of tick()), each inside an `#if defined(ARDUINO_ARCH_ESP8266)`
// branch (not its #else), so the ESP32 build never compiles it and its image is untouched.

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

struct Calls {
  int total;
  int onEsp8266Only;
};
Calls countCalls(const std::string& source, const std::string& needle) {
  const std::string code = blankNonCode(source);
  const std::string needleSq = squeeze(needle);
  // One entry per open #if: true while inside the branch that is compiled only on ESP8266.
  std::vector<bool> stack;
  Calls r = {0, 0};
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
        stack.push_back(rest == "defined(ARDUINO_ARCH_ESP8266)");
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

// src/core/ota_client.cpp, found relative to this test (the compiler's __FILE__ is absolute or relative to
// the project directory) or a few directories up from where the test runs.
bool loadOtaClient(std::string& out) {
  const std::string rel = "src/core/ota_client.cpp";
  const std::string self = __FILE__;
  const std::string tail = "test/test_ota_timewait/test_main.cpp";
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

const char* const kNeedle = "holdForTimeWait(now)";

void test_the_scanner_counts_guarded_calls_and_rejects_the_rest() {
  // Controls: a pass on the real file must not come from a scanner that sees nothing.
  Calls r = countCalls(
      "void tick() {\n#if defined(ARDUINO_ARCH_ESP8266)\n  if (holdForTimeWait(now)) return;\n#endif\n"
      "  if (x) {\n#if defined(ARDUINO_ARCH_ESP8266)\n    if (holdForTimeWait(now)) return;\n#endif\n  }\n}\n",
      kNeedle);
  TEST_ASSERT_EQUAL_INT(2, r.total);
  TEST_ASSERT_EQUAL_INT(2, r.onEsp8266Only);

  r = countCalls("void tick() {\n  checkNow();\n}\n", kNeedle);
  TEST_ASSERT_EQUAL_INT(0, r.total);

  r = countCalls("void tick() {\n  if (holdForTimeWait(now)) return;\n}\n", kNeedle);
  TEST_ASSERT_EQUAL_INT(1, r.total);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, r.onEsp8266Only, "an unguarded call reaches the ESP32 build");

  r = countCalls("#if defined(ARDUINO_ARCH_ESP8266)\n#else\n  if (holdForTimeWait(now)) return;\n#endif\n", kNeedle);
  TEST_ASSERT_EQUAL_INT(1, r.total);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, r.onEsp8266Only, "the #else branch is the ESP32 one");

  r = countCalls(
      "// if (holdForTimeWait(now)) return;\n/* holdForTimeWait(now) */\nconst char* s = \"holdForTimeWait(now)\";\n",
      kNeedle);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, r.total, "comments and strings are not code");
}

void test_tick_asks_before_it_runs_a_check_on_esp8266_only() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadOtaClient(src), "cannot read src/core/ota_client.cpp");
  const Calls r = countCalls(src, kNeedle);
  TEST_ASSERT_EQUAL_INT_MESSAGE(
      2, r.total,
      "tick() must call holdForTimeWait(now) before the first check and before each scheduled check");
  TEST_ASSERT_EQUAL_INT_MESSAGE(2, r.onEsp8266Only,
                                "both calls must sit inside #if defined(ARDUINO_ARCH_ESP8266)");
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_a_due_check_is_held_while_pcbs_remain_and_the_bound_is_not_reached);
  RUN_TEST(test_it_proceeds_when_no_pcb_is_left);
  RUN_TEST(test_the_hold_is_bounded_whatever_remains);
  RUN_TEST(test_the_boot_pcbs_expire_inside_the_bound_so_the_check_is_released_by_expiry);
  RUN_TEST(test_traffic_that_keeps_a_pcb_alive_cannot_starve_the_check);
  RUN_TEST(test_the_constants_the_bound_rests_on);
  RUN_TEST(test_the_scanner_counts_guarded_calls_and_rejects_the_rest);
  RUN_TEST(test_tick_asks_before_it_runs_a_check_on_esp8266_only);
  return UNITY_END();
}
