// Source pin for the yield at the end of loop() in src/main.cpp.
//
// Arduino's loopTask calls loop() back to back and never blocks, so on the ESP32 it spins on core 1
// and keeps the shared SPI flash bus busy; the Wi-Fi/lwIP code that runs on the other core then
// stalls on instruction fetches (LAN ping 540-846 ms, relay median 7-10 s, measured; the core-1 idle
// hook ran ~15 times in 30 s). One RTOS tick of sleep at the end of every pass fixes that whatever
// the code layout happens to be (idle hook ~30000 per 30 s, ping 28-43 ms).
//
// The yield needs the RTOS, so the native tests cannot run it. What must hold in the source, and
// what this test reads, is that loop() ENDS with
//
//     #if !defined(ARDUINO_ARCH_ESP8266)
//       vTaskDelay(1);
//     #endif
//   }
//
// as the last thing in the function: not inside the phase switch, where a phase that does not run it
// would go on spinning, and not under any other brace or #if (whatever encloses those three lines
// closes after them and so becomes the last line instead), with no `return` earlier in the body that
// could skip it. The ESP8266 has no vTaskDelay, and its loop() must stay as it was.
// The groups before the last one exercise the scanner on synthetic sources, so that a pass cannot
// come from a scanner that sees nothing.
#include <unity.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

bool isIdent(char c) {
  return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
}

// Blanks comments and the contents of string and character literals; every newline survives, so
// offsets and line numbers still match the source.
std::string blank(const std::string& s) {
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

std::vector<std::string> splitLines(const std::string& t) {
  std::vector<std::string> lines;
  std::string cur;
  for (size_t i = 0; i < t.size(); i++) {
    if (t[i] == '\n') {
      lines.push_back(cur);
      cur.clear();
    } else {
      cur.push_back(t[i]);
    }
  }
  lines.push_back(cur);
  return lines;
}

// The line with every blank removed: `#  if !defined( X )` and `#if !defined(X)` compare equal.
std::string squash(const std::string& s) {
  std::string out;
  for (size_t i = 0; i < s.size(); i++) {
    if (s[i] != ' ' && s[i] != '\t' && s[i] != '\r') out.push_back(s[i]);
  }
  return out;
}

bool tokenAt(const std::string& t, size_t pos, const char* word) {
  const std::string w(word);
  if (t.compare(pos, w.size(), w) != 0) return false;
  if (pos > 0 && isIdent(t[pos - 1])) return false;
  const size_t after = pos + w.size();
  return after >= t.size() || !isIdent(t[after]);
}

size_t skipSpace(const std::string& t, size_t j) {
  while (j < t.size() && (t[j] == ' ' || t[j] == '\t' || t[j] == '\n' || t[j] == '\r')) j++;
  return j;
}

// `void loop ( [void] ) {`: the offset just past the `{`, or npos. Calls such as
// `fry_provisioning::loop();` have no `void` in front and do not match.
size_t findLoopBodyStart(const std::string& t) {
  for (size_t i = t.find("void"); i != std::string::npos; i = t.find("void", i + 1)) {
    if (!tokenAt(t, i, "void")) continue;
    size_t j = skipSpace(t, i + 4);
    if (!tokenAt(t, j, "loop")) continue;
    j = skipSpace(t, j + 4);
    if (j >= t.size() || t[j] != '(') continue;
    j = skipSpace(t, j + 1);
    if (tokenAt(t, j, "void")) j = skipSpace(t, j + 4);
    if (j >= t.size() || t[j] != ')') continue;
    j = skipSpace(t, j + 1);
    if (j < t.size() && t[j] == '{') return j + 1;
  }
  return std::string::npos;
}

struct LoopYield {
  bool found = false;           // a `void loop()` definition exists
  bool closed = false;          // and its braces balance
  bool hasReturn = false;       // a `return` anywhere in the body: that path would skip the yield
  bool tailExact = false;       // the last three lines of the body are the guarded yield
  bool bodyIsTheRealOne = false;  // the body starts with fry_ota::loopGuard(): not a stray loop()
};

LoopYield scan(const std::string& source) {
  LoopYield r;
  const std::string t = blank(source);
  const size_t start = findLoopBodyStart(t);
  if (start == std::string::npos) return r;
  r.found = true;

  size_t end = std::string::npos;
  int depth = 0;
  for (size_t i = start; i < t.size(); i++) {
    if (t[i] == '{') {
      depth++;
    } else if (t[i] == '}') {
      if (depth == 0) {
        end = i;
        break;
      }
      depth--;
    }
  }
  if (end == std::string::npos) return r;
  r.closed = true;

  const std::string body = t.substr(start, end - start);
  for (size_t i = body.find("return"); i != std::string::npos; i = body.find("return", i + 1)) {
    if (tokenAt(body, i, "return")) r.hasReturn = true;
  }
  const size_t firstWord = skipSpace(body, 0);
  r.bodyIsTheRealOne = body.compare(firstWord, strlen("fry_ota::loopGuard();"), "fry_ota::loopGuard();") == 0;

  // The last three lines that hold anything.
  const std::vector<std::string> lines = splitLines(body);
  std::vector<std::string> last;
  for (size_t li = lines.size(); li > 0 && last.size() < 3; li--) {
    const std::string s = squash(lines[li - 1]);
    if (!s.empty()) last.insert(last.begin(), s);
  }
  if (last.size() < 3) return r;

  const bool guardOk = last[0] == "#if!defined(ARDUINO_ARCH_ESP8266)" ||
                       last[0] == "#if!definedARDUINO_ARCH_ESP8266" ||
                       last[0] == "#ifndefARDUINO_ARCH_ESP8266";
  r.tailExact = guardOk && last[1] == "vTaskDelay(1);" && last[2] == "#endif";
  return r;
}

// ---- the scanner, on synthetic sources ----------------------------------------------------------

const char kGood[] =
    "void loop() {\n"
    "  fry_ota::loopGuard();\n"
    "  switch (s_phase) {\n"
    "    case A:\n"
    "      work();\n"
    "      break;\n"
    "    case B:\n"
    "      other();\n"
    "      break;\n"
    "  }\n"
    "  // the yield, with a comment that mentions return and vTaskDelay(2);\n"
    "#if !defined(ARDUINO_ARCH_ESP8266)\n"
    "  vTaskDelay(1);\n"
    "#endif\n"
    "}\n";

void test_scanner_accepts_the_yield_at_the_end_of_loop() {
  const LoopYield r = scan(kGood);
  TEST_ASSERT_TRUE(r.found);
  TEST_ASSERT_TRUE(r.closed);
  TEST_ASSERT_TRUE(r.bodyIsTheRealOne);
  TEST_ASSERT_FALSE(r.hasReturn);  // `return` in a comment does not count
  TEST_ASSERT_TRUE(r.tailExact);
}

void test_scanner_accepts_the_equivalent_spellings_of_the_guard() {
  const char* guards[] = {"#ifndef ARDUINO_ARCH_ESP8266", "#  if !defined( ARDUINO_ARCH_ESP8266 )",
                          "#if !defined ARDUINO_ARCH_ESP8266"};
  for (size_t i = 0; i < sizeof(guards) / sizeof(guards[0]); i++) {
    const std::string src = std::string("void loop(void) {\n  fry_ota::loopGuard();\n") + guards[i] +
                            "\n  vTaskDelay( 1 );\n#endif\n}\n";
    const LoopYield r = scan(src);
    TEST_ASSERT_TRUE(r.tailExact);
  }
}

void test_scanner_rejects_a_missing_yield() {
  const LoopYield r = scan("void loop() {\n  fry_ota::loopGuard();\n  work();\n}\n");
  TEST_ASSERT_TRUE(r.found);
  TEST_ASSERT_FALSE(r.tailExact);
}

void test_scanner_rejects_a_yield_without_the_esp8266_guard() {
  // This is the build that would not even compile on the ESP8266 (no vTaskDelay there).
  const LoopYield r = scan("void loop() {\n  fry_ota::loopGuard();\n  work();\n  vTaskDelay(1);\n}\n");
  TEST_ASSERT_FALSE(r.tailExact);
}

void test_scanner_rejects_the_wrong_guard_or_delay() {
  const char* wrong[] = {
      "#if defined(ARDUINO_ARCH_ESP8266)\n  vTaskDelay(1);\n#endif\n",        // inverted guard
      "#if !defined(ARDUINO_ARCH_ESP32)\n  vTaskDelay(1);\n#endif\n",         // another macro
      "#if !defined(ARDUINO_ARCH_ESP8266)\n  vTaskDelay(0);\n#endif\n",       // does not block
      "#if !defined(ARDUINO_ARCH_ESP8266)\n  delay(1);\n#endif\n",            // 0 ticks if HZ < 1000
      "#if !defined(ARDUINO_ARCH_ESP8266)\n  yield();\n#endif\n",             // not a sleep
      "#if !defined(ARDUINO_ARCH_ESP8266)\n  vTaskDelay(1);\n#else\n#endif\n",  // #else/#endif tail
  };
  for (size_t i = 0; i < sizeof(wrong) / sizeof(wrong[0]); i++) {
    const LoopYield r = scan(std::string("void loop() {\n  fry_ota::loopGuard();\n  work();\n") + wrong[i] + "}\n");
    TEST_ASSERT_FALSE(r.tailExact);
  }
}

void test_scanner_rejects_a_yield_that_is_commented_out() {
  const LoopYield r = scan(
      "void loop() {\n  fry_ota::loopGuard();\n  work();\n"
      "// #if !defined(ARDUINO_ARCH_ESP8266)\n"
      "//   vTaskDelay(1);\n"
      "// #endif\n"
      "}\n");
  TEST_ASSERT_FALSE(r.tailExact);
}

void test_scanner_rejects_a_yield_inside_the_switch() {
  // Every phase has to yield, not only the one that carries it.
  const LoopYield inCase = scan(
      "void loop() {\n  fry_ota::loopGuard();\n  switch (s_phase) {\n"
      "    case A:\n      work();\n"
      "#if !defined(ARDUINO_ARCH_ESP8266)\n      vTaskDelay(1);\n#endif\n"
      "      break;\n    case B:\n      other();\n      break;\n  }\n}\n");
  TEST_ASSERT_FALSE(inCase.tailExact);
  // After the last `break`, but still inside the switch's braces: the switch's `}` comes last.
  const LoopYield inSwitch = scan(
      "void loop() {\n  fry_ota::loopGuard();\n  switch (s_phase) {\n"
      "    case A:\n      work();\n      break;\n"
      "#if !defined(ARDUINO_ARCH_ESP8266)\n      vTaskDelay(1);\n#endif\n"
      "  }\n}\n");
  TEST_ASSERT_FALSE(inSwitch.tailExact);
  // The same inside a block of its own.
  const LoopYield inBlock = scan(
      "void loop() {\n  fry_ota::loopGuard();\n  if (x) {\n"
      "#if !defined(ARDUINO_ARCH_ESP8266)\n    vTaskDelay(1);\n#endif\n"
      "  }\n}\n");
  TEST_ASSERT_FALSE(inBlock.tailExact);
}

void test_scanner_rejects_a_yield_nested_in_another_conditional() {
  const LoopYield r = scan(
      "void loop() {\n  fry_ota::loopGuard();\n"
      "#ifdef SOMETHING\n"
      "#if !defined(ARDUINO_ARCH_ESP8266)\n  vTaskDelay(1);\n#endif\n"
      "#endif\n}\n");
  TEST_ASSERT_FALSE(r.tailExact);
}

void test_scanner_flags_a_return_that_would_skip_the_yield() {
  const LoopYield r = scan(
      "void loop() {\n  fry_ota::loopGuard();\n"
      "  if (idle) return;\n"
      "#if !defined(ARDUINO_ARCH_ESP8266)\n  vTaskDelay(1);\n#endif\n}\n");
  TEST_ASSERT_TRUE(r.tailExact);
  TEST_ASSERT_TRUE(r.hasReturn);
  // `returned` and a call such as pollFactoryResetButton() are not a return statement.
  const LoopYield ok = scan(
      "void loop() {\n  fry_ota::loopGuard();\n  int returned = 0; (void)returned;\n"
      "#if !defined(ARDUINO_ARCH_ESP8266)\n  vTaskDelay(1);\n#endif\n}\n");
  TEST_ASSERT_FALSE(ok.hasReturn);
}

void test_scanner_finds_only_a_definition_of_loop() {
  const LoopYield r = scan("void f() {\n  fry_provisioning::loop();\n  loop();\n}\n");
  TEST_ASSERT_FALSE(r.found);
  // A loop() with a body that closes before the file ends, and one that does not.
  TEST_ASSERT_FALSE(scan("void loop() {\n  work();\n").closed);
  TEST_ASSERT_TRUE(scan("void loop() {\n  work();\n}\n").closed);
}

void test_scanner_ignores_braces_in_strings_and_comments() {
  const LoopYield r = scan(
      "void loop() {\n  fry_ota::loopGuard();\n"
      "  Serial.println(\"} }\");  // }\n"
      "  char c = '{';  /* { */\n"
      "#if !defined(ARDUINO_ARCH_ESP8266)\n  vTaskDelay(1);\n#endif\n}\n");
  TEST_ASSERT_TRUE(r.closed);
  TEST_ASSERT_TRUE(r.tailExact);
}

// ---- src/main.cpp itself ------------------------------------------------------------------------

bool readFile(const std::string& path, std::string& out) {
  std::ifstream f(path.c_str(), std::ios::in | std::ios::binary);
  if (!f) return false;
  std::ostringstream ss;
  ss << f.rdbuf();
  out = ss.str();
  return !out.empty();
}

// main.cpp, found relative to this test (the compiler's __FILE__ is absolute or relative to the
// project directory) or, failing that, a few directories up from where the test runs.
bool loadMainSource(std::string& out, std::string& where) {
  const std::string rel = "src/main.cpp";
  const std::string self = __FILE__;
  const std::string tail = "test/test_loop_yield/test_main.cpp";
  std::vector<std::string> prefixes;
  if (self.size() >= tail.size() && self.compare(self.size() - tail.size(), tail.size(), tail) == 0) {
    prefixes.push_back(self.substr(0, self.size() - tail.size()));
  }
  const char* ups[] = {"", "../", "../../", "../../../", "../../../../"};
  for (size_t i = 0; i < sizeof(ups) / sizeof(ups[0]); i++) prefixes.push_back(ups[i]);
  for (size_t i = 0; i < prefixes.size(); i++) {
    if (readFile(prefixes[i] + rel, out)) {
      where = prefixes[i] + rel;
      return true;
    }
  }
  return false;
}

void test_main_loop_ends_with_the_guarded_yield() {
  std::string src, where;
  TEST_ASSERT_TRUE_MESSAGE(loadMainSource(src, where), "cannot read src/main.cpp");
  const LoopYield r = scan(src);
  char msg[300];
  TEST_ASSERT_TRUE_MESSAGE(r.found, "src/main.cpp: no `void loop()` definition");
  TEST_ASSERT_TRUE_MESSAGE(r.closed, "src/main.cpp: the body of loop() does not close");
  // not vacuous: this is the loop() that guards the OTA rollback, i.e. the real one
  TEST_ASSERT_TRUE_MESSAGE(r.bodyIsTheRealOne, "src/main.cpp: loop() no longer starts with fry_ota::loopGuard();");
  snprintf(msg, sizeof msg,
           "%s: loop() must END with `#if !defined(ARDUINO_ARCH_ESP8266)` / `vTaskDelay(1);` / `#endif` "
           "(a pass that never sleeps starves Wi-Fi/lwIP on the other core)",
           where.c_str());
  TEST_ASSERT_TRUE_MESSAGE(r.tailExact, msg);
}

void test_main_loop_has_no_return_that_skips_the_yield() {
  std::string src, where;
  TEST_ASSERT_TRUE_MESSAGE(loadMainSource(src, where), "cannot read src/main.cpp");
  const LoopYield r = scan(src);
  TEST_ASSERT_TRUE_MESSAGE(r.found && r.closed, "src/main.cpp: loop() not found");
  TEST_ASSERT_FALSE_MESSAGE(r.hasReturn,
                            "src/main.cpp: loop() has a `return`: that pass would skip the yield at its end");
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_scanner_accepts_the_yield_at_the_end_of_loop);
  RUN_TEST(test_scanner_accepts_the_equivalent_spellings_of_the_guard);
  RUN_TEST(test_scanner_rejects_a_missing_yield);
  RUN_TEST(test_scanner_rejects_a_yield_without_the_esp8266_guard);
  RUN_TEST(test_scanner_rejects_the_wrong_guard_or_delay);
  RUN_TEST(test_scanner_rejects_a_yield_that_is_commented_out);
  RUN_TEST(test_scanner_rejects_a_yield_inside_the_switch);
  RUN_TEST(test_scanner_rejects_a_yield_nested_in_another_conditional);
  RUN_TEST(test_scanner_flags_a_return_that_would_skip_the_yield);
  RUN_TEST(test_scanner_finds_only_a_definition_of_loop);
  RUN_TEST(test_scanner_ignores_braces_in_strings_and_comments);
  RUN_TEST(test_main_loop_ends_with_the_guarded_yield);
  RUN_TEST(test_main_loop_has_no_return_that_skips_the_yield);
  return UNITY_END();
}
