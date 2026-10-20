// Source pin for src/esp32/vpn_wireguard.cpp.
//
// The relay glue needs lwIP and the Arduino core, so the native tests cannot run it. What must never
// come back in it is a plain shutdown(): toward a peer that is still open it leaves the netconn on a
// pcb that lwIP can free behind its back (FinAction in lib/fry_core/socks_relay_core.h). The only
// places allowed to call shutdown() are the `case FinAction::HalfClose` branch (a socket that was
// read to EOF) and the FRY_RELAY_HALFCLOSE guard (the bench switch that restores the old behaviour).
// The last group reads the glue source and fails on any other call; the groups before it exercise
// the scanner on synthetic sources, so that a pass cannot come from a scanner that sees nothing.
#include <unity.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>
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

std::string trim(const std::string& s) {
  size_t b = 0, e = s.size();
  while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r')) b++;
  while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r')) e--;
  return s.substr(b, e - b);
}

// For every line: is it compiled only when FRY_RELAY_HALFCLOSE is 1 (`#if FRY_RELAY_HALFCLOSE`, or
// the #else branch of `#if !FRY_RELAY_HALFCLOSE`)? Anything this does not recognise counts as "no".
std::vector<bool> legacyLines(const std::vector<std::string>& lines) {
  struct Cond {
    bool legacyInIf, legacyInElse, inElse;
  };
  std::vector<Cond> stack;
  std::vector<bool> out;
  for (size_t li = 0; li < lines.size(); li++) {
    const std::string line = trim(lines[li]);
    if (!line.empty() && line[0] == '#') {
      size_t d = 1;
      while (d < line.size() && (line[d] == ' ' || line[d] == '\t')) d++;
      size_t e = d;
      while (e < line.size() && isIdent(line[e])) e++;
      const std::string name = line.substr(d, e - d);
      const std::string rest = trim(line.substr(e));
      if (name == "if") {
        const Cond c = {rest == "FRY_RELAY_HALFCLOSE", rest == "!FRY_RELAY_HALFCLOSE", false};
        stack.push_back(c);
      } else if (name == "ifdef" || name == "ifndef") {
        const Cond c = {false, false, false};
        stack.push_back(c);
      } else if (name == "else" && !stack.empty()) {
        stack.back().inElse = true;
      } else if (name == "elif" && !stack.empty()) {
        stack.back().inElse = true;
        stack.back().legacyInElse = false;
      } else if (name == "endif" && !stack.empty()) {
        stack.pop_back();
      }
    }
    bool legacy = false;
    for (size_t i = 0; i < stack.size(); i++) {
      if (stack[i].inElse ? stack[i].legacyInElse : stack[i].legacyInIf) legacy = true;
    }
    out.push_back(legacy);
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

// [begin, end) of the body of every `case FinAction::HalfClose:` label: up to the next label of the
// same switch or the brace that closes it.
std::vector<std::pair<size_t, size_t> > halfCloseBodies(const std::string& t) {
  std::vector<std::pair<size_t, size_t> > spans;
  const std::string label = "case FinAction::HalfClose";
  for (size_t i = t.find(label); i != std::string::npos; i = t.find(label, i + 1)) {
    size_t j = i + label.size();
    while (j < t.size() && (t[j] == ' ' || t[j] == '\t' || t[j] == '\n' || t[j] == '\r')) j++;
    if (j >= t.size() || t[j] != ':') continue;
    j++;
    const size_t begin = j;
    size_t end = t.size();
    int depth = 0;
    for (; j < t.size(); j++) {
      const char c = t[j];
      if (c == '{') {
        depth++;
      } else if (c == '}') {
        if (depth == 0) {
          end = j;
          break;
        }
        depth--;
      } else if (depth == 0 && (tokenAt(t, j, "case") || tokenAt(t, j, "default"))) {
        end = j;
        break;
      }
    }
    spans.push_back(std::make_pair(begin, end));
  }
  return spans;
}

// Offsets of calls to shutdown(), ::shutdown() and lwip_shutdown(); takeShutdown() and friends are
// different identifiers and do not count.
std::vector<size_t> shutdownCalls(const std::string& t) {
  std::vector<size_t> pos;
  const std::string kw = "shutdown";
  for (size_t i = t.find(kw); i != std::string::npos; i = t.find(kw, i + 1)) {
    size_t start = i;
    if (start >= 5 && t.compare(start - 5, 5, "lwip_") == 0) start -= 5;
    if (start > 0 && isIdent(t[start - 1])) continue;
    size_t j = i + kw.size();
    while (j < t.size() && (t[j] == ' ' || t[j] == '\t')) j++;
    if (j < t.size() && t[j] == '(') pos.push_back(i);
  }
  return pos;
}

struct Call {
  int line;     // 1-based
  bool half;    // inside `case FinAction::HalfClose`
  bool legacy;  // inside the FRY_RELAY_HALFCLOSE branch
  bool allowed() const { return half || legacy; }
};

std::vector<Call> scan(const std::string& source) {
  const std::string t = blank(source);
  const std::vector<bool> legacy = legacyLines(splitLines(t));
  const std::vector<std::pair<size_t, size_t> > bodies = halfCloseBodies(t);
  std::vector<Call> calls;
  const std::vector<size_t> pos = shutdownCalls(t);
  for (size_t k = 0; k < pos.size(); k++) {
    int line = 1;
    for (size_t i = 0; i < pos[k]; i++) {
      if (t[i] == '\n') line++;
    }
    Call c;
    c.line = line;
    c.legacy = static_cast<size_t>(line - 1) < legacy.size() && legacy[line - 1];
    c.half = false;
    for (size_t b = 0; b < bodies.size(); b++) {
      if (pos[k] >= bodies[b].first && pos[k] < bodies[b].second) c.half = true;
    }
    calls.push_back(c);
  }
  return calls;
}

// ---- the scanner, on synthetic sources ----------------------------------------------------------

void test_scanner_flags_a_bare_call_and_reports_its_line() {
  const std::vector<Call> c = scan("void f() {\n  int x = 1;\n  shutdown(fd, SHUT_WR);\n}\n");
  TEST_ASSERT_EQUAL(1, (int)c.size());
  TEST_ASSERT_EQUAL(3, c[0].line);
  TEST_ASSERT_FALSE(c[0].allowed());
}

void test_scanner_ignores_comments_and_string_literals() {
  const std::vector<Call> c = scan(
      "// shutdown(fd, 1) in a line comment\n"
      "/* shutdown(fd, 1)\n   spanning lines */\n"
      "const char* s = \"shutdown(fd, 1) \\\" shutdown(fd, 1)\";\n"
      "char q = '\"';  // the quote is a char literal here, not the start of a string\n"
      "int ok = takeShutdown(s, side);\n");
  TEST_ASSERT_EQUAL(0, (int)c.size());
}

void test_scanner_matches_the_call_forms_that_matter() {
  const std::vector<Call> c = scan(
      "a = shutdown(fd, 1);\n"
      "b = shutdown (fd, 1);\n"
      "c = lwip_shutdown(fd, 1);\n"
      "d = ::shutdown(fd, 1);\n"
      "e = takeShutdown(s, side);\n"
      "f = shutdown_all(s);\n"
      "g = my_shutdown(s);\n"
      "h = shutdown;\n");
  TEST_ASSERT_EQUAL(4, (int)c.size());
  for (int i = 0; i < 4; i++) {
    TEST_ASSERT_EQUAL(i + 1, c[i].line);
    TEST_ASSERT_FALSE(c[i].allowed());
  }
}

void test_scanner_allows_only_the_half_close_case() {
  const std::vector<Call> c = scan(
      "switch (takeFinAction(s, side)) {\n"
      "  case FinAction::None:\n"
      "    shutdown(fd, 1);\n"               // line 3: not allowed
      "    break;\n"
      "  case FinAction::HalfClose:\n"
      "    if (fd >= 0) shutdown(fd, 1);\n"  // line 6: allowed
      "    break;\n"
      "  case FinAction::Close:\n"
      "    shutdown(fd, 1);\n"               // line 9: not allowed
      "    break;\n"
      "}\n"
      "shutdown(fd, 1);\n");                 // line 12: not allowed
  TEST_ASSERT_EQUAL(4, (int)c.size());
  const int line[4] = {3, 6, 9, 12};
  const bool ok[4] = {false, true, false, false};
  for (int i = 0; i < 4; i++) {
    TEST_ASSERT_EQUAL(line[i], c[i].line);
    TEST_ASSERT_EQUAL((int)ok[i], (int)c[i].half);
    TEST_ASSERT_FALSE(c[i].legacy);
  }
}

void test_scanner_follows_braces_inside_the_half_close_case() {
  const std::vector<Call> c = scan(
      "switch (a) {\n"
      "  case FinAction::HalfClose: {\n"
      "    if (x) {\n"
      "      switch (b) { case 1: shutdown(fd, 1); break; }\n"  // line 4: still inside the case
      "    }\n"
      "    break;\n"
      "  }\n"
      "  default:\n"
      "    shutdown(fd, 1);\n"                                  // line 9: after the case
      "}\n");
  TEST_ASSERT_EQUAL(2, (int)c.size());
  TEST_ASSERT_EQUAL(4, c[0].line);
  TEST_ASSERT_TRUE(c[0].allowed());
  TEST_ASSERT_EQUAL(9, c[1].line);
  TEST_ASSERT_FALSE(c[1].allowed());
}

void test_scanner_allows_only_the_legacy_guard() {
  const std::vector<Call> c = scan(
      "#if FRY_RELAY_HALFCLOSE\n"
      "  shutdown(fd, 1);\n"      // line 2: allowed
      "#else\n"
      "  shutdown(fd, 1);\n"      // line 4: not allowed
      "#endif\n"
      "#if !FRY_RELAY_HALFCLOSE\n"
      "  shutdown(fd, 1);\n"      // line 7: not allowed
      "#else\n"
      "  shutdown(fd, 1);\n"      // line 9: allowed
      "#endif\n"
      "#if FRY_RELAY_HALFCLOSE\n"
      "#if SOMETHING\n"
      "  shutdown(fd, 1);\n"      // line 13: allowed (a nested conditional inside the guard)
      "#endif\n"
      "#endif\n"
      "#ifdef FRY_RELAY_HALFCLOSE\n"
      "  shutdown(fd, 1);\n"      // line 17: not allowed (#ifdef is true for the default 0 as well)
      "#endif\n"
      "#if FRY_RELAY_HALFCLOSE\n"
      "#elif OTHER\n"
      "  shutdown(fd, 1);\n"      // line 21: not allowed
      "#endif\n"
      "shutdown(fd, 1);\n");      // line 23: not allowed
  TEST_ASSERT_EQUAL(8, (int)c.size());
  const int line[8] = {2, 4, 7, 9, 13, 17, 21, 23};
  const bool ok[8] = {true, false, false, true, true, false, false, false};
  for (int i = 0; i < 8; i++) {
    TEST_ASSERT_EQUAL(line[i], c[i].line);
    TEST_ASSERT_EQUAL((int)ok[i], (int)c[i].legacy);
    TEST_ASSERT_FALSE(c[i].half);
  }
}

// ---- the relay glue itself ---------------------------------------------------------------------

bool readFile(const std::string& path, std::string& out) {
  std::ifstream f(path.c_str(), std::ios::in | std::ios::binary);
  if (!f) return false;
  std::ostringstream ss;
  ss << f.rdbuf();
  out = ss.str();
  return !out.empty();
}

// The glue source, found relative to this test (the compiler's __FILE__ is absolute or relative to
// the project directory) or, failing that, a few directories up from where the test runs.
bool loadRelaySource(std::string& out, std::string& where) {
  const std::string rel = "src/esp32/vpn_wireguard.cpp";
  const std::string self = __FILE__;
  const std::string tail = "test/test_relay_source_pin/test_main.cpp";
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

void test_the_relay_glue_calls_shutdown_only_where_it_is_safe() {
  std::string src, where;
  TEST_ASSERT_TRUE_MESSAGE(loadRelaySource(src, where), "cannot read src/esp32/vpn_wireguard.cpp");
  const std::vector<Call> calls = scan(src);
  char msg[400];
  snprintf(msg, sizeof msg,
           "%s: shutdown() outside `case FinAction::HalfClose` and the FRY_RELAY_HALFCLOSE guard, line(s)",
           where.c_str());
  int bad = 0, inHalfClose = 0;
  for (size_t i = 0; i < calls.size(); i++) {
    if (calls[i].half) inHalfClose++;
    if (calls[i].allowed()) continue;
    const size_t used = strlen(msg);
    if (bad < 6) snprintf(msg + used, sizeof msg - used, " %d", calls[i].line);
    bad++;
  }
  TEST_ASSERT_EQUAL_MESSAGE(0, bad, msg);
  // not vacuous: the branch that is allowed to half-close is there and does call shutdown()
  TEST_ASSERT_TRUE_MESSAGE(inHalfClose >= 1, "no shutdown() in a `case FinAction::HalfClose` branch");
}

void test_the_legacy_half_close_switch_defaults_to_off() {
  std::string src, where;
  TEST_ASSERT_TRUE_MESSAGE(loadRelaySource(src, where), "cannot read src/esp32/vpn_wireguard.cpp");
  const std::string name = "FRY_RELAY_HALFCLOSE";
  const std::vector<std::string> lines = splitLines(blank(src));
  int definesOff = 0, definesOther = 0;
  for (size_t i = 0; i < lines.size(); i++) {
    const std::string l = trim(lines[i]);
    if (l.empty() || l[0] != '#') continue;
    size_t d = 1;
    while (d < l.size() && (l[d] == ' ' || l[d] == '\t')) d++;
    if (l.compare(d, 6, "define") != 0) continue;
    const std::string rest = trim(l.substr(d + 6));
    if (rest.compare(0, name.size(), name) != 0) continue;
    if (rest.size() > name.size() && isIdent(rest[name.size()])) continue;
    if (trim(rest.substr(name.size())) == "0") {
      definesOff++;
    } else {
      definesOther++;
    }
  }
  TEST_ASSERT_EQUAL_MESSAGE(1, definesOff, "FRY_RELAY_HALFCLOSE must default to 0 (defined exactly once)");
  TEST_ASSERT_EQUAL_MESSAGE(0, definesOther, "FRY_RELAY_HALFCLOSE is defined as something other than 0");
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_scanner_flags_a_bare_call_and_reports_its_line);
  RUN_TEST(test_scanner_ignores_comments_and_string_literals);
  RUN_TEST(test_scanner_matches_the_call_forms_that_matter);
  RUN_TEST(test_scanner_allows_only_the_half_close_case);
  RUN_TEST(test_scanner_follows_braces_inside_the_half_close_case);
  RUN_TEST(test_scanner_allows_only_the_legacy_guard);
  RUN_TEST(test_the_relay_glue_calls_shutdown_only_where_it_is_safe);
  RUN_TEST(test_the_legacy_half_close_switch_defaults_to_off);
  return UNITY_END();
}
