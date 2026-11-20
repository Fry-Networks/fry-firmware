// Boot registration of the ESP32 family, run from the PRODUCTION statements.
//
// The existing test_esp32_register_at_boot checks the wiring in src/core/hardwareapi_client.cpp
// as text and then runs a behavioural model (Esp32RegSim) that is written in the test itself, so
// the scenarios there do not exercise the code that ships. This test closes that gap without
// touching production code: it cuts the four state-changing fragments out of the real source,
//
//   * the RegClass::Ok block of registerInstallation()
//   * the healStaleTokenIfDue() success block
//   * the failure tail of registerInstallation()
//   * tick()'s due-check and attempt stamp
//
// and executes their statements on a small interpreter over the four scheduling variables
// (s_lastRegisterAttemptMs, s_nextRegisterDelayMs, s_regFailures, s_registered). The helpers the
// fragments call (fry::classifyRegistration, regClassRetryQuickly, nextRegisterDelayMs,
// nonZeroAttemptStamp) are the real ones from lib/fry_core/reg_result.h, and the request body is
// built by the real fry::buildInstallationDoc.
//
// Fail-closed: a statement that names one of the four variables in a form the interpreter does not
// know aborts the test, so a production edit cannot slip past it unseen. Only the ESP32 side of the
// `#if defined(ARDUINO_ARCH_ESP8266)` regions is modelled.
//
// The environment variable FRY_REG_SRC may name another copy of hardwareapi_client.cpp (an older
// release, or a mutated copy) so the same scenarios can be shown to fail on it.
#include <unity.h>

#include <ArduinoJson.h>

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "heartbeat_fields.h"
#include "reg_result.h"

namespace {

// ---- file access ---------------------------------------------------------------------------------

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
  const std::string tail = "test/test_reg_boot_prod_source/test_main.cpp";
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

// hardwareapi_client.cpp, or the copy named by FRY_REG_SRC.
bool loadHwapi(std::string& out) {
  const char* over = std::getenv("FRY_REG_SRC");
  if (over && *over) return readFile(over, out);
  return loadSource("src/core/hardwareapi_client.cpp", out);
}

bool between(const std::string& src, const std::string& from, const std::string& to, std::string& out) {
  const size_t a = src.find(from);
  if (a == std::string::npos) return false;
  const size_t b = src.find(to, a + from.size());
  if (b == std::string::npos) return false;
  out = src.substr(a, b - a);
  return true;
}

std::string trim(const std::string& s) {
  size_t a = 0, b = s.size();
  while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) a++;
  while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) b--;
  return s.substr(a, b - a);
}

bool startsWith(const std::string& s, const std::string& p) { return s.compare(0, p.size(), p) == 0; }

bool isIdentChar(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

// Whole-word search.
bool mentions(const std::string& text, const std::string& name) {
  for (size_t pos = text.find(name); pos != std::string::npos; pos = text.find(name, pos + 1)) {
    const bool leftOk = pos == 0 || !isIdentChar(text[pos - 1]);
    const size_t end = pos + name.size();
    const bool rightOk = end >= text.size() || !isIdentChar(text[end]);
    if (leftOk && rightOk) return true;
  }
  return false;
}

const char* const kStateVars[] = {"s_lastRegisterAttemptMs", "s_nextRegisterDelayMs", "s_regFailures",
                                  "s_registered"};

bool isStateVar(const std::string& n) {
  for (size_t i = 0; i < sizeof(kStateVars) / sizeof(kStateVars[0]); i++) {
    if (n == kStateVars[i]) return true;
  }
  return false;
}

bool mentionsState(const std::string& text) {
  for (size_t i = 0; i < sizeof(kStateVars) / sizeof(kStateVars[0]); i++) {
    if (mentions(text, kStateVars[i])) return true;
  }
  return false;
}

// ---- scanner: source text -> directives, statements, block opens and closes -----------------------

enum ItemKind { kDirective, kStmt, kOpen, kClose };

struct Item {
  ItemKind kind;
  std::string text;
};

bool scanItems(const std::string& src, std::vector<Item>& out, std::string& err) {
  std::string cur;
  int depth = 0;
  bool lineStart = true;
  size_t i = 0;
  const size_t n = src.size();
  while (i < n) {
    const char c = src[i];
    if (c == '\n') {
      cur += ' ';
      lineStart = true;
      i++;
      continue;
    }
    if (lineStart && (c == ' ' || c == '\t' || c == '\r')) {
      cur += ' ';
      i++;
      continue;
    }
    if (lineStart && c == '#') {
      size_t e = src.find('\n', i);
      if (e == std::string::npos) e = n;
      Item it;
      it.kind = kDirective;
      it.text = trim(src.substr(i, e - i));
      out.push_back(it);
      i = e;
      continue;
    }
    lineStart = false;
    if (c == '/' && i + 1 < n && src[i + 1] == '/') {
      const size_t e = src.find('\n', i);
      i = (e == std::string::npos) ? n : e;
      continue;
    }
    if (c == '/' && i + 1 < n && src[i + 1] == '*') {
      const size_t e = src.find("*/", i + 2);
      if (e == std::string::npos) {
        err = "unterminated block comment";
        return false;
      }
      i = e + 2;
      continue;
    }
    if (c == '"' || c == '\'') {
      cur += c;
      i++;
      while (i < n && src[i] != c) {
        if (src[i] == '\\' && i + 1 < n) {
          cur += src[i];
          i++;
        }
        cur += src[i];
        i++;
      }
      if (i >= n) {
        err = "unterminated literal";
        return false;
      }
      cur += c;
      i++;
      continue;
    }
    if (c == '(') depth++;
    if (c == ')') depth--;
    if (depth == 0 && c == ';') {
      const std::string t = trim(cur);
      if (!t.empty()) {
        Item it;
        it.kind = kStmt;
        it.text = t;
        out.push_back(it);
      }
      cur.clear();
      i++;
      continue;
    }
    if (depth == 0 && c == '{') {
      Item it;
      it.kind = kOpen;
      it.text = trim(cur);
      out.push_back(it);
      cur.clear();
      i++;
      continue;
    }
    if (depth == 0 && c == '}') {
      if (!trim(cur).empty()) {
        err = "text before '}' without ';': " + trim(cur);
        return false;
      }
      Item it;
      it.kind = kClose;
      out.push_back(it);
      cur.clear();
      i++;
      continue;
    }
    cur += c;
    i++;
  }
  if (!trim(cur).empty()) {
    err = "trailing text: " + trim(cur);
    return false;
  }
  return true;
}

// ---- interpreter state ---------------------------------------------------------------------------

struct Ctx {
  // the four production variables, with their production initial values
  uint32_t last = 0;
  uint32_t next = 0;
  uint32_t fails = 0;
  bool registered = false;
  // inputs of the fragment being run
  uint32_t now = 0;
  uint32_t started = 0;
  int cls = 0;
  uint32_t hb = 0;  // INSTALL_HEARTBEAT_MS, read from include/config.h
  std::map<std::string, uint32_t> locals;
  // hooks for the two calls the fragments make into code that needs the Arduino core
  std::function<bool()> registerHook;
  bool healResult = false;
  // outcome
  bool returned = false;
  bool retval = false;
  std::string err;
};

void fail(Ctx& c, const std::string& why) {
  if (c.err.empty()) c.err = why;
}

// ---- expression evaluator over uint32_t ----------------------------------------------------------

class Eval {
 public:
  Eval(Ctx& c, const std::string& text) : c_(c), p_(0) { tokenize(text); }

  uint32_t run() {
    const uint32_t v = orExpr();
    if (c_.err.empty() && p_ != t_.size()) fail(c_, "trailing tokens in expression");
    return v;
  }

 private:
  Ctx& c_;
  std::vector<std::string> t_;
  size_t p_;

  void tokenize(const std::string& s) {
    size_t i = 0;
    while (i < s.size()) {
      const char ch = s[i];
      if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') {
        i++;
        continue;
      }
      if (isIdentChar(ch) && !(ch >= '0' && ch <= '9')) {
        size_t j = i;
        while (j < s.size() && (isIdentChar(s[j]) || s[j] == ':')) j++;
        t_.push_back(s.substr(i, j - i));
        i = j;
        continue;
      }
      if (ch >= '0' && ch <= '9') {
        size_t j = i;
        while (j < s.size() && isIdentChar(s[j])) j++;
        t_.push_back(s.substr(i, j - i));
        i = j;
        continue;
      }
      if (i + 1 < s.size()) {
        const std::string two = s.substr(i, 2);
        if (two == "||" || two == "&&" || two == "==" || two == "!=" || two == ">=" || two == "<=") {
          t_.push_back(two);
          i += 2;
          continue;
        }
      }
      if (std::string("(),!*+-<>").find(ch) != std::string::npos) {
        t_.push_back(std::string(1, ch));
        i++;
        continue;
      }
      fail(c_, std::string("cannot evaluate character '") + ch + "' in: " + s);
      return;
    }
  }

  bool peek(const char* tok) const { return p_ < t_.size() && t_[p_] == tok; }

  void expect(const char* tok) {
    if (peek(tok)) {
      p_++;
    } else {
      fail(c_, std::string("expected ") + tok);
    }
  }

  uint32_t orExpr() {
    uint32_t v = andExpr();
    while (peek("||")) {
      p_++;
      const uint32_t r = andExpr();
      v = (v != 0 || r != 0) ? 1 : 0;
    }
    return v;
  }
  uint32_t andExpr() {
    uint32_t v = eqExpr();
    while (peek("&&")) {
      p_++;
      const uint32_t r = eqExpr();
      v = (v != 0 && r != 0) ? 1 : 0;
    }
    return v;
  }
  uint32_t eqExpr() {
    uint32_t v = relExpr();
    while (peek("==") || peek("!=")) {
      const bool eq = t_[p_] == "==";
      p_++;
      const uint32_t r = relExpr();
      v = (eq ? (v == r) : (v != r)) ? 1 : 0;
    }
    return v;
  }
  uint32_t relExpr() {
    uint32_t v = addExpr();
    while (peek("<") || peek(">") || peek("<=") || peek(">=")) {
      const std::string op = t_[p_];
      p_++;
      const uint32_t r = addExpr();
      bool res = false;
      if (op == "<") res = v < r;
      if (op == ">") res = v > r;
      if (op == "<=") res = v <= r;
      if (op == ">=") res = v >= r;
      v = res ? 1 : 0;
    }
    return v;
  }
  uint32_t addExpr() {
    uint32_t v = mulExpr();
    while (peek("+") || peek("-")) {
      const bool plus = t_[p_] == "+";
      p_++;
      const uint32_t r = mulExpr();
      v = plus ? static_cast<uint32_t>(v + r) : static_cast<uint32_t>(v - r);  // wraps like the 32-bit target
    }
    return v;
  }
  uint32_t mulExpr() {
    uint32_t v = unary();
    while (peek("*")) {
      p_++;
      const uint32_t r = unary();
      v = static_cast<uint32_t>(v * r);
    }
    return v;
  }
  uint32_t unary() {
    if (peek("!")) {
      p_++;
      return unary() == 0 ? 1 : 0;
    }
    return primary();
  }

  uint32_t number(const std::string& tk) {
    std::string d = tk;
    while (!d.empty() && (d[d.size() - 1] == 'u' || d[d.size() - 1] == 'U' || d[d.size() - 1] == 'l' ||
                          d[d.size() - 1] == 'L')) {
      d.erase(d.size() - 1);
    }
    return static_cast<uint32_t>(std::strtoull(d.c_str(), nullptr, 0));
  }

  uint32_t primary() {
    if (p_ >= t_.size()) {
      fail(c_, "unexpected end of expression");
      return 0;
    }
    const std::string tk = t_[p_++];
    if (tk == "(") {
      const uint32_t v = orExpr();
      expect(")");
      return v;
    }
    if (tk[0] >= '0' && tk[0] <= '9') return number(tk);
    if (isIdentChar(tk[0])) {
      if (peek("(")) return call(tk);
      return variable(tk);
    }
    fail(c_, "unexpected token " + tk);
    return 0;
  }

  void skipArgs() {  // the opening '(' is current
    int depth = 0;
    while (p_ < t_.size()) {
      if (t_[p_] == "(") depth++;
      if (t_[p_] == ")") {
        depth--;
        if (depth == 0) {
          p_++;
          return;
        }
      }
      p_++;
    }
    fail(c_, "unbalanced call");
  }

  uint32_t call(const std::string& name) {
    if (name == "registerInstallation" || name == "fry_hwapi::registerInstallation") {
      skipArgs();
      return c_.registerHook ? (c_.registerHook() ? 1 : 0) : 0;
    }
    if (name == "healStaleTokenIfDue") {
      skipArgs();
      return c_.healResult ? 1 : 0;
    }
    p_++;  // '('
    std::vector<uint32_t> a;
    if (!peek(")")) {
      for (;;) {
        a.push_back(orExpr());
        if (peek(",")) {
          p_++;
          continue;
        }
        break;
      }
    }
    expect(")");
    if (!c_.err.empty()) return 0;
    if (name == "fry::nonZeroAttemptStamp" && a.size() == 1) {
      return static_cast<uint32_t>(fry::nonZeroAttemptStamp(a[0]));
    }
    if (name == "fry::nextRegisterDelayMs" && a.size() == 2) {
      return fry::nextRegisterDelayMs(static_cast<fry::RegClass>(a[0]), a[1]);
    }
    if (name == "fry::registerAttemptDue" && a.size() == 3) {
      return fry::registerAttemptDue(a[0], a[1], a[2]) ? 1 : 0;
    }
    fail(c_, "unmodelled call " + name);
    return 0;
  }

  uint32_t variable(const std::string& n) {
    if (n == "s_lastRegisterAttemptMs") return c_.last;
    if (n == "s_nextRegisterDelayMs") return c_.next;
    if (n == "s_regFailures") return c_.fails;
    if (n == "s_registered") return c_.registered ? 1 : 0;
    if (n == "now") return c_.now;
    if (n == "started") return c_.started;
    if (n == "cls") return static_cast<uint32_t>(c_.cls);
    if (n == "INSTALL_HEARTBEAT_MS") return c_.hb;
    if (n == "true") return 1;
    if (n == "false") return 0;
    if (n == "fry::RegClass::Ok") return static_cast<uint32_t>(fry::RegClass::Ok);
    if (n == "fry::RegClass::Unauthorized") return static_cast<uint32_t>(fry::RegClass::Unauthorized);
    if (n == "fry::RegClass::Forbidden") return static_cast<uint32_t>(fry::RegClass::Forbidden);
    if (n == "fry::RegClass::Conflict") return static_cast<uint32_t>(fry::RegClass::Conflict);
    if (n == "fry::RegClass::OtherClientError") return static_cast<uint32_t>(fry::RegClass::OtherClientError);
    if (n == "fry::RegClass::Unreachable") return static_cast<uint32_t>(fry::RegClass::Unreachable);
    std::map<std::string, uint32_t>::const_iterator it = c_.locals.find(n);
    if (it != c_.locals.end()) return it->second;
    fail(c_, "unknown name in expression: " + n);
    return 0;
  }
};

bool evalCond(Ctx& c, const std::string& text) { return Eval(c, text).run() != 0; }

// ---- statement runner ----------------------------------------------------------------------------

struct Frame {
  bool isPp;
  bool parentActive;
  bool cond;
  bool chainTaken;
  bool active;
};

std::string squeeze(const std::string& s) {
  std::string o;
  bool sp = false;
  for (size_t i = 0; i < s.size(); i++) {
    if (s[i] == ' ' || s[i] == '\t') {
      sp = true;
      continue;
    }
    if (sp && !o.empty()) o += ' ';
    sp = false;
    o += s[i];
  }
  return o;
}

// The text between the '(' that opens at `open` and its matching ')'; npos in `closeAt` if unbalanced.
std::string parenInner(const std::string& s, size_t open, size_t& closeAt) {
  int depth = 0;
  for (size_t i = open; i < s.size(); i++) {
    if (s[i] == '(') depth++;
    if (s[i] == ')') {
      depth--;
      if (depth == 0) {
        closeAt = i;
        return s.substr(open + 1, i - open - 1);
      }
    }
  }
  closeAt = std::string::npos;
  return std::string();
}

class Runner {
 public:
  explicit Runner(Ctx& c) : c_(c) {}

  void run(const std::vector<Item>& items) {
    st_.clear();
    Frame last = {false, false, false, false, false};
    bool haveLast = false;
    for (size_t k = 0; k < items.size() && c_.err.empty() && !c_.returned; k++) {
      const Item& it = items[k];
      if (it.kind == kDirective) {
        directive(squeeze(it.text));
        haveLast = false;
      } else if (it.kind == kOpen) {
        open(squeeze(it.text), last, haveLast);
        haveLast = false;
      } else if (it.kind == kClose) {
        if (st_.empty() || st_.back().isPp) {
          fail(c_, "unbalanced '}'");
          return;
        }
        last = st_.back();
        st_.pop_back();
        haveLast = true;
      } else {
        stmt(it.text);
        haveLast = false;
      }
    }
    if (c_.err.empty() && !c_.returned && !st_.empty()) fail(c_, "unclosed block");
  }

 private:
  Ctx& c_;
  std::vector<Frame> st_;

  bool active() const { return st_.empty() ? true : st_.back().active; }

  void directive(const std::string& t) {
    const bool parent = active();
    if (startsWith(t, "#if")) {
      bool cond = false;
      if (t == "#if !defined(ARDUINO_ARCH_ESP8266)") {
        cond = true;
      } else if (t == "#if defined(ARDUINO_ARCH_ESP8266)") {
        cond = false;
      } else if (parent) {
        fail(c_, "unmodelled preprocessor line: " + t);
      }
      Frame f = {true, parent, cond, cond, parent && cond};
      st_.push_back(f);
    } else if (t == "#else") {
      if (st_.empty() || !st_.back().isPp) {
        fail(c_, "#else without #if");
        return;
      }
      st_.back().cond = !st_.back().cond;
      st_.back().active = st_.back().parentActive && st_.back().cond;
    } else if (t == "#endif") {
      if (st_.empty() || !st_.back().isPp) {
        fail(c_, "#endif without #if");
        return;
      }
      st_.pop_back();
    } else if (parent) {
      fail(c_, "unmodelled preprocessor line: " + t);
    }
  }

  std::string condOf(const std::string& header, size_t from) {
    const size_t open = header.find('(', from);
    size_t close = std::string::npos;
    if (open == std::string::npos) {
      fail(c_, "no condition in: " + header);
      return std::string();
    }
    const std::string inner = parenInner(header, open, close);
    if (close == std::string::npos || !trim(header.substr(close + 1)).empty()) {
      fail(c_, "cannot parse condition in: " + header);
    }
    return inner;
  }

  void open(const std::string& header, const Frame& last, bool haveLast) {
    const bool parent = active();
    Frame f = {false, parent, false, false, false};
    if (startsWith(header, "else if")) {
      if (!haveLast) {
        fail(c_, "else without if");
        return;
      }
      const bool prev = last.chainTaken;
      bool cond = false;
      if (parent && !prev) cond = evalCond(c_, condOf(header, 7));
      f.cond = cond;
      f.chainTaken = prev || cond;
      f.active = parent && !prev && cond;
    } else if (header == "else") {
      if (!haveLast) {
        fail(c_, "else without if");
        return;
      }
      const bool prev = last.chainTaken;
      f.cond = !prev;
      f.chainTaken = true;
      f.active = parent && !prev;
    } else if (startsWith(header, "if (") || startsWith(header, "if(")) {
      const bool cond = parent ? evalCond(c_, condOf(header, 2)) : false;
      f.cond = cond;
      f.chainTaken = cond;
      f.active = parent && cond;
    } else if (parent) {
      fail(c_, "cannot model block header: " + header);
      return;
    }
    st_.push_back(f);
  }

  void stmt(const std::string& raw) {
    if (!active()) return;
    const std::string t = squeeze(trim(raw));
    if (startsWith(t, "return")) {
      const std::string rest = trim(t.substr(6));
      c_.retval = rest.empty() ? false : evalCond(c_, rest);
      c_.returned = true;
      return;
    }
    if (startsWith(t, "FRY_PRINTF(") || startsWith(t, "FRY_PRINTLN(")) return;  // reads only
    if (startsWith(t, "if (") || startsWith(t, "if(")) {
      size_t close = std::string::npos;
      const std::string cond = parenInner(t, t.find('('), close);
      if (close == std::string::npos) {
        fail(c_, "cannot parse: " + t);
        return;
      }
      const std::string rest = trim(t.substr(close + 1));
      if (mentionsState(cond) || mentionsState(rest)) {
        if (evalCond(c_, cond) && c_.err.empty()) stmt(rest);
      } else if (startsWith(rest, "return")) {
        fail(c_, "cannot model a conditional return: " + t);
      }
      return;
    }
    if (!mentionsState(t)) return;  // no effect on the four scheduling variables
    if (startsWith(t, "bool ")) {
      const size_t eq = t.find('=');
      if (eq == std::string::npos) {
        fail(c_, "unrecognised state statement: " + t);
        return;
      }
      const std::string name = trim(t.substr(5, eq - 5));
      c_.locals[name] = evalCond(c_, trim(t.substr(eq + 1))) ? 1 : 0;
      return;
    }
    if (t.size() > 2 && t.compare(t.size() - 2, 2, "++") == 0) {
      const std::string name = trim(t.substr(0, t.size() - 2));
      if (!isStateVar(name)) {
        fail(c_, "unrecognised state statement: " + t);
        return;
      }
      if (name == "s_regFailures") {
        c_.fails++;
      } else if (name == "s_lastRegisterAttemptMs") {
        c_.last++;
      } else if (name == "s_nextRegisterDelayMs") {
        c_.next++;
      } else {
        fail(c_, "unrecognised state statement: " + t);
      }
      return;
    }
    // NAME = EXPR, where '=' is a plain assignment
    size_t eq = std::string::npos;
    for (size_t i = 0; i < t.size(); i++) {
      if (t[i] != '=') continue;
      const char prev = i > 0 ? t[i - 1] : ' ';
      const char next = i + 1 < t.size() ? t[i + 1] : ' ';
      if (next == '=' || prev == '=' || prev == '!' || prev == '<' || prev == '>') continue;
      eq = i;
      break;
    }
    if (eq == std::string::npos) {
      fail(c_, "unrecognised state statement: " + t);
      return;
    }
    const std::string lhs = trim(t.substr(0, eq));
    if (!isStateVar(lhs)) {
      fail(c_, "unrecognised state statement: " + t);
      return;
    }
    const uint32_t v = Eval(c_, trim(t.substr(eq + 1))).run();
    if (!c_.err.empty()) return;
    if (lhs == "s_lastRegisterAttemptMs") c_.last = v;
    if (lhs == "s_nextRegisterDelayMs") c_.next = v;
    if (lhs == "s_regFailures") c_.fails = v;
    if (lhs == "s_registered") c_.registered = v != 0;
  }
};

// ---- the production fragments --------------------------------------------------------------------

struct Frags {
  std::vector<Item> ok, heal, fail, tick;
  std::string bootTrigger;  // fry_trigger_register_now()
  std::string src;
};

bool cut(const std::string& src, const char* from, const char* to, std::vector<Item>& items,
         std::string& why) {
  std::string frag;
  if (!between(src, from, to, frag)) {
    why = std::string("cannot find the fragment starting at: ") + from;
    return false;
  }
  std::string err;
  if (!scanItems(frag, items, err)) {
    why = std::string("cannot scan the fragment starting at: ") + from + " (" + err + ")";
    return false;
  }
  return true;
}

bool loadFrags(Frags& f, std::string& why) {
  if (!loadHwapi(f.src)) {
    why = "cannot read hardwareapi_client.cpp";
    return false;
  }
  std::string fn;
  if (!between(f.src, "bool registerInstallation() {", "int lastRegisterHttp()", fn)) {
    why = "cannot find registerInstallation()";
    return false;
  }
  if (!cut(fn, "if (cls == fry::RegClass::Ok) {", "if (!fry::regClassRetryQuickly(cls)) {", f.ok, why)) return false;
  if (!cut(fn, "if (healStaleTokenIfDue(", "break;", f.heal, why)) return false;
  if (!cut(fn, "if (s_regFailures < 0xFFFFFFFFu) s_regFailures++;", "return false;\n}", f.fail, why)) return false;
  if (!cut(f.src, "bool dueForAttempt =", "fry_telemetry::tick();", f.tick, why)) return false;
  if (!between(f.src, "extern \"C\" void fry_trigger_register_now() {", "extern \"C\" void fry_trigger_poc_now",
               f.bootTrigger)) {
    why = "cannot find fry_trigger_register_now()";
    return false;
  }
  return true;
}

uint32_t heartbeatFromConfig() {
  std::string cfg;
  if (!loadSource("include/config.h", cfg)) return 0;
  const std::string key = "#define INSTALL_HEARTBEAT_MS";
  const size_t at = cfg.find(key);
  if (at == std::string::npos) return 0;
  return static_cast<uint32_t>(std::strtoull(cfg.c_str() + at + key.size(), nullptr, 0));
}

std::string versionFromIni() {
  std::string ini;
  if (!loadSource("platformio.ini", ini)) return std::string();
  const std::string key = "-DFRY_FIRMWARE_VERSION='\"";
  const size_t at = ini.find(key);
  if (at == std::string::npos) return std::string();
  const size_t b = at + key.size();
  const size_t e = ini.find('"', b);
  return e == std::string::npos ? std::string() : ini.substr(b, e - b);
}

// ---- a device built from the fragments -----------------------------------------------------------

struct Dev {
  Frags f;
  Ctx c;
  std::vector<int> script;  // HTTP status of each request, in order; `fallback` after the end
  size_t si;
  int fallback;
  bool healWorks;
  int posts;
  int heals;
  int lastCode;
  std::vector<std::string> bodies;
  std::string version;

  Dev() : si(0), fallback(200), healWorks(false), posts(0), heals(0), lastCode(0), version("0.0.0-test") {}

  bool load(std::string& why) {
    if (!loadFrags(f, why)) return false;
    c.last = 0;
    c.next = heartbeatFromConfig();  // `unsigned long s_nextRegisterDelayMs = INSTALL_HEARTBEAT_MS;`
    c.hb = c.next;
    c.fails = 0;
    c.registered = false;
    if (c.hb == 0) {
      why = "cannot read INSTALL_HEARTBEAT_MS from include/config.h";
      return false;
    }
    c.registerHook = std::bind(&Dev::registerInstallation, this);
    return true;
  }

  void recordBody() {
    fry::InstallationFields fields{};
    fields.minerKey = "FEM-TEST-0001";
    fields.installId = "0123456789abcdef0123456789abcdef";
    fields.minerCode = "IOTVPN";
    fields.softwareVersion = version.c_str();
    fields.pocVersion = "1.0.0";
    fields.hostname = "fry-test";
    fields.os = "esp32s3";
    fields.deviceName = "fry-test";
    fields.flash = {4194304, 4194304, 1500000, 900000};
    JsonDocument doc;
    fry::buildInstallationDoc(doc, fields);
    std::string body;
    serializeJson(doc, body);
    bodies.push_back(body);
  }

  int nextCode() { return si < script.size() ? script[si++] : fallback; }

  // registerInstallation(): the request loop is modelled here (two attempts, a quick retry only for an
  // unreachable server); every state change comes from the production fragments.
  bool registerInstallation() {
    c.started = c.now;
    for (int attempt = 0; attempt < 2; attempt++) {
      lastCode = nextCode();
      posts++;
      recordBody();
      const fry::RegClass cls = fry::classifyRegistration(lastCode);
      c.cls = static_cast<int>(cls);
      c.returned = false;
      Runner(c).run(f.ok);
      if (c.returned) {
        c.returned = false;
        return c.retval;
      }
      if (!fry::regClassRetryQuickly(cls)) {
        c.healResult = healWorks && lastCode == 404;  // the stale-token signature is a 404 with our token sent
        if (lastCode == 404) heals++;
        Runner(c).run(f.heal);
        if (c.returned) {
          c.returned = false;
          return c.retval;
        }
        break;
      }
    }
    c.returned = false;
    Runner(c).run(f.fail);
    c.returned = false;
    return false;
  }

  // fry_trigger_register_now() on the ESP32 family: registerInstallation() directly.
  void boot(uint32_t nowMs) {
    c.now = nowMs;
    registerInstallation();
  }

  void tick(uint32_t nowMs) {
    c.now = nowMs;
    c.locals.clear();
    c.returned = false;
    Runner(c).run(f.tick);
    c.returned = false;
  }
};

void loaded(Dev& d) {
  std::string why;
  TEST_ASSERT_TRUE_MESSAGE(d.load(why), why.c_str());
}

void clean(const Dev& d) { TEST_ASSERT_TRUE_MESSAGE(d.c.err.empty(), d.c.err.c_str()); }

// ---- tests ---------------------------------------------------------------------------------------

void test_the_four_production_fragments_are_found_and_run_clean() {
  Dev d;
  loaded(d);
  TEST_ASSERT_TRUE(d.f.ok.size() > 3);
  TEST_ASSERT_TRUE(d.f.heal.size() > 3);
  TEST_ASSERT_TRUE(d.f.fail.size() > 3);
  TEST_ASSERT_TRUE(d.f.tick.size() > 3);
  d.script.push_back(200);
  d.boot(4000);
  clean(d);
  TEST_ASSERT_EQUAL_INT(1, d.posts);
}

void test_the_esp32_boot_trigger_calls_registerInstallation_and_nothing_else() {
  Dev d;
  loaded(d);
  std::vector<Item> items;
  std::string err;
  TEST_ASSERT_TRUE_MESSAGE(scanItems(d.f.bootTrigger, items, err), err.c_str());
  // The ESP32 side of the #if is the `#else` branch: exactly one statement, the direct call.
  bool inElse = false;
  int stmts = 0;
  std::string only;
  for (size_t i = 0; i < items.size(); i++) {
    if (items[i].kind == kDirective && squeeze(items[i].text) == "#else") inElse = true;
    if (items[i].kind == kDirective && squeeze(items[i].text) == "#endif") inElse = false;
    if (inElse && items[i].kind == kStmt) {
      stmts++;
      only = items[i].text;
    }
  }
  TEST_ASSERT_EQUAL_INT(1, stmts);
  TEST_ASSERT_EQUAL_STRING("fry_hwapi::registerInstallation()", only.c_str());
}

void test_interpreter_aborts_on_a_state_statement_it_does_not_know() {
  const char* bad[] = {"s_registered |= true;", "memset(&s_regFailures, 0, 4);", "s_regFailures += 2;",
                       "auto& alias = s_registered;"};
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    std::vector<Item> items;
    std::string err;
    TEST_ASSERT_TRUE(scanItems(bad[i], items, err));
    Ctx k;
    Runner(k).run(items);
    TEST_ASSERT_TRUE_MESSAGE(k.err.find("unrecognised state statement") != std::string::npos, bad[i]);
  }
  // control: the recognised forms run and change the variables
  std::vector<Item> items;
  std::string err;
  TEST_ASSERT_TRUE(scanItems("s_regFailures = 0; s_regFailures++; s_registered = true;", items, err));
  Ctx k;
  k.fails = 9;
  Runner(k).run(items);
  TEST_ASSERT_TRUE_MESSAGE(k.err.empty(), k.err.c_str());
  TEST_ASSERT_EQUAL_UINT32(1, k.fails);
  TEST_ASSERT_TRUE(k.registered);
}

void test_boot_success_is_recorded_so_the_first_ticks_do_not_register_again() {
  Dev d;
  loaded(d);
  d.script.push_back(200);
  d.boot(4000);
  clean(d);
  TEST_ASSERT_EQUAL_INT(1, d.posts);
  TEST_ASSERT_EQUAL_UINT32(4000, d.c.last);
  TEST_ASSERT_EQUAL_UINT32(d.c.hb, d.c.next);
  TEST_ASSERT_EQUAL_UINT32(0, d.c.fails);
  TEST_ASSERT_TRUE(d.c.registered);
  TEST_ASSERT_TRUE_MESSAGE(d.c.hb >= 900000UL, "a heartbeat under 15 minutes would be a registration storm");

  d.tick(4005);
  d.tick(19000);          // 15 s later
  d.tick(4000 + d.c.hb - 1);
  clean(d);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, d.posts, "a second registration before the heartbeat is due");
  TEST_ASSERT_EQUAL_UINT32(4000, d.c.last);

  d.tick(4000 + d.c.hb);  // the hourly refresh
  clean(d);
  TEST_ASSERT_EQUAL_INT(2, d.posts);
  TEST_ASSERT_EQUAL_UINT32(4000 + d.c.hb, d.c.last);
  d.tick(4000 + d.c.hb + 10);
  TEST_ASSERT_EQUAL_INT(2, d.posts);
}

void test_unreachable_at_boot_retries_on_the_first_tick_then_backs_off() {
  Dev d;
  loaded(d);
  d.script.push_back(503);  // attempt 1
  d.script.push_back(503);  // the quick retry inside the same call
  d.boot(4000);
  clean(d);
  TEST_ASSERT_EQUAL_INT(2, d.posts);
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(0, d.c.last, "a failed boot attempt must leave the stamp at 0");
  TEST_ASSERT_EQUAL_UINT32(1, d.c.fails);
  TEST_ASSERT_EQUAL_UINT32(fry::nextRegisterDelayMs(fry::RegClass::Unreachable, 1), d.c.next);
  TEST_ASSERT_FALSE(d.c.registered);

  d.script.push_back(200);  // the server is back
  d.tick(4050);
  clean(d);
  TEST_ASSERT_EQUAL_INT(3, d.posts);
  TEST_ASSERT_EQUAL_UINT32(4050, d.c.last);
  TEST_ASSERT_TRUE(d.c.registered);
  TEST_ASSERT_EQUAL_UINT32(0, d.c.fails);
  d.tick(5000);
  TEST_ASSERT_EQUAL_INT(3, d.posts);
}

void test_rejected_at_boot_retries_once_on_the_first_tick_then_waits_the_long_delay() {
  Dev d;
  loaded(d);
  d.fallback = 401;
  d.boot(4000);
  clean(d);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, d.posts, "a 4xx is an answer: no quick retry");
  TEST_ASSERT_EQUAL_UINT32(0, d.c.last);
  TEST_ASSERT_EQUAL_UINT32(fry::nextRegisterDelayMs(fry::RegClass::Unauthorized, 1), d.c.next);

  d.tick(4050);
  clean(d);
  TEST_ASSERT_EQUAL_INT(2, d.posts);
  TEST_ASSERT_EQUAL_UINT32(4050, d.c.last);
  TEST_ASSERT_FALSE(d.c.registered);
  d.tick(10000);
  d.tick(4050 + 3599000);
  TEST_ASSERT_EQUAL_INT(2, d.posts);
  d.tick(4050 + d.c.next);
  TEST_ASSERT_EQUAL_INT(3, d.posts);
}

void test_stale_token_heal_success_is_recorded_like_a_normal_success() {
  Dev d;
  loaded(d);
  d.script.push_back(404);
  d.healWorks = true;
  d.boot(4500);
  clean(d);
  TEST_ASSERT_EQUAL_INT(1, d.heals);
  TEST_ASSERT_EQUAL_UINT32(4500, d.c.last);
  TEST_ASSERT_EQUAL_UINT32(d.c.hb, d.c.next);
  TEST_ASSERT_EQUAL_UINT32(0, d.c.fails);
  TEST_ASSERT_TRUE(d.c.registered);
  d.tick(4600);
  d.tick(4500 + d.c.hb - 1);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, d.posts, "the heal path must not leave tick() a second registration");
}

void test_stale_token_heal_failure_is_not_recorded_so_tick_retries_at_once() {
  Dev d;
  loaded(d);
  d.script.push_back(404);
  d.healWorks = false;
  d.boot(4500);
  clean(d);
  TEST_ASSERT_EQUAL_INT(1, d.heals);
  TEST_ASSERT_EQUAL_UINT32(0, d.c.last);
  TEST_ASSERT_EQUAL_UINT32(1, d.c.fails);
  TEST_ASSERT_FALSE(d.c.registered);
  d.script.push_back(200);
  d.tick(4550);
  clean(d);
  TEST_ASSERT_EQUAL_INT(2, d.posts);
  TEST_ASSERT_TRUE(d.c.registered);
}

void test_ota_reboot_sends_exactly_one_registration_carrying_the_new_version() {
  const std::string version = versionFromIni();
  TEST_ASSERT_TRUE_MESSAGE(!version.empty(), "cannot read FRY_FIRMWARE_VERSION from platformio.ini");
  Dev d;
  loaded(d);
  // The production body builder takes the version from the build flag.
  TEST_ASSERT_TRUE_MESSAGE(d.f.src.find("fields.softwareVersion = FRY_FIRMWARE_VERSION;") != std::string::npos,
                           "the registration body no longer takes its version from FRY_FIRMWARE_VERSION");
  d.version = version;
  d.script.push_back(200);
  d.boot(3800);  // RAM state is fresh after the OTA reboot; NVS identity is kept
  d.tick(3900);
  d.tick(60000);
  clean(d);
  TEST_ASSERT_EQUAL_INT(1, d.posts);
  TEST_ASSERT_EQUAL_UINT32(1, static_cast<uint32_t>(d.bodies.size()));
  JsonDocument parsed;
  TEST_ASSERT_FALSE(deserializeJson(parsed, d.bodies[0]));
  TEST_ASSERT_EQUAL_STRING(version.c_str(), parsed["software_version_installed"] | "");
}

void test_the_due_check_survives_the_32_bit_millis_wrap() {
  Dev d;
  loaded(d);
  d.script.push_back(200);
  const uint32_t started = 4294967040u;  // 256 ms before the counter wraps
  d.boot(started);
  clean(d);
  TEST_ASSERT_EQUAL_UINT32(started, d.c.last);
  d.tick(started + 100);                              // not wrapped yet
  d.tick(static_cast<uint32_t>(started + 300));       // wrapped
  d.tick(static_cast<uint32_t>(started + d.c.hb - 1));
  TEST_ASSERT_EQUAL_INT(1, d.posts);
  d.tick(static_cast<uint32_t>(started + d.c.hb));
  TEST_ASSERT_EQUAL_INT(2, d.posts);
}

void test_a_boot_at_millis_zero_is_still_recorded() {
  Dev d;
  loaded(d);
  d.script.push_back(200);
  d.boot(0);
  clean(d);
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(1, d.c.last, "a stamp of 0 would mean 'never attempted' and re-register");
  d.tick(5);
  d.tick(15000);
  TEST_ASSERT_EQUAL_INT(1, d.posts);
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_four_production_fragments_are_found_and_run_clean);
  RUN_TEST(test_the_esp32_boot_trigger_calls_registerInstallation_and_nothing_else);
  RUN_TEST(test_interpreter_aborts_on_a_state_statement_it_does_not_know);
  RUN_TEST(test_boot_success_is_recorded_so_the_first_ticks_do_not_register_again);
  RUN_TEST(test_unreachable_at_boot_retries_on_the_first_tick_then_backs_off);
  RUN_TEST(test_rejected_at_boot_retries_once_on_the_first_tick_then_waits_the_long_delay);
  RUN_TEST(test_stale_token_heal_success_is_recorded_like_a_normal_success);
  RUN_TEST(test_stale_token_heal_failure_is_not_recorded_so_tick_retries_at_once);
  RUN_TEST(test_ota_reboot_sends_exactly_one_registration_carrying_the_new_version);
  RUN_TEST(test_the_due_check_survives_the_32_bit_millis_wrap);
  RUN_TEST(test_a_boot_at_millis_zero_is_still_recorded);
  return UNITY_END();
}
