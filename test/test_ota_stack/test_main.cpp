// The OTA check must not put ~2 KB of locals on the ESP8266's 4 KB loop stack.
//
// Measured on the bench board (esp8266_heapnet_wdtoff-6, 2026-10-22): the forced 16384/512 TLS connect of the
// manifest check never completed, on GitHub and on hardwareapi alike. The loop() stack (core cont.h
// CONT_STACKSIZE, 4096 B) was already 2272 B deep when http.GET() started, because checkNow() had a 1920 B
// frame (gcc -fstack-usage): downloadAndApply() is called once, so it was inlined into checkNow(), and its
// `uint8_t buf[1024]`, second HTTPClient / WiFiClientSecure / WiFiClient and Sha256 sat in the frame during
// the manifest GET. The connect chain (sendRequest .. _run_until .. lwIP/SDK output) plus one level-1
// interrupt frame (XTOS reserves 256 B, ~350 B with the WiFi handler) went ~430 B past the end of the stack.
// cont_t's pc_suspend / sp_suspend sit directly below it, so cont_can_suspend() turned false: optimistic_yield()
// stopped yielding, the SDK never ran (no send, no ACK, no timers: a 15 s gap, then BearSSL's own 15 s timeout)
// and the soft WDT fired when it was on. "Stack smashing detected." followed at the end of loop().
//
// The ESP8266 build therefore has to keep the download phase out of checkNow()'s frame and the 1 KB read buffer
// off the stack. ota_client.cpp needs the Arduino core, so the native tests cannot run it; like test_ota_session
// and test_relay_source_pin this reads the source. THIS IS A SOURCE-TEXT PIN, not a measurement: it keeps the
// two known causes from coming back, it does not prove the stack margin. The margin was measured on hardware
// (cf / sp_free in the bench [hop] lines) and with gcc -fstack-usage (see the commit message).
//
// What must hold, for the code that is compiled on ESP8266 (not in the #else of `#if defined(ARDUINO_ARCH_ESP8266)`
// and not in `#if !defined(...)`):
//   1. no local array of 256 B or more (named constexpr sizes are resolved);
//   2. downloadAndApply() is declared with FRY_OTA_ESP8266_NOINLINE, which expands to __attribute__((noinline))
//      only in an ESP8266-only branch and to nothing otherwise, so the ESP32 images are untouched.
#include <unity.h>

#include <cstdlib>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace {

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

enum Branch { Neutral, Esp8266Only, NotEsp8266 };

struct CodeLine {
  std::string text;  // comments and literals blanked, spacing kept
  int no;            // 1-based line number
  bool live8266;     // compiled on ESP8266: no enclosing branch that is dead there
  bool only8266;     // inside a branch compiled on ESP8266 only
};

// Code lines of `source` with their ESP8266 reachability. Preprocessor lines other than #define are consumed.
std::vector<CodeLine> scan(const std::string& source) {
  const std::string code = blankNonCode(source);
  std::vector<Branch> stack;
  std::vector<CodeLine> lines;
  std::string cur;
  int no = 1;
  for (size_t i = 0; i <= code.size(); i++) {
    if (i < code.size() && code[i] != '\n') {
      cur.push_back(code[i]);
      continue;
    }
    const std::string sq = squeeze(cur);
    bool consumed = false;
    if (!sq.empty() && sq[0] == '#') {
      size_t d = 0;
      while (d < cur.size() && (cur[d] == ' ' || cur[d] == '\t')) d++;
      d++;  // '#'
      while (d < cur.size() && (cur[d] == ' ' || cur[d] == '\t')) d++;
      size_t e = d;
      while (e < cur.size() && ((cur[e] >= 'a' && cur[e] <= 'z') || (cur[e] >= 'A' && cur[e] <= 'Z'))) e++;
      const std::string name = cur.substr(d, e - d);
      const std::string rest = squeeze(cur.substr(e));
      if (name == "if") {
        if (rest == "defined(ARDUINO_ARCH_ESP8266)") stack.push_back(Esp8266Only);
        else if (rest == "!defined(ARDUINO_ARCH_ESP8266)") stack.push_back(NotEsp8266);
        else stack.push_back(Neutral);
        consumed = true;
      } else if (name == "ifdef" || name == "ifndef") {
        stack.push_back(Neutral);
        consumed = true;
      } else if (name == "else" && !stack.empty()) {
        if (stack.back() == Esp8266Only) stack.back() = NotEsp8266;
        else if (stack.back() == NotEsp8266) stack.back() = Esp8266Only;
        consumed = true;
      } else if (name == "elif" && !stack.empty()) {
        stack.back() = Neutral;
        consumed = true;
      } else if (name == "endif" && !stack.empty()) {
        stack.pop_back();
        consumed = true;
      } else if (name != "define") {
        consumed = true;  // #include, #error, #undef ...
      }
    }
    if (!consumed && !sq.empty()) {
      CodeLine l;
      l.text = cur;
      l.no = no;
      l.live8266 = true;
      l.only8266 = false;
      for (size_t k = 0; k < stack.size(); k++) {
        if (stack[k] == NotEsp8266) l.live8266 = false;
        if (stack[k] == Esp8266Only) l.only8266 = true;
      }
      lines.push_back(l);
    }
    cur.clear();
    no++;
  }
  return lines;
}

bool isIdent(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'; }

// Size in bytes of the element type named by the word before an array declarator, 0 if it is not a type word.
size_t typeBytes(const std::string& w) {
  if (w == "char" || w == "uint8_t" || w == "int8_t" || w == "bool") return 1;
  if (w == "uint16_t" || w == "int16_t" || w == "short") return 2;
  if (w == "uint32_t" || w == "int32_t" || w == "int" || w == "long" || w == "size_t" || w == "unsigned" ||
      w == "float")
    return 4;
  if (w == "uint64_t" || w == "int64_t" || w == "double") return 8;
  return 0;
}

struct BigArray {
  int no;
  std::string name;
  size_t bytes;
};

// Local/static arrays of at least `limit` bytes among the lines that are compiled on ESP8266. Sizes are digits or the
// name of a `constexpr ... NAME = digits;` seen in the same source.
std::vector<BigArray> bigArrays(const std::string& source, size_t limit) {
  const std::vector<CodeLine> lines = scan(source);
  std::map<std::string, size_t> consts;
  for (size_t li = 0; li < lines.size(); li++) {
    const std::string& t = lines[li].text;
    const size_t ce = t.find("constexpr");
    if (ce == std::string::npos) continue;
    const size_t eq = t.find('=', ce);
    if (eq == std::string::npos) continue;
    size_t ne = eq;
    while (ne > ce && t[ne - 1] == ' ') ne--;
    size_t nb = ne;
    while (nb > ce && isIdent(t[nb - 1])) nb--;
    size_t vb = eq + 1;
    while (vb < t.size() && t[vb] == ' ') vb++;
    size_t ve = vb;
    while (ve < t.size() && t[ve] >= '0' && t[ve] <= '9') ve++;
    if (nb < ne && ve > vb) consts[t.substr(nb, ne - nb)] = static_cast<size_t>(std::atol(t.substr(vb, ve - vb).c_str()));
  }
  std::vector<BigArray> out;
  for (size_t li = 0; li < lines.size(); li++) {
    if (!lines[li].live8266) continue;
    const std::string& t = lines[li].text;
    for (size_t p = 0; p < t.size(); p++) {
      if (t[p] != '[') continue;
      size_t ne = p;
      size_t nb = ne;
      while (nb > 0 && isIdent(t[nb - 1])) nb--;
      if (nb == ne) continue;  // not `name[`
      size_t q = nb;
      while (q > 0 && t[q - 1] == ' ') q--;
      size_t wb = q;
      while (wb > 0 && isIdent(t[wb - 1])) wb--;
      const size_t elem = typeBytes(t.substr(wb, q - wb));
      if (!elem) continue;  // `doc["x"][y]`, `a = b[i]`: not a declaration
      const size_t close = t.find(']', p);
      if (close == std::string::npos) continue;
      const std::string dim = squeeze(t.substr(p + 1, close - p - 1));
      size_t n = 0;
      if (!dim.empty() && dim.find_first_not_of("0123456789") == std::string::npos) {
        n = static_cast<size_t>(std::atol(dim.c_str()));
      } else if (consts.count(dim)) {
        n = consts[dim];
      }
      if (n * elem >= limit) out.push_back({lines[li].no, t.substr(nb, ne - nb), n * elem});
    }
  }
  return out;
}

// Counts of `needle` (matched on blank-free text) among the live lines: total, and those in an ESP8266-only branch.
struct Hits {
  int total;
  int onlyEsp8266;
};
Hits countHits(const std::string& source, const std::string& needle) {
  const std::vector<CodeLine> lines = scan(source);
  const std::string nsq = squeeze(needle);
  Hits h = {0, 0};
  for (size_t li = 0; li < lines.size(); li++) {
    const std::string sq = squeeze(lines[li].text);
    size_t pos = 0;
    while ((pos = sq.find(nsq, pos)) != std::string::npos) {
      h.total++;
      if (lines[li].only8266) h.onlyEsp8266++;
      pos += nsq.size();
    }
  }
  return h;
}

bool readFile(const std::string& path, std::string& out) {
  std::ifstream f(path.c_str(), std::ios::in | std::ios::binary);
  if (!f) return false;
  std::ostringstream ss;
  ss << f.rdbuf();
  out = ss.str();
  return !out.empty();
}

bool loadOtaClient(std::string& out) {
  const std::string rel = "src/core/ota_client.cpp";
  const std::string self = __FILE__;
  const std::string tail = "test/test_ota_stack/test_main.cpp";
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

// ---- the scanner itself: controls, so a pass cannot come from a scanner that sees nothing -----------------------

void test_scanner_finds_a_big_array_and_resolves_named_sizes() {
  std::vector<BigArray> r = bigArrays("void f() {\n  uint8_t buf[1024];\n}\n", 256);
  TEST_ASSERT_EQUAL_UINT(1, r.size());
  TEST_ASSERT_EQUAL_UINT(1024, r[0].bytes);
  TEST_ASSERT_EQUAL_INT(2, r[0].no);

  r = bigArrays("void f() {\n  constexpr size_t kBuf = 512;\n  char b[kBuf];\n}\n", 256);
  TEST_ASSERT_EQUAL_UINT_MESSAGE(1, r.size(), "a named constexpr size must be resolved");
  TEST_ASSERT_EQUAL_UINT(512, r[0].bytes);

  r = bigArrays("void f() {\n  uint32_t w[100];\n}\n", 256);  // 400 B: the element size counts
  TEST_ASSERT_EQUAL_UINT(1, r.size());
}

void test_scanner_ignores_small_arrays_indexing_comments_and_non_esp8266_branches() {
  TEST_ASSERT_EQUAL_UINT(0, bigArrays("void f() {\n  char key[40] = {0};\n  uint8_t digest[32];\n}\n", 256).size());
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, bigArrays("void f() {\n  x = doc[\"builds\"][1024];\n  y = buf[1024];\n}\n", 256).size(),
                                 "indexing is not a declaration");
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, bigArrays("// uint8_t buf[1024];\n/* uint8_t b[1024]; */\nconst char* s = \"uint8_t b[1024]\";\n", 256).size(),
                                 "comments and strings are not code");
  TEST_ASSERT_EQUAL_UINT_MESSAGE(
      0,
      bigArrays("#if defined(ARDUINO_ARCH_ESP8266)\n  int x;\n#else\n  uint8_t buf[1024];\n#endif\n", 256).size(),
      "the #else of the ESP8266 branch is the ESP32 build");
  TEST_ASSERT_EQUAL_UINT_MESSAGE(0, bigArrays("#if !defined(ARDUINO_ARCH_ESP8266)\n  uint8_t buf[1024];\n#endif\n", 256).size(),
                                 "a !defined(ESP8266) branch is the ESP32 build");
  TEST_ASSERT_EQUAL_UINT_MESSAGE(
      1,
      bigArrays("#if defined(ARDUINO_ARCH_ESP8266)\n  uint8_t buf[1024];\n#else\n  int x;\n#endif\n", 256).size(),
      "the ESP8266 branch itself is checked");
  TEST_ASSERT_EQUAL_UINT_MESSAGE(1, bigArrays("#if defined(FRY_BOARD_ESP8266)\n  uint8_t buf[1024];\n#endif\n", 256).size(),
                                 "an unknown condition is treated as live on ESP8266");
}

void test_scanner_counts_hits_by_branch() {
  Hits h = countHits("#if defined(ARDUINO_ARCH_ESP8266)\n#define X __attribute__((noinline))\n#else\n#define X\n#endif\n",
                     "__attribute__((noinline))");
  TEST_ASSERT_EQUAL_INT(1, h.total);
  TEST_ASSERT_EQUAL_INT(1, h.onlyEsp8266);
  h = countHits("#define X __attribute__((noinline))\n", "__attribute__((noinline))");
  TEST_ASSERT_EQUAL_INT(1, h.total);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, h.onlyEsp8266, "an unguarded attribute would change the ESP32 images");
  h = countHits("// __attribute__((noinline))\n", "__attribute__((noinline))");
  TEST_ASSERT_EQUAL_INT(0, h.total);
}

// ---- the real file -----------------------------------------------------------------------------------------------

void test_no_large_array_is_a_stack_local_on_esp8266() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadOtaClient(src), "cannot read src/core/ota_client.cpp");
  const std::vector<BigArray> r = bigArrays(src, 256);
  std::string what;
  for (size_t i = 0; i < r.size(); i++) {
    what += " line " + std::to_string(r[i].no) + " " + r[i].name + "[" + std::to_string(r[i].bytes) + " B]";
  }
  TEST_ASSERT_EQUAL_UINT_MESSAGE(
      0, r.size(),
      ("ota_client.cpp declares a stack array of >= 256 B on the ESP8266 build (4 KB loop stack, ~2.3 KB already "
       "used when the manifest GET starts):" + what).c_str());
}

void test_download_is_not_inlined_into_checknow_on_esp8266() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadOtaClient(src), "cannot read src/core/ota_client.cpp");
  const Hits attr = countHits(src, "__attribute__((noinline))");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, attr.total, "exactly one noinline attribute (the FRY_OTA_ESP8266_NOINLINE definition)");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, attr.onlyEsp8266, "the noinline definition must sit in an ESP8266-only branch");
  const Hits decl = countHits(src, "FRY_OTA_ESP8266_NOINLINE bool downloadAndApply(");
  TEST_ASSERT_EQUAL_INT_MESSAGE(
      1, decl.total,
      "downloadAndApply() must be declared FRY_OTA_ESP8266_NOINLINE: inlined into checkNow() its locals sit in "
      "checkNow()'s frame during the manifest GET");
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_scanner_finds_a_big_array_and_resolves_named_sizes);
  RUN_TEST(test_scanner_ignores_small_arrays_indexing_comments_and_non_esp8266_branches);
  RUN_TEST(test_scanner_counts_hits_by_branch);
  RUN_TEST(test_no_large_array_is_a_stack_local_on_esp8266);
  RUN_TEST(test_download_is_not_inlined_into_checknow_on_esp8266);
  return UNITY_END();
}
