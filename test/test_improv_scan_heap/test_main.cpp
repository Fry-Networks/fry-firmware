// The ESP8266 Improv scan list lives on the heap for one scan reply only (lib/fry_core/improv_scan_slot.h).
//
// pollScan() kept a `static ScanList` (1060 B of .bss) for the whole uptime. The heap is [_heap_start, 0x3FFFC000), so every static byte is a
// byte the image download's TLS session does not have (the 0.4.15 ESP8266 image missed gate b by 24 B). This test measures the real class with
// a counting global operator new: idle costs 0 B, a held list is one block of at least sizeof(ScanList), release gives all of it back, and an
// allocation that fails returns nullptr instead of throwing (the core panics on a failed throwing new).
//
// On main 46666f12 the header does not exist: the `#else` test fails and prints the static size that baseline pollScan() kept.
#include <unity.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <new>
#include <sstream>
#include <string>
#include <vector>

#include "improv_scan.h"

#if __has_include("improv_scan_slot.h")
#include "improv_scan_slot.h"
#define FRY_HAVE_SCAN_SLOT 1
#endif

namespace {
long g_liveBytes = 0;
long g_liveBlocks = 0;
long g_allocs = 0;
bool g_failNext = false;

struct Header {
  size_t size;
  size_t pad;
};
}  // namespace

void* operator new(std::size_t n, const std::nothrow_t&) noexcept {
  if (g_failNext) return nullptr;
  Header* h = static_cast<Header*>(std::malloc(sizeof(Header) + n));
  if (!h) return nullptr;
  h->size = n;
  g_liveBytes += static_cast<long>(n);
  g_liveBlocks++;
  g_allocs++;
  return h + 1;
}
void* operator new(std::size_t n) {
  void* p = operator new(n, std::nothrow);
  if (!p) throw std::bad_alloc();
  return p;
}
void operator delete(void* p) noexcept {
  if (!p) return;
  Header* h = static_cast<Header*>(p) - 1;
  g_liveBytes -= static_cast<long>(h->size);
  g_liveBlocks--;
  std::free(h);
}
void operator delete(void* p, std::size_t) noexcept { operator delete(p); }
void operator delete(void* p, const std::nothrow_t&) noexcept { operator delete(p); }

void setUp() {
  g_liveBytes = 0;
  g_liveBlocks = 0;
  g_allocs = 0;
  g_failNext = false;
}
void tearDown() {}

// Source pins on the glue (it needs the Arduino core, so it is not host-compiled; same technique as test_stale_token_heal_wiring).
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
  const std::string tail = "test/test_improv_scan_heap/test_main.cpp";
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

bool pollScanBody(std::string& body) {
  std::string src;
  if (!loadSource("src/core/improv_serial_glue.cpp", src)) return false;
  const size_t a = src.find("void pollScan() {");
  if (a == std::string::npos) return false;
  const size_t b = src.find("\n}\n", a);
  if (b == std::string::npos) return false;
  body = src.substr(a, b - a);
  return true;
}
}  // namespace

void test_glue_keeps_no_static_scan_list() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/core/improv_serial_glue.cpp", src), "improv_serial_glue.cpp");
  size_t pos = 0;
  while ((pos = src.find("ScanList", pos)) != std::string::npos) {
    const size_t ls = src.rfind('\n', pos);
    const std::string line = src.substr(ls == std::string::npos ? 0 : ls + 1, pos - (ls == std::string::npos ? 0 : ls + 1));
    TEST_ASSERT_TRUE_MESSAGE(line.find("static ") == std::string::npos, "no static ScanList object in the glue");
    pos += 8;
  }
}

void test_the_esp8266_branch_of_pollscan_uses_the_slot() {
  std::string body;
  TEST_ASSERT_TRUE(pollScanBody(body));
  const size_t slot = body.find("fry::improv::ScanListSlot slot;");
  TEST_ASSERT_TRUE_MESSAGE(slot != std::string::npos, "pollScan() declares a ScanListSlot");
  const size_t guard = body.rfind("#if defined(ARDUINO_ARCH_ESP8266)", slot);
  TEST_ASSERT_TRUE_MESSAGE(guard != std::string::npos, "inside the ESP8266 guard");
  TEST_ASSERT_TRUE_MESSAGE(body.find("#else", guard) > slot, "in the ESP8266 branch, not the #else one");
  TEST_ASSERT_TRUE(body.find("slot.acquire()", slot) != std::string::npos);
}

void test_a_failed_acquire_ends_the_scan_cleanly() {
  std::string body;
  TEST_ASSERT_TRUE(pollScanBody(body));
  const size_t a = body.find("if (!listp) {");
  TEST_ASSERT_TRUE_MESSAGE(a != std::string::npos, "the null-acquire path exists");
  const size_t r = body.find("return;", a);
  TEST_ASSERT_TRUE(r != std::string::npos);
  const std::string path = body.substr(a, r - a);
  TEST_ASSERT_TRUE_MESSAGE(path.find("sendError(") != std::string::npos, "the client gets an error");
  TEST_ASSERT_TRUE_MESSAGE(path.find("restoreScanMode();") != std::string::npos, "the radio mode is restored");
  TEST_ASSERT_TRUE_MESSAGE(path.find("WiFi.scanDelete();") != std::string::npos, "the scan results are freed");
}

#ifdef FRY_HAVE_SCAN_SLOT

using fry::improv::ScanList;
using fry::improv::ScanListSlot;

void test_an_idle_slot_holds_no_heap_and_is_pointer_sized() {
  ScanListSlot slot;
  TEST_ASSERT_FALSE(slot.held());
  TEST_ASSERT_EQUAL_INT(0, (int)g_liveBytes);
  TEST_ASSERT_EQUAL_INT(0, (int)g_allocs);
  TEST_ASSERT_TRUE_MESSAGE(sizeof(ScanListSlot) <= sizeof(void*), "the static footprint is one pointer");
  TEST_ASSERT_TRUE_MESSAGE(sizeof(ScanList) >= 1000, "the list this saves from .bss");
}

void test_a_held_list_is_one_block_and_release_gives_it_all_back() {
  ScanListSlot slot;
  ScanList* l = slot.acquire();
  TEST_ASSERT_NOT_NULL(l);
  TEST_ASSERT_TRUE(slot.held());
  TEST_ASSERT_EQUAL_INT(1, (int)g_liveBlocks);
  TEST_ASSERT_TRUE((size_t)g_liveBytes >= sizeof(ScanList));
  TEST_ASSERT_TRUE(l->add("home", -40, true));
  TEST_ASSERT_EQUAL_INT(1, (int)l->count());
  slot.release();
  TEST_ASSERT_FALSE(slot.held());
  TEST_ASSERT_EQUAL_INT(0, (int)g_liveBytes);
  TEST_ASSERT_EQUAL_INT(0, (int)g_liveBlocks);
}

void test_a_rescan_starts_with_an_empty_list() {
  ScanListSlot slot;
  ScanList* a = slot.acquire();
  TEST_ASSERT_NOT_NULL(a);
  a->add("one", -50, false);
  a->add("two", -60, true);
  TEST_ASSERT_EQUAL_INT(2, (int)a->count());
  ScanList* b = slot.acquire();  // a second acquire without release reuses the block, cleared
  TEST_ASSERT_NOT_NULL(b);
  TEST_ASSERT_EQUAL_INT(0, (int)b->count());
  TEST_ASSERT_EQUAL_INT(1, (int)g_liveBlocks);
}

void test_a_failed_allocation_returns_null_without_throwing() {
  ScanListSlot slot;
  g_failNext = true;
  ScanList* l = slot.acquire();
  g_failNext = false;
  TEST_ASSERT_NULL(l);
  TEST_ASSERT_FALSE(slot.held());
  TEST_ASSERT_EQUAL_INT(0, (int)g_liveBytes);
  TEST_ASSERT_NOT_NULL(slot.acquire());  // and the slot still works afterwards
}

void test_repeated_scans_do_not_leak_and_the_destructor_releases() {
  for (int i = 0; i < 50; i++) {
    ScanListSlot slot;
    ScanList* l = slot.acquire();
    TEST_ASSERT_NOT_NULL(l);
    l->add("x", -30 - i, true);
  }
  TEST_ASSERT_EQUAL_INT(50, (int)g_allocs);
  TEST_ASSERT_EQUAL_INT(0, (int)g_liveBytes);
  TEST_ASSERT_EQUAL_INT(0, (int)g_liveBlocks);
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_glue_keeps_no_static_scan_list);
  RUN_TEST(test_the_esp8266_branch_of_pollscan_uses_the_slot);
  RUN_TEST(test_a_failed_acquire_ends_the_scan_cleanly);
  RUN_TEST(test_an_idle_slot_holds_no_heap_and_is_pointer_sized);
  RUN_TEST(test_a_held_list_is_one_block_and_release_gives_it_all_back);
  RUN_TEST(test_a_rescan_starts_with_an_empty_list);
  RUN_TEST(test_a_failed_allocation_returns_null_without_throwing);
  RUN_TEST(test_repeated_scans_do_not_leak_and_the_destructor_releases);
  return UNITY_END();
}

#else  // baseline: no slot

void test_pollscan_keeps_no_static_scan_list() {
  char msg[96];
  std::snprintf(msg, sizeof(msg), "baseline: pollScan() keeps a static ScanList of %u B in .bss (no improv_scan_slot.h)",
                (unsigned)sizeof(fry::improv::ScanList));
  TEST_FAIL_MESSAGE(msg);
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_glue_keeps_no_static_scan_list);
  RUN_TEST(test_the_esp8266_branch_of_pollscan_uses_the_slot);
  RUN_TEST(test_a_failed_acquire_ends_the_scan_cleanly);
  RUN_TEST(test_pollscan_keeps_no_static_scan_list);
  return UNITY_END();
}

#endif
