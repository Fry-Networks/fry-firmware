// T-ESP: the stricter ESP8266 RAM guard and the IRAM-heap build are wired, and the old gates are untouched.
//
// tools/esp8266_ram_margin.py fails the esp8266 build above tools/esp8266_ram_margin.json measured_total + headroom (33596 + 64).
// This native test pins, on the host, what the post-link script cannot be trusted to keep: the numbers stay strict, the old budget
// (tools/check_esp8266_ram_budget.py, 34408) and the OTA heap gates in platformio.ini are exactly as before, and the IRAM-heap flag that
// moves BearSSL's record buffers out of the DRAM heap is present together with the handler it needs.
#include <unity.h>

#include <fstream>
#include <sstream>
#include <string>

namespace {

std::string slurp(const char* rel) {
  std::string path = rel;
  std::ifstream f(path);
  if (!f) {
    path = std::string("../") + rel;
    f.open(path);
  }
  std::stringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

bool has(const std::string& hay, const char* needle) { return hay.find(needle) != std::string::npos; }

long numberAfter(const std::string& text, const char* key) {
  size_t p = text.find(key);
  if (p == std::string::npos) return -1;
  p = text.find(':', p);
  return p == std::string::npos ? -1 : std::stol(text.substr(p + 1));
}

std::string envSection(const std::string& ini, const char* header) {
  size_t a = ini.find(header);
  if (a == std::string::npos) return "";
  size_t b = ini.find("\n[env:", a + 1);
  return ini.substr(a, b == std::string::npos ? std::string::npos : b - a);
}

}  // namespace

void test_the_margin_numbers_are_strict() {
  const std::string j = slurp("tools/esp8266_ram_margin.json");
  TEST_ASSERT_TRUE_MESSAGE(!j.empty(), "cannot read tools/esp8266_ram_margin.json");
  const long total = numberAfter(j, "\"measured_total\"");
  const long head = numberAfter(j, "\"headroom\"");
  TEST_ASSERT_EQUAL_INT(33596, total);
  TEST_ASSERT_TRUE(head >= 0 && head <= 128);
  TEST_ASSERT_EQUAL_INT(1648 + 4892 + 27056, total);
  TEST_ASSERT_TRUE(total + head < 34408 - 500);  // far below the old budget
  TEST_ASSERT_EQUAL_INT(34356, numberAfter(j, "\"pre_t_esp_total\""));
}

void test_the_old_budget_is_untouched() {
  const std::string old = slurp("tools/check_esp8266_ram_budget.py");
  TEST_ASSERT_TRUE(has(old, "BASELINE_BYTES = 34152"));
  TEST_ASSERT_TRUE(has(old, "MARGIN_BYTES = 256"));
}

void test_the_ota_heap_gates_are_not_loosened() {
  const std::string sect = envSection(slurp("platformio.ini"), "[env:esp8266]");
  TEST_ASSERT_TRUE(has(sect, "-DHEAP_GATE_OTA_MANIFEST=29976 -DHEAP_GATE_OTA_MANIFEST_BLOCK=29808"));
  TEST_ASSERT_TRUE(has(sect, "-DHEAP_GATE_OTA_DOWNLOAD=42280 -DHEAP_GATE_OTA_DOWNLOAD_BLOCK=36816 -DHEAP_GATE_OTA_STREAM=5376"));
}

void test_the_iram_heap_and_both_gates_are_wired_in_the_prod_env() {
  const std::string sect = envSection(slurp("platformio.ini"), "[env:esp8266]");
  TEST_ASSERT_TRUE(has(sect, "-D PIO_FRAMEWORK_ARDUINO_MMU_CACHE16_IRAM48_SECHEAP_SHARED"));
  TEST_ASSERT_TRUE(has(sect, "-DNON32XFER_HANDLER"));
  TEST_ASSERT_TRUE(has(sect, "-D PIO_FRAMEWORK_ARDUINO_LWIP2_LOW_MEMORY"));
  TEST_ASSERT_TRUE(has(sect, "post:tools/check_esp8266_ram_budget.py"));
  TEST_ASSERT_TRUE(has(sect, "post:tools/esp8266_ram_margin.py"));
}

void test_the_heartbeat_bodies_reserve_before_serializing() {
  const std::string src = slurp("src/core/hardwareapi_client.cpp");
  size_t n = 0, p = 0;
  while ((p = src.find("body.reserve(measureJson(doc));", p)) != std::string::npos) {
    n++;
    p++;
  }
  TEST_ASSERT_EQUAL_UINT32(3, n);
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_margin_numbers_are_strict);
  RUN_TEST(test_the_old_budget_is_untouched);
  RUN_TEST(test_the_ota_heap_gates_are_not_loosened);
  RUN_TEST(test_the_iram_heap_and_both_gates_are_wired_in_the_prod_env);
  RUN_TEST(test_the_heartbeat_bodies_reserve_before_serializing);
  return UNITY_END();
}
