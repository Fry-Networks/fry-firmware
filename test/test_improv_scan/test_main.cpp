// Improv "request scanned Wi-Fi networks" row list (lib/fry_core/improv_scan.*).
//
// Before: the ESP8266 build answered every scan request with the empty terminator, so an Improv
// client on that chip never saw a network. The rules below are what its scan results are reduced to
// before they go on the wire: no hidden/empty SSIDs, one row per SSID (the strongest), a bounded
// list, strongest first, and the same RSSI / auth cells the ESP32 path sends.
#include <unity.h>

#include <cstdio>
#include <cstring>

#include "improv_scan.h"

using fry::improv::ScanList;

namespace {

void test_empty_and_hidden_ssids_are_dropped() {
  ScanList l;
  TEST_ASSERT_FALSE(l.add("", -40, true));
  TEST_ASSERT_FALSE(l.add(nullptr, -40, true));
  TEST_ASSERT_EQUAL(0, (int)l.count());
}

void test_duplicate_ssid_keeps_the_strongest() {
  ScanList l;
  l.add("home", -80, true);
  l.add("home", -50, true);
  l.add("home", -70, true);
  TEST_ASSERT_EQUAL(1, (int)l.count());
  TEST_ASSERT_EQUAL(-50, l.at(0).rssi);
}

void test_rows_are_ordered_strongest_first() {
  ScanList l;
  l.add("b", -70, true);
  l.add("a", -40, false);
  l.add("c", -90, true);
  TEST_ASSERT_EQUAL_STRING("a", l.at(0).ssid);
  TEST_ASSERT_EQUAL_STRING("b", l.at(1).ssid);
  TEST_ASSERT_EQUAL_STRING("c", l.at(2).ssid);
}

void test_list_is_bounded_and_keeps_the_strongest() {
  ScanList l;
  char name[8];
  for (int i = 0; i < 40; i++) {
    snprintf(name, sizeof(name), "n%d", i);
    l.add(name, -100 + i, true);  // n39 is the strongest
  }
  TEST_ASSERT_EQUAL((int)ScanList::kMax, (int)l.count());
  TEST_ASSERT_EQUAL_STRING("n39", l.at(0).ssid);
  TEST_ASSERT_EQUAL(-100 + 39 - (int)ScanList::kMax + 1, l.at(l.count() - 1).rssi);
}

void test_over_long_ssid_is_truncated_to_32() {
  ScanList l;
  char longName[64];
  memset(longName, 'x', sizeof(longName) - 1);
  longName[sizeof(longName) - 1] = 0;
  TEST_ASSERT_TRUE(l.add(longName, -60, true));
  TEST_ASSERT_EQUAL(32, (int)strlen(l.at(0).ssid));
}

void test_row_cells_match_the_esp32_path() {
  ScanList l;
  l.add("open", -61, false);
  l.add("wpa", -62, true);
  char rssi[8];
  fry::improv::formatRssi(l.at(0).rssi, rssi, sizeof(rssi));
  TEST_ASSERT_EQUAL_STRING("-61", rssi);
  TEST_ASSERT_EQUAL_STRING("NO", fry::improv::authCell(l.at(0).secure));
  TEST_ASSERT_EQUAL_STRING("YES", fry::improv::authCell(l.at(1).secure));
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_empty_and_hidden_ssids_are_dropped);
  RUN_TEST(test_duplicate_ssid_keeps_the_strongest);
  RUN_TEST(test_rows_are_ordered_strongest_first);
  RUN_TEST(test_list_is_bounded_and_keeps_the_strongest);
  RUN_TEST(test_over_long_ssid_is_truncated_to_32);
  RUN_TEST(test_row_cells_match_the_esp32_path);
  return UNITY_END();
}
