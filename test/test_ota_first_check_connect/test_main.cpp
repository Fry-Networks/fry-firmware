// The first manifest check is also counted from the Wi-Fi connect, not from the boot clock alone (ESP8266): it does not start before the
// TLS gate window (kBootAsyncEventDoneMs) plus a slot for the boot registration has passed after the connect anchor. With a late connect
// the boot-clock rule (20 s uptime, 10 s after the first tick) let the check start right behind the registration and meet its connection
// while it was still closing. See lib/fry_core/ota_first_check.h. The wiring test is a source pin (tick() needs the Arduino core).
#include <unity.h>

#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "ota_first_check.h"
#include "tls_boot_gate.h"

namespace {

// Measured on a normal connect: gate open 15866 ms, registered 16698 ms, first check 20000 ms; the anchor is the gate opening minus 9000.
const uint32_t kNormalAnchor = 15866 - 9000;

// The rule as it was before this change: keyed off the boot clock and the first tick only (control for the replays).
bool bootKeyedOpen(uint32_t now, uint32_t firstTick) { return fry::otaFirstCheckWaitMs(now, firstTick) == 0; }

// Both rules together, as tick() evaluates them.
bool open(uint32_t now, uint32_t firstTick, uint32_t anchor, bool have) {
  return fry::otaFirstCheckWaitMs(now, firstTick) == 0 && fry::otaFirstCheckAfterConnectWaitMs(now, anchor, have) == 0;
}

// The first loop pass at or after `from` (100 ms steps) where the check may start.
uint32_t firstOpen(uint32_t from, uint32_t firstTick, uint32_t anchor, bool have, bool bootKeyedOnly) {
  for (uint32_t t = from; t < from + 200000; t += 100) {
    if (bootKeyedOnly ? bootKeyedOpen(t, firstTick) : open(t, firstTick, anchor, have)) return t;
  }
  return 0;
}

void test_the_constants() {
  TEST_ASSERT_EQUAL_UINT32(4100, fry::kOtaFirstCheckRegSlotMs);
  TEST_ASSERT_EQUAL_UINT32(9000, fry::kBootAsyncEventDoneMs);
  // the slot is the measured gate-open-to-first-check time (4134 ms) rounded down, and covers the 832 ms registration several times over
  TEST_ASSERT_TRUE(fry::kOtaFirstCheckRegSlotMs <= 20000 - 15866);
  TEST_ASSERT_TRUE(fry::kOtaFirstCheckRegSlotMs >= 4 * 832);
}

void test_no_connect_seen_waits_the_whole_window() {
  const uint32_t window = fry::kBootAsyncEventDoneMs + fry::kOtaFirstCheckRegSlotMs;
  TEST_ASSERT_EQUAL_UINT32(window, fry::otaFirstCheckAfterConnectWaitMs(0, 0, false));
  TEST_ASSERT_EQUAL_UINT32(window, fry::otaFirstCheckAfterConnectWaitMs(123456, 0, false));
  TEST_ASSERT_EQUAL_UINT32(window, fry::otaFirstCheckAfterConnectWaitMs(0xFFFFFFF0u, 5, false));
}

void test_the_wait_counts_down_from_the_anchor() {
  const uint32_t window = 13100;
  TEST_ASSERT_EQUAL_UINT32(window, fry::otaFirstCheckAfterConnectWaitMs(1000, 1000, true));
  TEST_ASSERT_EQUAL_UINT32(1, fry::otaFirstCheckAfterConnectWaitMs(1000 + window - 1, 1000, true));
  TEST_ASSERT_EQUAL_UINT32(0, fry::otaFirstCheckAfterConnectWaitMs(1000 + window, 1000, true));
  TEST_ASSERT_EQUAL_UINT32(0, fry::otaFirstCheckAfterConnectWaitMs(1000 + window + 50000, 1000, true));
}

void test_a_normal_connect_is_unchanged_the_20_s_floor_still_decides() {
  // anchor 6866 -> 19966 < 20000: the new rule is already open when the old one opens
  const uint32_t firstTick = kNormalAnchor + 100;
  TEST_ASSERT_EQUAL_UINT32(0, fry::otaFirstCheckAfterConnectWaitMs(20000, kNormalAnchor, true));
  TEST_ASSERT_EQUAL_UINT32(19966 - 19900, fry::otaFirstCheckAfterConnectWaitMs(19900, kNormalAnchor, true));
  TEST_ASSERT_EQUAL_UINT32(20000, firstOpen(15000, firstTick, kNormalAnchor, true, false));
  TEST_ASSERT_EQUAL_UINT32(20000, firstOpen(15000, firstTick, kNormalAnchor, true, true));
}

void test_a_late_connect_moves_the_first_check_out_with_the_anchor() {
  // forced 6 s late connect: anchor 12902, TLS gate opens 21902, registration runs there
  const uint32_t anchor = kNormalAnchor + 6036;
  const uint32_t firstTick = anchor + 100;
  const uint32_t gateOpen = anchor + fry::kBootAsyncEventDoneMs;
  // control: the boot-keyed rule opens at 23000 (first tick + 10 s) and so right behind the registration that starts at gateOpen
  const uint32_t oldOpen = firstOpen(15000, firstTick, anchor, true, true);
  TEST_ASSERT_TRUE(oldOpen < gateOpen + fry::kOtaFirstCheckRegSlotMs);
  // new: not before anchor + 9000 + 4100, the same 4.1 s after the gate opened as on a normal boot
  const uint32_t nowOpen = firstOpen(15000, firstTick, anchor, true, false);
  TEST_ASSERT_TRUE(nowOpen >= anchor + 13100);
  TEST_ASSERT_TRUE(nowOpen < anchor + 13100 + 100);
  TEST_ASSERT_TRUE(nowOpen - gateOpen >= fry::kOtaFirstCheckRegSlotMs);
  // closed through the whole slot, open exactly at the end
  TEST_ASSERT_FALSE(open(anchor + 13099, firstTick, anchor, true));
  TEST_ASSERT_TRUE(open(anchor + 13100, firstTick, anchor, true));
  TEST_ASSERT_FALSE(open(gateOpen + 74, firstTick, anchor, true));  // the loop pass right behind the registration
}

void test_a_connect_far_into_the_boot_is_waited_for_in_full() {
  const uint32_t anchor = 120000;
  TEST_ASSERT_EQUAL_UINT32(13100, fry::otaFirstCheckAfterConnectWaitMs(anchor, anchor, true));
  TEST_ASSERT_FALSE(open(anchor + 13099, anchor + 100, anchor, true));
  TEST_ASSERT_TRUE(open(anchor + 13100, anchor + 100, anchor, true));
}

void test_an_anchor_ahead_of_now_adds_the_distance() {
  // association seen, the address not yet: anchor = assoc + lead, still ahead of now
  TEST_ASSERT_EQUAL_UINT32(2500 + 13100, fry::otaFirstCheckAfterConnectWaitMs(5000, 7500, true));
  TEST_ASSERT_EQUAL_UINT32(1 + 13100, fry::otaFirstCheckAfterConnectWaitMs(7499, 7500, true));
}

void test_a_reconnect_re_arms_the_wait() {
  const uint32_t a1 = 6866, a2 = 400000;
  TEST_ASSERT_EQUAL_UINT32(0, fry::otaFirstCheckAfterConnectWaitMs(a1 + 20000, a1, true));
  TEST_ASSERT_EQUAL_UINT32(13100, fry::otaFirstCheckAfterConnectWaitMs(a2, a2, true));
  TEST_ASSERT_EQUAL_UINT32(0, fry::otaFirstCheckAfterConnectWaitMs(a2 + 13100, a2, true));
}

void test_wrap_safe_around_the_counter_end() {
  const uint32_t anchor = 0xFFFFFFFFu - 3000;
  TEST_ASSERT_EQUAL_UINT32(13100, fry::otaFirstCheckAfterConnectWaitMs(anchor, anchor, true));
  TEST_ASSERT_EQUAL_UINT32(13100 - 4000, fry::otaFirstCheckAfterConnectWaitMs(anchor + 4000u, anchor, true));  // now has wrapped past 0
  TEST_ASSERT_EQUAL_UINT32(0, fry::otaFirstCheckAfterConnectWaitMs(anchor + 13100u, anchor, true));
  // anchor just ahead of now across the wrap
  TEST_ASSERT_EQUAL_UINT32(1000 + 13100, fry::otaFirstCheckAfterConnectWaitMs(0xFFFFFFFFu - 999u, 0u, true));
}

void test_it_never_closes_again_after_half_the_counter_range() {
  // the old tlsConnectWaitMs mistake: an anchor older than 2^31 ms flips "ahead" positive and re-closes the gate for ~25 days
  const uint32_t anchor = 6500;
  for (uint32_t extra = 0; extra < 3; extra++) {
    const uint32_t now = anchor + 0x80000000u + extra * 1000u;
    TEST_ASSERT_EQUAL_UINT32(0, fry::otaFirstCheckAfterConnectWaitMs(now, anchor, true));
  }
  TEST_ASSERT_EQUAL_UINT32(0, fry::otaFirstCheckAfterConnectWaitMs(anchor + 0x7FFFFFFFu, anchor, true));
  TEST_ASSERT_EQUAL_UINT32(0, fry::otaFirstCheckAfterConnectWaitMs(anchor + 0x80000001u, anchor, true));
  TEST_ASSERT_EQUAL_UINT32(0, fry::otaFirstCheckAfterConnectWaitMs(anchor + 0xC0000000u, anchor, true));
}

void test_the_old_rule_is_untouched() {
  TEST_ASSERT_EQUAL_UINT32(20000 - 5000, fry::otaFirstCheckWaitMs(5000, 100));
  TEST_ASSERT_EQUAL_UINT32(0, fry::otaFirstCheckWaitMs(30000, 20000));
  TEST_ASSERT_EQUAL_UINT32(1, fry::otaFirstCheckWaitMs(29999, 20000));
}

// ---- source pin -------------------------------------------------------------------------------------------------------------------
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
  const std::string tail = "test/test_ota_first_check_connect/test_main.cpp";
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

void test_tick_evaluates_the_connect_wait_before_the_closing_pcb_hold() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadOtaClient(src), "cannot read src/core/ota_client.cpp");
  const size_t tick = src.find("void tick() {");
  TEST_ASSERT_TRUE_MESSAGE(tick != std::string::npos, "cannot find tick()");
  const size_t guard = src.find("#if defined(ARDUINO_ARCH_ESP8266)", tick);
  const size_t endif = src.find("#endif", guard);
  const size_t done = src.find("s_firstCheckDone = true;", tick);
  TEST_ASSERT_TRUE_MESSAGE(guard != std::string::npos && endif != std::string::npos && done != std::string::npos, "first-check branch not found");
  const size_t anchor = src.find("fry_wifi::connectAnchorMs(", tick);
  const size_t wait = src.find("fry::otaFirstCheckAfterConnectWaitMs(", tick);
  const size_t hold = src.find("holdForTimeWait(now)", tick);
  TEST_ASSERT_TRUE_MESSAGE(anchor != std::string::npos && wait != std::string::npos && hold != std::string::npos, "calls not found in tick()");
  TEST_ASSERT_TRUE_MESSAGE(guard < anchor && anchor < wait && wait < endif, "the connect wait must sit inside the ESP8266 block of tick()");
  TEST_ASSERT_TRUE_MESSAGE(wait < hold, "the connect wait must be evaluated BEFORE holdForTimeWait(now)");
  TEST_ASSERT_TRUE_MESSAGE(hold < done, "holdForTimeWait(now) must still come before s_firstCheckDone = true");
  const size_t oldWait = src.find("fry::otaFirstCheckWaitMs(", tick);
  TEST_ASSERT_TRUE_MESSAGE(oldWait != std::string::npos && oldWait < wait, "the boot-clock wait must remain, ahead of the new one");
  TEST_ASSERT_TRUE_MESSAGE(src.find("fry::otaFirstCheckAfterConnectWaitMs(", wait + 10) == std::string::npos, "only the first check may use the connect wait");
  const std::string call = src.substr(wait, 100);
  TEST_ASSERT_TRUE_MESSAGE(call.find("connectAnchor, haveConnect") != std::string::npos, "the wait must be asked with the recorded anchor and its flag");
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_the_constants);
  RUN_TEST(test_no_connect_seen_waits_the_whole_window);
  RUN_TEST(test_the_wait_counts_down_from_the_anchor);
  RUN_TEST(test_a_normal_connect_is_unchanged_the_20_s_floor_still_decides);
  RUN_TEST(test_a_late_connect_moves_the_first_check_out_with_the_anchor);
  RUN_TEST(test_a_connect_far_into_the_boot_is_waited_for_in_full);
  RUN_TEST(test_an_anchor_ahead_of_now_adds_the_distance);
  RUN_TEST(test_a_reconnect_re_arms_the_wait);
  RUN_TEST(test_wrap_safe_around_the_counter_end);
  RUN_TEST(test_it_never_closes_again_after_half_the_counter_range);
  RUN_TEST(test_the_old_rule_is_untouched);
  RUN_TEST(test_tick_evaluates_the_connect_wait_before_the_closing_pcb_hold);
  return UNITY_END();
}
