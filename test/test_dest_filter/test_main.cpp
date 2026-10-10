// Relay destination filter (lib/fry_core/dest_filter.h): full range table.
#include <unity.h>

#include <cstring>

#include "dest_filter.h"

using fry::DestCtx;

namespace {
constexpr uint32_t ip4(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
  return (a << 24) | (b << 16) | (c << 8) | d;
}
DestCtx noCtx() { return DestCtx{}; }
// A board on 203.0.113.0/24 (TEST-NET-3 as a stand-in public LAN), gateway .1
DestCtx pubLan() { return DestCtx{ip4(203, 0, 113, 77), ip4(255, 255, 255, 0), ip4(203, 0, 113, 1)}; }
}  // namespace

void setUp() { fry::destCountersReset(); }
void tearDown() {}

void test_v4_blocked_ranges_edges() {
  struct Row { uint32_t ip; bool blocked; const char* why; } rows[] = {
      {ip4(0, 0, 0, 0), true, "0/8 lo"},          {ip4(0, 255, 255, 255), true, "0/8 hi"},
      {ip4(1, 0, 0, 0), false, "1.0.0.0"},
      {ip4(127, 0, 0, 1), true, "127/8"},         {ip4(127, 255, 255, 255), true, "127/8 hi"},
      {ip4(126, 255, 255, 255), false, "126.x"},  {ip4(128, 0, 0, 0), false, "128.0.0.0"},
      {ip4(10, 0, 0, 0), true, "10/8 lo"},        {ip4(10, 255, 255, 255), true, "10/8 hi"},
      {ip4(9, 255, 255, 255), false, "9.x"},      {ip4(11, 0, 0, 0), false, "11.x"},
      {ip4(172, 15, 255, 255), false, "172.15"},  {ip4(172, 16, 0, 0), true, "172.16/12 lo"},
      {ip4(172, 31, 255, 255), true, "172.16/12 hi"}, {ip4(172, 32, 0, 0), false, "172.32"},
      {ip4(192, 167, 255, 255), false, "192.167"}, {ip4(192, 168, 0, 0), true, "192.168/16 lo"},
      {ip4(192, 168, 255, 255), true, "192.168/16 hi"}, {ip4(192, 169, 0, 0), false, "192.169"},
      {ip4(169, 253, 255, 255), false, "169.253"}, {ip4(169, 254, 0, 0), true, "169.254/16 lo"},
      {ip4(169, 254, 255, 255), true, "169.254/16 hi"}, {ip4(169, 255, 0, 0), false, "169.255"},
      {ip4(100, 63, 255, 255), false, "100.63"},  {ip4(100, 64, 0, 0), true, "100.64/10 lo"},
      {ip4(100, 127, 255, 255), true, "100.64/10 hi"}, {ip4(100, 128, 0, 0), false, "100.128"},
      {ip4(223, 255, 255, 255), false, "223.x"},  {ip4(224, 0, 0, 0), true, "224/4 lo"},
      {ip4(239, 255, 255, 255), true, "224/4 hi"}, {ip4(240, 0, 0, 0), true, "240/4 lo"},
      {ip4(255, 255, 254, 255), true, "240/4 hi region"}, {ip4(255, 255, 255, 255), true, "bcast"},
      {ip4(8, 8, 8, 8), false, "public"},         {ip4(93, 184, 216, 34), false, "public 2"},
  };
  for (const Row& r : rows) {
    TEST_ASSERT_EQUAL_MESSAGE(r.blocked, fry::destIsBlockedV4(r.ip, noCtx()), r.why);
  }
}

void test_v4_own_gateway_and_subnet_blocked_even_when_public_space() {
  DestCtx c = pubLan();
  TEST_ASSERT_TRUE(fry::destIsBlockedV4(ip4(203, 0, 113, 1), c));    // gateway
  TEST_ASSERT_TRUE(fry::destIsBlockedV4(ip4(203, 0, 113, 200), c));  // same subnet
  TEST_ASSERT_TRUE(fry::destIsBlockedV4(ip4(203, 0, 113, 77), c));   // self
  TEST_ASSERT_FALSE(fry::destIsBlockedV4(ip4(203, 0, 114, 1), c));   // next subnet
  TEST_ASSERT_FALSE(fry::destIsBlockedV4(ip4(203, 0, 113, 1), noCtx()));  // unknown ctx: no extra block
}

void test_gateway_outside_subnet_is_blocked() {
  DestCtx c{ip4(198, 51, 100, 9), ip4(255, 255, 255, 252), ip4(198, 51, 100, 10)};
  TEST_ASSERT_TRUE(fry::destIsBlockedV4(ip4(198, 51, 100, 10), c));
  TEST_ASSERT_FALSE(fry::destIsBlockedV4(ip4(198, 51, 100, 40), c));
  DestCtx odd{ip4(198, 51, 100, 9), ip4(255, 255, 255, 252), ip4(192, 0, 2, 1)};  // gw off-subnet
  TEST_ASSERT_TRUE(fry::destIsBlockedV4(ip4(192, 0, 2, 1), odd));
}

static void v6(uint8_t out[16], const uint8_t* head, size_t n) {
  memset(out, 0, 16);
  memcpy(out, head, n);
}

void test_v6_table() {
  uint8_t a[16];
  // ::1 loopback and :: unspecified
  memset(a, 0, 16);
  TEST_ASSERT_TRUE(fry::destIsBlockedV6(a));
  a[15] = 1;
  TEST_ASSERT_TRUE(fry::destIsBlockedV6(a));
  a[15] = 2;
  TEST_ASSERT_FALSE(fry::destIsBlockedV6(a));  // ::2 is not special here
  // fc00::/7 covers fc and fd
  { const uint8_t h[] = {0xfc, 0x00}; v6(a, h, 2); TEST_ASSERT_TRUE(fry::destIsBlockedV6(a)); }
  { const uint8_t h[] = {0xfd, 0xff}; v6(a, h, 2); TEST_ASSERT_TRUE(fry::destIsBlockedV6(a)); }
  { const uint8_t h[] = {0xfb, 0xff}; v6(a, h, 2); TEST_ASSERT_FALSE(fry::destIsBlockedV6(a)); }
  { const uint8_t h[] = {0xfe, 0x00}; v6(a, h, 2); TEST_ASSERT_FALSE(fry::destIsBlockedV6(a)); }  // fe00 not fe80
  // fe80::/10 covers fe80..febf
  { const uint8_t h[] = {0xfe, 0x80}; v6(a, h, 2); TEST_ASSERT_TRUE(fry::destIsBlockedV6(a)); }
  { const uint8_t h[] = {0xfe, 0xbf}; v6(a, h, 2); TEST_ASSERT_TRUE(fry::destIsBlockedV6(a)); }
  { const uint8_t h[] = {0xfe, 0xc0}; v6(a, h, 2); TEST_ASSERT_FALSE(fry::destIsBlockedV6(a)); }
  // ff00::/8 multicast
  { const uint8_t h[] = {0xff, 0x02}; v6(a, h, 2); TEST_ASSERT_TRUE(fry::destIsBlockedV6(a)); }
  // public global unicast 2606:4700::
  { const uint8_t h[] = {0x26, 0x06, 0x47, 0x00}; v6(a, h, 4); TEST_ASSERT_FALSE(fry::destIsBlockedV6(a)); }
}

void test_v4_mapped_v6_follows_the_v4_rules() {
  uint8_t a[16] = {0};
  a[10] = 0xff; a[11] = 0xff;
  a[12] = 127; a[15] = 1;  // ::ffff:127.0.0.1
  TEST_ASSERT_TRUE(fry::destIsBlockedV6(a));
  a[12] = 10; a[13] = 0; a[14] = 0; a[15] = 5;
  TEST_ASSERT_TRUE(fry::destIsBlockedV6(a));
  a[12] = 8; a[13] = 8; a[14] = 8; a[15] = 8;
  TEST_ASSERT_FALSE(fry::destIsBlockedV6(a));
}

void test_counters_count_allowed_and_blocked() {
  TEST_ASSERT_EQUAL_UINT32(0, fry::destCounters().allowed);
  TEST_ASSERT_TRUE(fry::destFilterV4(ip4(8, 8, 8, 8), noCtx()));
  TEST_ASSERT_FALSE(fry::destFilterV4(ip4(10, 1, 2, 3), noCtx()));
  TEST_ASSERT_FALSE(fry::destFilterV4(ip4(192, 168, 1, 1), noCtx()));
  uint8_t lo[16] = {0}; lo[15] = 1;
  TEST_ASSERT_FALSE(fry::destFilterV6(lo));
  uint8_t pub[16] = {0x26, 0x06, 0x47};
  TEST_ASSERT_TRUE(fry::destFilterV6(pub));
  TEST_ASSERT_EQUAL_UINT32(2, fry::destCounters().allowed);
  TEST_ASSERT_EQUAL_UINT32(3, fry::destCounters().blocked);
  fry::destCountersReset();
  TEST_ASSERT_EQUAL_UINT32(0, fry::destCounters().blocked);
}

void test_dotted_text_and_text_v6_helpers() {
  bool ok = false;
  TEST_ASSERT_TRUE(fry::destFilterText("10.0.0.1", noCtx(), &ok) == false && ok);
  TEST_ASSERT_TRUE(fry::destFilterText("8.8.8.8", noCtx(), &ok) == true && ok);
  TEST_ASSERT_TRUE(fry::destFilterText("::1", noCtx(), &ok) == false && ok);
  TEST_ASSERT_TRUE(fry::destFilterText("fe80::1", noCtx(), &ok) == false && ok);
  TEST_ASSERT_TRUE(fry::destFilterText("2606:4700::1111", noCtx(), &ok) == true && ok);
  fry::destFilterText("example.com", noCtx(), &ok);  // not a literal: caller must resolve first
  TEST_ASSERT_FALSE(ok);
}

// Review HIGH: lwIP reads "012.0.0.1" as octal 10.0.0.1, "0x0a.0.0.1" as hex, "10.1" as 10.0.0.1,
// "0177.0.0.1" as 127.0.0.1 and "2130706433" as 127.0.0.1. All must be literal and blocked.
void test_noncanonical_literals_are_blocked() {
  const char* vec[] = {"012.0.0.1", "0x0a.0.0.1", "10.1", "172.032.0.1", "0177.0.0.1", "2130706433",
                       "010.1.1.1", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.", "0x7f.1", "::1%eth0", "1::2::3"};
  for (const char* h : vec) {
    bool lit = false;
    bool allowed = fry::destFilterText(h, noCtx(), &lit);
    TEST_ASSERT_TRUE_MESSAGE(lit, h);
    TEST_ASSERT_FALSE_MESSAGE(allowed, h);
    uint32_t ip;
    TEST_ASSERT_FALSE_MESSAGE(fry::destParseV4(h, &ip), h);
  }
  bool lit = true;
  fry::destFilterText("1password.com", noCtx(), &lit);
  TEST_ASSERT_FALSE(lit);  // a real name that merely starts with a digit stays a name
  fry::destFilterText("123.example.org", noCtx(), &lit);
  TEST_ASSERT_FALSE(lit);
  uint32_t ip = 0;
  TEST_ASSERT_TRUE(fry::destParseV4("8.8.4.4", &ip));
  TEST_ASSERT_EQUAL_UINT32(ip4(8, 8, 4, 4), ip);
  TEST_ASSERT_TRUE(fry::destParseV4("0.0.0.0", &ip));
}

// Review LOW: embedded IPv4 is checked with the real ctx; NAT64 and 6to4 follow the v4 rules.
void test_embedded_v4_uses_ctx_nat64_6to4() {
  DestCtx c = pubLan();
  uint8_t a[16] = {0};
  a[10] = 0xff; a[11] = 0xff; a[12] = 203; a[13] = 0; a[14] = 113; a[15] = 1;  // ::ffff:gateway
  TEST_ASSERT_TRUE(fry::destIsBlockedV6(a, c));
  TEST_ASSERT_FALSE(fry::destIsBlockedV6(a));  // without ctx a public v4 stays allowed
  uint8_t n[16] = {0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1};  // 64:ff9b::10.0.0.1
  TEST_ASSERT_TRUE(fry::destIsBlockedV6(n));
  n[12] = 8; n[13] = 8; n[14] = 8; n[15] = 8;
  TEST_ASSERT_FALSE(fry::destIsBlockedV6(n));
  uint8_t t[16] = {0x20, 0x02, 192, 168, 1, 1};  // 2002:c0a8:0101:: 6to4 of 192.168.1.1
  TEST_ASSERT_TRUE(fry::destIsBlockedV6(t));
  uint8_t t2[16] = {0x20, 0x02, 8, 8, 8, 8};
  TEST_ASSERT_FALSE(fry::destIsBlockedV6(t2));
  TEST_ASSERT_TRUE(fry::destIsBlockedV6(t2, DestCtx{ip4(8, 8, 8, 1), ip4(255, 255, 255, 0), 0}));
  bool lit = false;
  TEST_ASSERT_FALSE(fry::destFilterText("::ffff:10.0.0.1", noCtx(), &lit));
  TEST_ASSERT_TRUE(lit);
}

int main() {
  UNITY_BEGIN();
  RUN_TEST(test_noncanonical_literals_are_blocked);
  RUN_TEST(test_embedded_v4_uses_ctx_nat64_6to4);
  RUN_TEST(test_v4_blocked_ranges_edges);
  RUN_TEST(test_v4_own_gateway_and_subnet_blocked_even_when_public_space);
  RUN_TEST(test_gateway_outside_subnet_is_blocked);
  RUN_TEST(test_v6_table);
  RUN_TEST(test_v4_mapped_v6_follows_the_v4_rules);
  RUN_TEST(test_counters_count_allowed_and_blocked);
  RUN_TEST(test_dotted_text_and_text_v6_helpers);
  return UNITY_END();
}
