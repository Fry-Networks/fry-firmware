// lib/fry_core/relay_guard.h: the source guard in front of the ESP32 SOCKS5 relay.
//
// The relay used to listen on INADDR_ANY and accept any peer. It now binds to the device's tunnel
// address and drops an accepted peer whose source is outside that address's subnet (src/esp32/
// vpn_wireguard.cpp acceptClients). The predicate is pure, so it is pinned here: the "inside" edge
// of the subnet, the "outside" edge one address past it, the /32 case (only the device itself),
// prefixes that do not fall on an octet boundary, and the drop counter's saturation.
#include <unity.h>

#include <cstdint>

#include "relay_guard.h"

using fry_relay::bumpSaturating;
using fry_relay::ipInSubnet;

namespace {

// 10.13.13.2 in the host-order convention fry::parseIpv4Cidr uses (bit 31 = first octet).
const uint32_t kDev = 0x0A0D0D02u;

uint32_t ip(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
  return (a << 24) | (b << 16) | (c << 8) | d;
}

void test_a_slash_24_admits_its_whole_subnet_and_the_device_itself() {
  TEST_ASSERT_TRUE(ipInSubnet(kDev, kDev, 24));
  TEST_ASSERT_TRUE(ipInSubnet(ip(10, 13, 13, 1), kDev, 24));
  TEST_ASSERT_TRUE(ipInSubnet(ip(10, 13, 13, 255), kDev, 24));
  TEST_ASSERT_TRUE(ipInSubnet(ip(10, 13, 13, 0), kDev, 24));
}

void test_a_slash_24_refuses_the_addresses_just_outside_it() {
  TEST_ASSERT_FALSE(ipInSubnet(ip(10, 13, 12, 255), kDev, 24));
  TEST_ASSERT_FALSE(ipInSubnet(ip(10, 13, 14, 0), kDev, 24));
  TEST_ASSERT_FALSE(ipInSubnet(ip(10, 13, 13, 2), ip(192, 168, 1, 2), 24));
  TEST_ASSERT_FALSE(ipInSubnet(ip(0, 0, 0, 0), kDev, 24));
}

void test_a_slash_32_admits_only_the_device_address() {
  TEST_ASSERT_TRUE(ipInSubnet(kDev, kDev, 32));
  TEST_ASSERT_FALSE(ipInSubnet(ip(10, 13, 13, 3), kDev, 32));
  TEST_ASSERT_FALSE(ipInSubnet(ip(10, 13, 13, 1), kDev, 32));
}

void test_a_prefix_off_an_octet_boundary_uses_the_real_mask() {
  // /28 on 10.13.13.2 -> 10.13.13.0/28, so .1 .. .15 are inside and .16 and .0x20 are not.
  TEST_ASSERT_TRUE(ipInSubnet(ip(10, 13, 13, 15), kDev, 28));
  TEST_ASSERT_FALSE(ipInSubnet(ip(10, 13, 13, 16), kDev, 28));
  TEST_ASSERT_FALSE(ipInSubnet(ip(10, 13, 13, 32), kDev, 28));
  // /23 spans two third-octets in both directions.
  TEST_ASSERT_TRUE(ipInSubnet(ip(10, 13, 12, 7), kDev, 23));
  TEST_ASSERT_FALSE(ipInSubnet(ip(10, 13, 14, 0), kDev, 23));
}

void test_a_slash_8_is_the_floor_and_matches_only_its_first_octet() {
  TEST_ASSERT_EQUAL_INT(8, fry_relay::kMinTunnelPrefix);
  TEST_ASSERT_TRUE(ipInSubnet(ip(10, 0, 0, 1), kDev, 8));
  TEST_ASSERT_TRUE(ipInSubnet(ip(10, 255, 255, 255), kDev, 8));
  TEST_ASSERT_FALSE(ipInSubnet(ip(11, 13, 13, 2), kDev, 8));
}

void test_the_device_address_need_not_be_the_network_address() {
  // .2/24 is inside 10.13.13.0/24 even though it is not the network address itself.
  TEST_ASSERT_TRUE(ipInSubnet(kDev, ip(10, 13, 13, 200), 24));
  TEST_ASSERT_FALSE(ipInSubnet(ip(10, 13, 13, 200), ip(10, 13, 14, 2), 24));
}

void test_the_counter_saturates_instead_of_wrapping() {
  uint32_t c = 0;
  bumpSaturating(c);
  TEST_ASSERT_EQUAL_UINT32(1, c);
  c = 41;
  bumpSaturating(c);
  TEST_ASSERT_EQUAL_UINT32(42, c);
  c = 0xFFFFFFFEu;
  bumpSaturating(c);
  bumpSaturating(c);
  bumpSaturating(c);
  TEST_ASSERT_EQUAL_UINT32(0xFFFFFFFFu, c);
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_a_slash_24_admits_its_whole_subnet_and_the_device_itself);
  RUN_TEST(test_a_slash_24_refuses_the_addresses_just_outside_it);
  RUN_TEST(test_a_slash_32_admits_only_the_device_address);
  RUN_TEST(test_a_prefix_off_an_octet_boundary_uses_the_real_mask);
  RUN_TEST(test_a_slash_8_is_the_floor_and_matches_only_its_first_octet);
  RUN_TEST(test_the_device_address_need_not_be_the_network_address);
  RUN_TEST(test_the_counter_saturates_instead_of_wrapping);
  return UNITY_END();
}
