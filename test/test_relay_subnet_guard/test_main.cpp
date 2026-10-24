// lib/fry_core/relay_guard.h: who the ESP32 SOCKS5 relay listens for and who it admits.
//
// The relay binds to the device's own tunnel address and admits exactly two kinds of source:
//   (a) an address inside the device's own tunnel subnet, when the provisioned prefix leaves room
//       for a peer beside the device (/8../31), and
//   (b) the WireGuard server's own tunnel address, a /32 taken from the provisioned allowed-ips.
// (b) is not a nicety: WG1/hardwareapi provision every fleet device with a bare /32 (the hardware
// run measured wgAddr 10.77.0.2/32 with the server at 10.77.0.1/32), so the device's subnet holds
// no peer at all and the server is the only legitimate client. A guard that admitted only (a)
// turned the relay off on every device - the regression these tests exist to prevent.
//
// Everything else fails closed: another tunnel peer, a foreign 10.x address, a LAN host.
#include <unity.h>

#include <cstdint>

#include "relay_guard.h"

using fry_relay::bumpSaturating;
using fry_relay::GuardConfig;
using fry_relay::ipInSubnet;
using fry_relay::peerAdmitted;
using fry_relay::pickServerTunnelAddress;
using fry_relay::prefixAdmitsPeers;
using fry_relay::relayEnabled;

namespace {

const uint32_t kDev = 0x0A0D0D02u;  // 10.13.13.2, the lab shape
const uint32_t kDev32 = 0x0A4D0002u;    // 10.77.0.2, the fleet shape (bare /32)
const uint32_t kSrv32 = 0x0A4D0001u;    // 10.77.0.1, the WG server's own tunnel address

uint32_t ip(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
  return (a << 24) | (b << 16) | (c << 8) | d;
}

GuardConfig lab() {  // a device provisioned with a subnet, no server address known
  GuardConfig g;
  g.deviceIp = kDev;
  g.prefix = 24;
  return g;
}

GuardConfig fleet() {  // what the hardware run measured
  GuardConfig g;
  g.deviceIp = kDev32;
  g.prefix = 32;
  g.serverIp = kSrv32;
  return g;
}

// ---- the subnet half (/8../31) -----------------------------------------------------------------

void test_a_slash_24_admits_its_whole_subnet_and_the_device_itself() {
  const GuardConfig g = lab();
  TEST_ASSERT_TRUE(peerAdmitted(kDev, g));
  TEST_ASSERT_TRUE(peerAdmitted(ip(10, 13, 13, 1), g));
  TEST_ASSERT_TRUE(peerAdmitted(ip(10, 13, 13, 255), g));
  TEST_ASSERT_TRUE(peerAdmitted(ip(10, 13, 13, 0), g));
}

void test_a_slash_24_refuses_the_addresses_just_outside_it_and_the_lan() {
  const GuardConfig g = lab();
  TEST_ASSERT_FALSE(peerAdmitted(ip(10, 13, 12, 255), g));
  TEST_ASSERT_FALSE(peerAdmitted(ip(10, 13, 14, 0), g));
  TEST_ASSERT_FALSE(peerAdmitted(ip(192, 168, 1, 10), g));  // the device's own uplink LAN
  TEST_ASSERT_FALSE(peerAdmitted(ip(0, 0, 0, 0), g));
  TEST_ASSERT_FALSE(peerAdmitted(ip(10, 77, 0, 1), g));     // a foreign tunnel address
}

void test_a_prefix_off_an_octet_boundary_uses_the_real_mask() {
  GuardConfig g = lab();
  g.prefix = 28;  // 10.13.13.0/28
  TEST_ASSERT_TRUE(peerAdmitted(ip(10, 13, 13, 15), g));
  TEST_ASSERT_FALSE(peerAdmitted(ip(10, 13, 13, 16), g));
  g.prefix = 23;  // spans two third-octets
  TEST_ASSERT_TRUE(peerAdmitted(ip(10, 13, 12, 7), g));
  TEST_ASSERT_FALSE(peerAdmitted(ip(10, 13, 14, 0), g));
}

void test_only_a_prefix_that_leaves_room_for_a_peer_admits_a_subnet() {
  TEST_ASSERT_EQUAL_INT(8, fry_relay::kMinTunnelPrefix);
  TEST_ASSERT_EQUAL_INT(31, fry_relay::kMaxSubnetPrefix);
  TEST_ASSERT_FALSE(prefixAdmitsPeers(0));
  TEST_ASSERT_FALSE(prefixAdmitsPeers(7));   // wider than /8: the guard would pass everything
  TEST_ASSERT_TRUE(prefixAdmitsPeers(8));
  TEST_ASSERT_TRUE(prefixAdmitsPeers(24));
  TEST_ASSERT_TRUE(prefixAdmitsPeers(31));   // the device plus exactly one peer
  TEST_ASSERT_FALSE(prefixAdmitsPeers(32));  // the device alone
  // ...which is exactly what ipInSubnet() would do with a /32, so the two agree.
  TEST_ASSERT_FALSE(ipInSubnet(ip(10, 13, 13, 1), kDev, 32));
}

// ---- the server half (the fleet shape) ---------------------------------------------------------

void test_a_slash_32_device_serves_the_server_and_nobody_else() {
  const GuardConfig g = fleet();
  TEST_ASSERT_TRUE_MESSAGE(relayEnabled(g), "a /32 device with a known server address must listen");
  TEST_ASSERT_FALSE(prefixAdmitsPeers(g.prefix));  // nothing else could ever be admitted
  TEST_ASSERT_TRUE(peerAdmitted(kSrv32, g));       // the server: the legitimate relay client
  TEST_ASSERT_FALSE(peerAdmitted(ip(10, 77, 0, 3), g));   // another tunnel peer
  TEST_ASSERT_FALSE(peerAdmitted(ip(10, 77, 0, 0), g));   // the subnet's network address
  TEST_ASSERT_FALSE(peerAdmitted(ip(192, 168, 1, 10), g)); // the LAN
  TEST_ASSERT_FALSE(peerAdmitted(ip(10, 13, 13, 1), g));  // the lab subnet
  TEST_ASSERT_FALSE(peerAdmitted(0, g));
}

void test_a_slash_32_device_with_no_server_address_does_not_listen() {
  GuardConfig g = fleet();
  g.serverIp = 0;
  TEST_ASSERT_FALSE_MESSAGE(relayEnabled(g), "no subnet and no server: there is nobody to serve");
  TEST_ASSERT_FALSE(peerAdmitted(kSrv32, g));
  TEST_ASSERT_FALSE(peerAdmitted(ip(192, 168, 1, 10), g));
}

void test_a_subnet_device_admits_both_the_subnet_and_the_server() {
  GuardConfig g = lab();
  g.serverIp = kSrv32;
  TEST_ASSERT_TRUE(relayEnabled(g));
  TEST_ASSERT_TRUE(peerAdmitted(ip(10, 13, 13, 9), g));  // subnet
  TEST_ASSERT_TRUE(peerAdmitted(kSrv32, g));             // server
  TEST_ASSERT_FALSE(peerAdmitted(ip(10, 77, 0, 9), g));  // neither
}

void test_an_unprovisioned_device_listens_for_nobody() {
  GuardConfig g;  // deviceIp 0, prefix 32, no server
  TEST_ASSERT_FALSE(relayEnabled(g));
  TEST_ASSERT_FALSE(peerAdmitted(0, g));
  TEST_ASSERT_FALSE(peerAdmitted(ip(10, 13, 13, 1), g));
}

// ---- picking the server address out of the provisioned allowed-ips -----------------------------

void test_the_server_address_is_the_single_address_in_the_allowed_csv() {
  TEST_ASSERT_EQUAL_UINT32(kSrv32, pickServerTunnelAddress("10.77.0.1/32", kDev32));
  TEST_ASSERT_EQUAL_UINT32(kSrv32, pickServerTunnelAddress("10.77.0.0/24;10.77.0.1/32", kDev32));
  TEST_ASSERT_EQUAL_UINT32(kSrv32, pickServerTunnelAddress("junk;10.77.0.1/32;", kDev32));
}

void test_a_subnet_entry_is_a_route_not_a_peer() {
  TEST_ASSERT_EQUAL_UINT32(0, pickServerTunnelAddress("10.77.0.0/24", kDev32));
  TEST_ASSERT_EQUAL_UINT32(0, pickServerTunnelAddress("10.0.0.0/8;192.168.0.0/16", kDev32));
  TEST_ASSERT_EQUAL_UINT32(0, pickServerTunnelAddress("", kDev32));
  TEST_ASSERT_EQUAL_UINT32(0, pickServerTunnelAddress(nullptr, kDev32));
}

void test_the_devices_own_slash_32_is_never_mistaken_for_the_server() {
  // planWgRoutes() falls back to the device's own address when nothing else survives, so this is a
  // real CSV value - and treating it as "the server" would admit the device itself and nothing else.
  TEST_ASSERT_EQUAL_UINT32(0, pickServerTunnelAddress("10.77.0.2/32", kDev32));
  TEST_ASSERT_EQUAL_UINT32(0, pickServerTunnelAddress("10.77.0.2/32;10.77.0.2/32", kDev32));
  TEST_ASSERT_EQUAL_UINT32(kSrv32, pickServerTunnelAddress("10.77.0.2/32;10.77.0.1/32", kDev32));
}

void test_the_first_single_address_wins_and_an_overlong_entry_is_skipped() {
  TEST_ASSERT_EQUAL_UINT32(ip(10, 77, 0, 9), pickServerTunnelAddress("10.77.0.9/32;10.77.0.1/32", kDev32));
  TEST_ASSERT_EQUAL_UINT32(kSrv32,
                           pickServerTunnelAddress("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;10.77.0.1/32", kDev32));
}

// ---- the counter ----------------------------------------------------------------------------

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
  RUN_TEST(test_a_slash_24_refuses_the_addresses_just_outside_it_and_the_lan);
  RUN_TEST(test_a_prefix_off_an_octet_boundary_uses_the_real_mask);
  RUN_TEST(test_only_a_prefix_that_leaves_room_for_a_peer_admits_a_subnet);
  RUN_TEST(test_a_slash_32_device_serves_the_server_and_nobody_else);
  RUN_TEST(test_a_slash_32_device_with_no_server_address_does_not_listen);
  RUN_TEST(test_a_subnet_device_admits_both_the_subnet_and_the_server);
  RUN_TEST(test_an_unprovisioned_device_listens_for_nobody);
  RUN_TEST(test_the_server_address_is_the_single_address_in_the_allowed_csv);
  RUN_TEST(test_a_subnet_entry_is_a_route_not_a_peer);
  RUN_TEST(test_the_devices_own_slash_32_is_never_mistaken_for_the_server);
  RUN_TEST(test_the_first_single_address_wins_and_an_overlong_entry_is_skipped);
  RUN_TEST(test_the_counter_saturates_instead_of_wrapping);
  return UNITY_END();
}
