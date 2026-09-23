// Bug this suite proves is fixed: droscy/esp_wireguard 0.4.5 defaults WIREGUARD_MAX_SRC_IPS to 1,
// filled by the device's own tunnel /32 — so every reply the server sends back to ITS tunnel IP
// gets ERR_RTE (handshake completes, no data ever crosses). The route-planning group below is
// where that bug lives and where its fix is pinned.
//
// RFC 7748 section 6.1's Alice/Bob X25519 vectors are used where a real, externally-published
// 32-byte value is more convincing than a value this suite invented — fetched verbatim from
// https://www.rfc-editor.org/rfc/rfc7748.txt during planning and cross-checked byte-length. The
// actual X25519 scalar multiplication (crypto_scalarmult_curve25519_base) is NOT exercised here:
// it lives in src/esp32/wg_provision_client.cpp via ESPHome's libsodium fork, which is an
// ESP32-specific vendored port (custom port/port_include dirs, curated srcFilter) that does not
// link into a native/host build — same reason lib/fry_core/sha256.cpp is a from-scratch
// implementation rather than pulling in a platform TLS crypto library. What IS native-testable,
// and what this suite pins, is (a) the clamp bitmask logic in isolation and (b) that our own
// base64 codec round-trips a real 32-byte value without corruption. The scalar multiplication
// itself is proven on real hardware at bench time (bench step 7's E2E: "wg: keypair generated"
// through a real WireGuard handshake) — a stronger proof than any host-side unit test could give.
#include <unity.h>

#include <cstring>

#include "wg_provision.h"

namespace {

// ── Key encoding (7) ─────────────────────────────────────────────────────────────────────────

void test_valid_wg_key_b64_accepted() {
  // A real device-generated-shaped key: 44 chars, standard alphabet, single '=' pad.
  TEST_ASSERT_TRUE(fry::isWgKeyB64("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Xw="));
}

void test_key_wrong_length_rejected() {
  TEST_ASSERT_FALSE(fry::isWgKeyB64("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8X="));   // 43
  TEST_ASSERT_FALSE(fry::isWgKeyB64("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Xw=="));  // 45
}

void test_key_bad_alphabet_rejected() {
  // '_' is valid in the URL-safe alphabet but not WireGuard's standard one.
  TEST_ASSERT_FALSE(fry::isWgKeyB64("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8X_="));
}

void test_key_missing_padding_rejected() {
  // Same 44 characters, but the last one isn't '=' — not a canonical 32-byte key string.
  TEST_ASSERT_FALSE(fry::isWgKeyB64("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Xwx"));
}

void test_key_tail_char_with_nonzero_low_bits_rejected() {
  // The 43rd character (index 42) closes a 2-byte tail group whose low 2 bits are always the
  // zero-padding bits (only 16 real bits exist in that final group). 'B' (value 1) has low bits
  // 01 != 0, so this is a well-formed-looking but non-canonical key string.
  TEST_ASSERT_FALSE(fry::isWgKeyB64("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8XB="));
}

void test_encode_known_bytes_round_trip_through_isWgKeyB64() {
  // Alice's public key from RFC 7748 section 6.1 — a real, externally-published 32-byte value,
  // not one this suite invented. Proves our own base64 codec produces a canonical WireGuard key
  // string (accepted by isWgKeyB64) from real bytes, without needing libsodium's scalarmult.
  const uint8_t alicePub[32] = {0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d,
                                0xdc, 0xb4, 0x3e, 0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38,
                                0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a};
  char out[45];
  size_t n = fry::encodeWgKeyB64(alicePub, out, sizeof(out));
  TEST_ASSERT_EQUAL_UINT32(45, n);
  TEST_ASSERT_EQUAL_UINT32(44, strlen(out));
  TEST_ASSERT_TRUE(fry::isWgKeyB64(out));
}

void test_clamp_sets_and_clears_expected_bits() {
  uint8_t allOnes[32];
  memset(allOnes, 0xFF, sizeof(allOnes));
  fry::clampX25519Private(allOnes);
  TEST_ASSERT_EQUAL_UINT8(0xF8, allOnes[0]);   // low 3 bits cleared
  TEST_ASSERT_EQUAL_UINT8(0x7F, allOnes[31]);  // high bit cleared, bit 6 (already set) kept

  uint8_t allZeros[32];
  memset(allZeros, 0x00, sizeof(allZeros));
  fry::clampX25519Private(allZeros);
  TEST_ASSERT_EQUAL_UINT8(0x00, allZeros[0]);  // already-clear low bits stay clear
  TEST_ASSERT_EQUAL_UINT8(0x40, allZeros[31]);  // bit 6 forced on, high bit stays clear

  // Idempotent: clamping an already-clamped key changes nothing (matters because
  // crypto_scalarmult_curve25519_base clamps its input again internally).
  uint8_t twice[32];
  memcpy(twice, allOnes, sizeof(twice));
  fry::clampX25519Private(twice);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(allOnes, twice, 32);
}

void test_encode_rejects_undersized_buffer() {
  uint8_t zero[32] = {};
  char out[44];  // one short of the required 45
  TEST_ASSERT_EQUAL_UINT32(0, fry::encodeWgKeyB64(zero, out, sizeof(out)));
}

// ── Request body (3) ─────────────────────────────────────────────────────────────────────────

void test_body_exact_shape() {
  const char* key = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Xw=";
  char out[160];
  size_t n = fry::buildWgProvisionBody(key, "0.3.3", "ESP32-C3", out, sizeof(out));
  TEST_ASSERT_TRUE(n > 0);
  TEST_ASSERT_EQUAL_STRING(
      "{\"public_key\":\"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Xw=\","
      "\"firmware_version\":\"0.3.3\",\"chip\":\"ESP32-C3\"}",
      out);
}

void test_body_rejects_wrong_length_key() {
  char out[160];
  TEST_ASSERT_EQUAL_UINT32(0, fry::buildWgProvisionBody("tooshort", "0.3.3", "ESP32", out,
                                                        sizeof(out)));
}

void test_body_undersized_buffer_returns_zero() {
  const char* key = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Xw=";
  char out[10];
  TEST_ASSERT_EQUAL_UINT32(0, fry::buildWgProvisionBody(key, "0.3.3", "ESP32-C3", out,
                                                        sizeof(out)));
}

// ── Response validation (10) ─────────────────────────────────────────────────────────────────

const char* kServerPub = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Xw=";
const char* kPsk = "b3T7jvY0oQyv0m4v0m4v0m4v0m4v0m4v0m4v0m4v0m0=";  // shape-only, not a real key

fry::WgProvisionRaw fullValidRaw(const char* const* allowed, int allowedCount) {
  fry::WgProvisionRaw raw;
  raw.serverPub = kServerPub;
  raw.endpointHost = "203.0.113.7";
  raw.endpointPort = 51820;
  raw.tunnelAddress = "10.13.13.2/24";
  raw.allowedIps = allowed;
  raw.allowedIpsCount = allowedCount;
  raw.psk = kPsk;
  raw.keepaliveProvided = true;
  raw.keepaliveValue = 25;
  return raw;
}

void test_validate_accepts_full_response() {
  const char* allowed[] = {"10.13.13.1/32"};
  fry::WgProvisionRaw raw = fullValidRaw(allowed, 1);
  fry::WgProvisionConfig cfg = fry::validateWgProvision(raw);
  TEST_ASSERT_TRUE(cfg.ok);
  TEST_ASSERT_EQUAL_STRING(kServerPub, cfg.serverPub);
  TEST_ASSERT_TRUE(cfg.hasPsk);
  TEST_ASSERT_EQUAL_STRING(kPsk, cfg.psk);
  TEST_ASSERT_EQUAL_STRING("203.0.113.7", cfg.endpointHost);
  TEST_ASSERT_EQUAL_UINT32(51820, cfg.endpointPort);
  TEST_ASSERT_EQUAL_STRING("10.13.13.2/24", cfg.addressCidr);
  TEST_ASSERT_EQUAL_INT(1, cfg.allowedIpsCount);
  TEST_ASSERT_EQUAL_STRING("10.13.13.1/32", cfg.allowedIps[0]);
  TEST_ASSERT_EQUAL_UINT32(25, cfg.keepaliveS);
}

void test_validate_accepts_null_psk() {
  const char* allowed[] = {"10.13.13.1/32"};
  fry::WgProvisionRaw raw = fullValidRaw(allowed, 1);
  raw.psk = nullptr;
  fry::WgProvisionConfig cfg = fry::validateWgProvision(raw);
  TEST_ASSERT_TRUE(cfg.ok);
  TEST_ASSERT_FALSE(cfg.hasPsk);
}

void test_validate_defaults_keepalive_when_absent() {
  const char* allowed[] = {"10.13.13.1/32"};
  fry::WgProvisionRaw raw = fullValidRaw(allowed, 1);
  raw.keepaliveProvided = false;
  fry::WgProvisionConfig cfg = fry::validateWgProvision(raw);
  TEST_ASSERT_TRUE(cfg.ok);
  TEST_ASSERT_EQUAL_UINT32(25, cfg.keepaliveS);
}

void test_validate_rejects_zero_keepalive() {
  // Absent (use default) and explicit-0 (server bug) must NOT be treated the same.
  const char* allowed[] = {"10.13.13.1/32"};
  fry::WgProvisionRaw raw = fullValidRaw(allowed, 1);
  raw.keepaliveProvided = true;
  raw.keepaliveValue = 0;
  fry::WgProvisionConfig cfg = fry::validateWgProvision(raw);
  TEST_ASSERT_FALSE(cfg.ok);
  TEST_ASSERT_EQUAL_STRING("zero_keepalive", cfg.rejectReason);
}

void test_validate_rejects_bad_server_pubkey() {
  const char* allowed[] = {"10.13.13.1/32"};
  fry::WgProvisionRaw raw = fullValidRaw(allowed, 1);
  raw.serverPub = "not-a-key";
  fry::WgProvisionConfig cfg = fry::validateWgProvision(raw);
  TEST_ASSERT_FALSE(cfg.ok);
  TEST_ASSERT_EQUAL_STRING("bad_server_pubkey", cfg.rejectReason);
}

void test_validate_rejects_missing_endpoint_host() {
  const char* allowed[] = {"10.13.13.1/32"};
  fry::WgProvisionRaw raw = fullValidRaw(allowed, 1);
  raw.endpointHost = "";
  fry::WgProvisionConfig cfg = fry::validateWgProvision(raw);
  TEST_ASSERT_FALSE(cfg.ok);
  TEST_ASSERT_EQUAL_STRING("bad_endpoint_host", cfg.rejectReason);
}

void test_validate_rejects_port_zero_and_over_65535() {
  const char* allowed[] = {"10.13.13.1/32"};
  fry::WgProvisionRaw raw = fullValidRaw(allowed, 1);
  raw.endpointPort = 0;
  TEST_ASSERT_FALSE(fry::validateWgProvision(raw).ok);
  raw.endpointPort = 65536;
  TEST_ASSERT_FALSE(fry::validateWgProvision(raw).ok);
}

void test_validate_rejects_malformed_tunnel_address() {
  const char* allowed[] = {"10.13.13.1/32"};
  fry::WgProvisionRaw raw = fullValidRaw(allowed, 1);
  raw.tunnelAddress = "10.13.13.2";  // no /prefix
  fry::WgProvisionConfig cfg = fry::validateWgProvision(raw);
  TEST_ASSERT_FALSE(cfg.ok);
  TEST_ASSERT_EQUAL_STRING("bad_tunnel_address", cfg.rejectReason);
}

void test_validate_rejects_empty_allowed_ips() {
  fry::WgProvisionRaw raw = fullValidRaw(nullptr, 0);
  fry::WgProvisionConfig cfg = fry::validateWgProvision(raw);
  TEST_ASSERT_FALSE(cfg.ok);
  TEST_ASSERT_EQUAL_STRING("allowed_ips_empty", cfg.rejectReason);
}

void test_validate_rejects_more_than_8_allowed_ips() {
  const char* allowed[9] = {"10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32", "10.0.0.4/32",
                            "10.0.0.5/32", "10.0.0.6/32", "10.0.0.7/32", "10.0.0.8/32",
                            "10.0.0.9/32"};
  fry::WgProvisionRaw raw = fullValidRaw(allowed, 9);
  fry::WgProvisionConfig cfg = fry::validateWgProvision(raw);
  TEST_ASSERT_FALSE(cfg.ok);
  TEST_ASSERT_EQUAL_STRING("allowed_ips_too_many", cfg.rejectReason);
}

// ── IPv4 helpers (5) ─────────────────────────────────────────────────────────────────────────

void test_parse_ipv4_cidr_valid() {
  uint32_t ip;
  int prefix;
  TEST_ASSERT_TRUE(fry::parseIpv4Cidr("10.13.13.1/24", &ip, &prefix));
  TEST_ASSERT_EQUAL_UINT32(0x0A0D0D01u, ip);
  TEST_ASSERT_EQUAL_INT(24, prefix);
}

void test_parse_ipv4_cidr_rejects_octet_over_255_and_prefix_over_32() {
  uint32_t ip;
  int prefix;
  TEST_ASSERT_FALSE(fry::parseIpv4Cidr("10.13.13.256/24", &ip, &prefix));
  TEST_ASSERT_FALSE(fry::parseIpv4Cidr("10.13.13.1/33", &ip, &prefix));
}

void test_parse_ipv4_cidr_rejects_trailing_junk() {
  uint32_t ip;
  int prefix;
  TEST_ASSERT_FALSE(fry::parseIpv4Cidr("10.13.13.1/24x", &ip, &prefix));
  TEST_ASSERT_FALSE(fry::parseIpv4Cidr("10.13.13.1", &ip, &prefix));  // no prefix at all
  TEST_ASSERT_FALSE(fry::parseIpv4Cidr("", &ip, &prefix));
}

void test_prefix_to_mask_boundaries() {
  TEST_ASSERT_EQUAL_UINT32(0x00000000u, fry::prefixToMask(0));
  TEST_ASSERT_EQUAL_UINT32(0xFFFFFF00u, fry::prefixToMask(24));
  TEST_ASSERT_EQUAL_UINT32(0xFFFFFFFFu, fry::prefixToMask(32));
}

void test_format_ipv4_and_cidr_roundtrip() {
  char out[16];
  TEST_ASSERT_EQUAL_UINT32(10, fry::formatIpv4(0x0A0D0D01u, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("10.13.13.1", out);

  char cidr[20];
  TEST_ASSERT_TRUE(fry::formatIpv4Cidr(0x0A0D0D00u, 24, cidr, sizeof(cidr)) > 0);
  TEST_ASSERT_EQUAL_STRING("10.13.13.0/24", cidr);
}

void test_mask_to_prefix_roundtrips_with_prefix_to_mask() {
  // Real-world need: wg_provision_client.cpp turns WiFi.subnetMask() back into a prefix length
  // for planWgRoutes' STA-capture check.
  TEST_ASSERT_EQUAL_INT(24, fry::maskToPrefix(0xFFFFFF00u));
  TEST_ASSERT_EQUAL_INT(0, fry::maskToPrefix(0x00000000u));
  TEST_ASSERT_EQUAL_INT(32, fry::maskToPrefix(0xFFFFFFFFu));
  TEST_ASSERT_EQUAL_INT(20, fry::maskToPrefix(0xFFFFF000u));  // a /20 LAN such as 192.168.0.0/20
  for (int p = 0; p <= 32; p++) {
    TEST_ASSERT_EQUAL_INT(p, fry::maskToPrefix(fry::prefixToMask(p)));
  }
}

// ── Route planning (9) — where the in-scope bug's fix is proven ────────────────────────────────

void test_route_plan_includes_the_servers_allowed_ip() {
  // THE core regression test. WIREGUARD_MAX_SRC_IPS=1 (the shipped default) leaves a peer with
  // only its own /32 — unable to express a route back to the server's tunnel IP. This is the
  // real backend contract's numbers (BE-WG endpoint facts): server tunnel 10.13.13.1/24, this
  // device's address 10.13.13.2/24, allowed_ips=["10.13.13.1/32"].
  const char* allowed[] = {"10.13.13.1/32"};
  fry::WgRoutePlan plan =
      fry::planWgRoutes("10.13.13.2/24", allowed, 1, /*staIp=*/0, /*staPrefix=*/0, /*staGw=*/0);
  TEST_ASSERT_TRUE(plan.ok);
  bool foundServer = false;
  for (int i = 0; i < plan.allowedCount; i++) {
    if (strcmp(plan.allowedCidr[i], "10.13.13.1/32") == 0) foundServer = true;
  }
  TEST_ASSERT_TRUE(foundServer);
}

void test_route_plan_caps_at_three_entries() {
  const char* allowed[] = {"10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24", "10.0.4.0/24",
                            "10.0.5.0/24"};
  fry::WgRoutePlan plan = fry::planWgRoutes("10.13.13.2/24", allowed, 5, 0, 0, 0);
  TEST_ASSERT_TRUE(plan.ok);
  TEST_ASSERT_EQUAL_INT(fry::kWgMaxPlannedRoutes, plan.allowedCount);
}

void test_route_plan_drops_prefixes_narrower_than_8() {
  const char* allowed[] = {"0.0.0.0/0", "10.0.0.0/6", "10.0.0.0/8"};
  fry::WgRoutePlan plan = fry::planWgRoutes("10.13.13.2/24", allowed, 3, 0, 0, 0);
  TEST_ASSERT_TRUE(plan.ok);
  TEST_ASSERT_EQUAL_INT(1, plan.allowedCount);
  TEST_ASSERT_EQUAL_STRING("10.0.0.0/8", plan.allowedCidr[0]);
}

void test_route_plan_dedupes_identical_candidates() {
  const char* allowed[] = {"10.13.13.1/32", "10.13.13.1/32", "10.13.13.1/32"};
  fry::WgRoutePlan plan = fry::planWgRoutes("10.13.13.2/24", allowed, 3, 0, 0, 0);
  TEST_ASSERT_TRUE(plan.ok);
  TEST_ASSERT_EQUAL_INT(1, plan.allowedCount);
}

void test_route_plan_defaults_to_tunnel_subnet_when_nothing_survives() {
  // Every candidate filtered out (all wider than /8) -> falls back to addressCidr's own network.
  const char* allowed[] = {"0.0.0.0/0"};
  fry::WgRoutePlan plan = fry::planWgRoutes("10.13.13.2/24", allowed, 1, 0, 0, 0);
  TEST_ASSERT_TRUE(plan.ok);
  TEST_ASSERT_EQUAL_INT(1, plan.allowedCount);
  TEST_ASSERT_EQUAL_STRING("10.13.13.0/24", plan.allowedCidr[0]);
}

void test_route_plan_refuses_sta_subnet_capture() {
  // A (misconfigured) server hands back the board's own WiFi /24 as an allowed-ip. Accepting it
  // verbatim would route the board's own LAN traffic into the tunnel. staIp=192.168.1.50,
  // staPrefix=24, staGw=192.168.1.1 all fall inside the candidate 192.168.1.0/24.
  const char* allowed[] = {"192.168.1.0/24"};
  fry::WgRoutePlan plan =
      fry::planWgRoutes("10.13.13.2/24", allowed, 1, 0xC0A80132u /*192.168.1.50*/, 24,
                        0xC0A80101u /*192.168.1.1*/);
  TEST_ASSERT_TRUE(plan.ok);
  for (int i = 0; i < plan.allowedCount; i++) {
    TEST_ASSERT_NOT_EQUAL(0, strcmp(plan.allowedCidr[i], "192.168.1.0/24"));
  }
}

void test_route_plan_narrows_until_sta_ip_and_gateway_both_excluded() {
  // A wide /16 candidate containing both the STA IP and its gateway is narrowed bit by bit
  // (never flatly refused) until a sub-block excluding both remains.
  const char* allowed[] = {"192.168.0.0/16"};
  uint32_t staIp = 0xC0A80132u;  // 192.168.1.50
  uint32_t staGw = 0xC0A80101u;  // 192.168.1.1 — same /24 as staIp, so one narrowing target
  fry::WgRoutePlan plan = fry::planWgRoutes("10.13.13.2/24", allowed, 1, staIp, 24, staGw);
  TEST_ASSERT_TRUE(plan.ok);
  TEST_ASSERT_EQUAL_INT(1, plan.allowedCount);
  uint32_t net;
  int prefix;
  TEST_ASSERT_TRUE(fry::parseIpv4Cidr(plan.allowedCidr[0], &net, &prefix));
  TEST_ASSERT_TRUE(prefix > 16);  // genuinely narrower than the original /16
  uint32_t mask = fry::prefixToMask(prefix);
  TEST_ASSERT_NOT_EQUAL(net, staIp & mask);
  TEST_ASSERT_NOT_EQUAL(net, staGw & mask);
}

void test_route_plan_coexists_with_bench_lan_supernet() {
  // Real deployment numbers: server tunnel 10.13.13.0/24 (allowed_ips 10.13.13.1/32) must plan
  // normally even though the STA network is a /20 such as 192.168.0.0/20 — the guard triggers
  // ONLY on an actual STA-address overlap, never on "both networks happen to be private-ish."
  const char* allowed[] = {"10.13.13.1/32"};
  uint32_t staIp = 0xC0A80032u;  // 192.168.0.50, inside that /20
  uint32_t staGw = 0xC0A80001u;  // 192.168.0.1
  fry::WgRoutePlan plan = fry::planWgRoutes("10.13.13.2/24", allowed, 1, staIp, 20, staGw);
  TEST_ASSERT_TRUE(plan.ok);
  TEST_ASSERT_EQUAL_INT(1, plan.allowedCount);
  TEST_ASSERT_EQUAL_STRING("10.13.13.1/32", plan.allowedCidr[0]);
}

void test_route_plan_rejects_bad_address_cidr() {
  const char* allowed[] = {"10.13.13.1/32"};
  fry::WgRoutePlan plan = fry::planWgRoutes("not-an-address", allowed, 1, 0, 0, 0);
  TEST_ASSERT_FALSE(plan.ok);
  TEST_ASSERT_EQUAL_STRING("bad_address_cidr", plan.rejectReason);
}

// ── HTTP outcome classification + retry schedule (5) ────────────────────────────────────────

void test_classify_gates_checked_before_http_status() {
  // With an earlier gate failing, httpStatus is irrelevant — proves check ORDER, not just result.
  TEST_ASSERT_EQUAL(fry::WgFetchOutcome::NoToken, fry::classifyWgFetch(false, true, true, 201));
  TEST_ASSERT_EQUAL(fry::WgFetchOutcome::NoHeap, fry::classifyWgFetch(true, false, true, 201));
  TEST_ASSERT_EQUAL(fry::WgFetchOutcome::NoClock, fry::classifyWgFetch(true, true, false, 201));
}

void test_classify_maps_status_codes() {
  TEST_ASSERT_EQUAL(fry::WgFetchOutcome::Ok, fry::classifyWgFetch(true, true, true, 201));
  TEST_ASSERT_EQUAL(fry::WgFetchOutcome::Ok, fry::classifyWgFetch(true, true, true, 200));
  TEST_ASSERT_EQUAL(fry::WgFetchOutcome::Unauthorized401,
                    fry::classifyWgFetch(true, true, true, 401));
  TEST_ASSERT_EQUAL(fry::WgFetchOutcome::Forbidden403,
                    fry::classifyWgFetch(true, true, true, 403));
  TEST_ASSERT_EQUAL(fry::WgFetchOutcome::Conflict409,
                    fry::classifyWgFetch(true, true, true, 409));
  TEST_ASSERT_EQUAL(fry::WgFetchOutcome::RateLimited429,
                    fry::classifyWgFetch(true, true, true, 429));
  TEST_ASSERT_EQUAL(fry::WgFetchOutcome::OtherClientError4xx,
                    fry::classifyWgFetch(true, true, true, 422));
  TEST_ASSERT_EQUAL(fry::WgFetchOutcome::ServerError5xx,
                    fry::classifyWgFetch(true, true, true, 503));
  TEST_ASSERT_EQUAL(fry::WgFetchOutcome::TransientError,
                    fry::classifyWgFetch(true, true, true, -1));
}

void test_retry_403_is_flat_and_long_never_tight_loop() {
  TEST_ASSERT_EQUAL_UINT32(21600000,
                           fry::wgRetryDelayMs(fry::WgFetchOutcome::Forbidden403, 0, 0).delayMs);
  TEST_ASSERT_EQUAL_UINT32(21600000,
                           fry::wgRetryDelayMs(fry::WgFetchOutcome::Forbidden403, 50, 0).delayMs);
}

void test_retry_429_honours_and_clamps_retry_after() {
  TEST_ASSERT_EQUAL_UINT32(
      60000, fry::wgRetryDelayMs(fry::WgFetchOutcome::RateLimited429, 0, 5).delayMs);  // clamped up
  TEST_ASSERT_EQUAL_UINT32(
      86400000,
      fry::wgRetryDelayMs(fry::WgFetchOutcome::RateLimited429, 0, 999999).delayMs);  // clamped down
  TEST_ASSERT_EQUAL_UINT32(
      3600000, fry::wgRetryDelayMs(fry::WgFetchOutcome::RateLimited429, 0, 0).delayMs);  // default
}

void test_retry_exponential_transient_caps_and_is_wrap_safe() {
  TEST_ASSERT_EQUAL_UINT32(
      30000, fry::wgRetryDelayMs(fry::WgFetchOutcome::TransientError, 0, 0).delayMs);
  TEST_ASSERT_EQUAL_UINT32(
      120000, fry::wgRetryDelayMs(fry::WgFetchOutcome::TransientError, 2, 0).delayMs);
  TEST_ASSERT_EQUAL_UINT32(
      1800000, fry::wgRetryDelayMs(fry::WgFetchOutcome::TransientError, 6, 0).delayMs);
  // A very large attempt number must saturate at the cap, never overflow to a short delay.
  TEST_ASSERT_EQUAL_UINT32(
      1800000, fry::wgRetryDelayMs(fry::WgFetchOutcome::TransientError, 4000000000u, 0).delayMs);
  TEST_ASSERT_EQUAL_UINT32(
      1800000, fry::wgRetryDelayMs(fry::WgFetchOutcome::ServerError5xx, 10, 0).delayMs);
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}

void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();

  RUN_TEST(test_valid_wg_key_b64_accepted);
  RUN_TEST(test_key_wrong_length_rejected);
  RUN_TEST(test_key_bad_alphabet_rejected);
  RUN_TEST(test_key_missing_padding_rejected);
  RUN_TEST(test_key_tail_char_with_nonzero_low_bits_rejected);
  RUN_TEST(test_encode_known_bytes_round_trip_through_isWgKeyB64);
  RUN_TEST(test_clamp_sets_and_clears_expected_bits);
  RUN_TEST(test_encode_rejects_undersized_buffer);

  RUN_TEST(test_body_exact_shape);
  RUN_TEST(test_body_rejects_wrong_length_key);
  RUN_TEST(test_body_undersized_buffer_returns_zero);

  RUN_TEST(test_validate_accepts_full_response);
  RUN_TEST(test_validate_accepts_null_psk);
  RUN_TEST(test_validate_defaults_keepalive_when_absent);
  RUN_TEST(test_validate_rejects_zero_keepalive);
  RUN_TEST(test_validate_rejects_bad_server_pubkey);
  RUN_TEST(test_validate_rejects_missing_endpoint_host);
  RUN_TEST(test_validate_rejects_port_zero_and_over_65535);
  RUN_TEST(test_validate_rejects_malformed_tunnel_address);
  RUN_TEST(test_validate_rejects_empty_allowed_ips);
  RUN_TEST(test_validate_rejects_more_than_8_allowed_ips);

  RUN_TEST(test_parse_ipv4_cidr_valid);
  RUN_TEST(test_parse_ipv4_cidr_rejects_octet_over_255_and_prefix_over_32);
  RUN_TEST(test_parse_ipv4_cidr_rejects_trailing_junk);
  RUN_TEST(test_prefix_to_mask_boundaries);
  RUN_TEST(test_format_ipv4_and_cidr_roundtrip);
  RUN_TEST(test_mask_to_prefix_roundtrips_with_prefix_to_mask);

  RUN_TEST(test_route_plan_includes_the_servers_allowed_ip);
  RUN_TEST(test_route_plan_caps_at_three_entries);
  RUN_TEST(test_route_plan_drops_prefixes_narrower_than_8);
  RUN_TEST(test_route_plan_dedupes_identical_candidates);
  RUN_TEST(test_route_plan_defaults_to_tunnel_subnet_when_nothing_survives);
  RUN_TEST(test_route_plan_refuses_sta_subnet_capture);
  RUN_TEST(test_route_plan_narrows_until_sta_ip_and_gateway_both_excluded);
  RUN_TEST(test_route_plan_coexists_with_bench_lan_supernet);
  RUN_TEST(test_route_plan_rejects_bad_address_cidr);

  RUN_TEST(test_classify_gates_checked_before_http_status);
  RUN_TEST(test_classify_maps_status_codes);
  RUN_TEST(test_retry_403_is_flat_and_long_never_tight_loop);
  RUN_TEST(test_retry_429_honours_and_clamps_retry_after);
  RUN_TEST(test_retry_exponential_transient_caps_and_is_wrap_safe);

  return UNITY_END();
}
