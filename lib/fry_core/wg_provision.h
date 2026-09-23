#pragma once
// Pure C++ support for server-driven WireGuard provisioning (the fetch path added alongside the
// existing lab-only `set_wg` serial command). Zero Arduino includes, zero external crypto/JSON
// dependencies, so it links into `pio test -e native` exactly like wg_endpoint.h/semver.h/sha256.h
// — the Arduino-side wrapper (src/esp32/wg_provision_client.cpp) does the HTTPS call and the
// ArduinoJson parsing, then hands this module plain extracted fields.
//
// Bug this module exists to fix: droscy/esp_wireguard 0.4.5 defaults WIREGUARD_MAX_SRC_IPS to 1
// (wireguard-platform.h), which esp_wireguard fills with the device's own /32 tunnel address.
// Every reply the peer sends back to the SERVER's tunnel IP then gets ERR_RTE: the handshake
// completes ("up") but no data ever crosses. planWgRoutes() below turns the server's
// `allowed_ips` list into a bounded, de-duplicated, non-STA-capturing route set that actually
// includes a route BACK to the server, and platformio.ini raises CONFIG_WIREGUARD_MAX_SRC_IPS to
// 4 so there is room for the device's own /32 plus up to 3 planned routes
// (see src/esp32/vpn_wireguard.cpp's compile-time static_assert on the same constant).
#include <cstddef>
#include <cstdint>

namespace fry {

// ── Key encoding (RFC 7748 X25519, WireGuard's own base64 key-string convention) ────────────

// A WireGuard key string: exactly 44 base64 characters (32 bytes + padding), standard alphabet
// (not URL-safe), ending in a single '=' whose low bits are consistent with a 32-byte payload.
// This is a SHAPE check only — it does not reject a low-order/all-zero point; the server and
// esp_wireguard both validate the decoded point separately.
bool isWgKeyB64(const char* s);

// RFC 7748 section 5 clamp, applied in place: key[0] &= 248; key[31] &= 127; key[31] |= 64.
// Idempotent — clamping an already-clamped key changes nothing, which matters because
// crypto_scalarmult_curve25519_base() (libsodium) clamps its input again internally; applying
// this before persisting the private key just means the NVS copy and what libsodium actually
// used are the same 32 bytes, so a reboot never re-derives a different keypair from stale bytes.
void clampX25519Private(uint8_t key[32]);

// Standard base64 with '=' padding (WireGuard's convention — NOT the URL-safe alphabet). Writes
// a NUL-terminated 44-char string plus NUL (45 bytes) to `out` and returns 45 on success, or 0 if
// `outLen` < 45 or `in`/`out` is null. Self-contained (no libb64 dependency, which is ESP8266-only
// and would not link into `native`).
size_t encodeWgKeyB64(const uint8_t in[32], char* out, size_t outLen);

// ── Request body ─────────────────────────────────────────────────────────────────────────────

// Builds {"public_key":"<44b64>","firmware_version":"<fw>","chip":"<chip>"} exactly (field order
// and spacing matter: this is compared byte-for-byte against the documented backend contract).
// Returns the number of characters written (excluding NUL), or 0 on failure: `pubKeyB64` is not
// exactly 44 chars, `firmwareVersion`/`chip` contain a character that would need JSON escaping
// (see isJsonSafeToken-style reasoning in telemetry_body.h — these are always compile-time
// constants in practice, so refusing anything else is cheap insurance), or the buffer is too
// small.
size_t buildWgProvisionBody(const char* pubKeyB64, const char* firmwareVersion, const char* chip,
                            char* out, size_t outLen);

// ── Response validation ──────────────────────────────────────────────────────────────────────

constexpr int kWgMaxAllowedIps = 8;  // backend contract's hard cap on the raw list it sends

struct WgProvisionConfig {
  bool ok = false;
  char rejectReason[32] = {};  // set only when ok == false

  char serverPub[45] = {};        // server's WireGuard public key, 44 b64 chars + NUL
  bool hasPsk = false;
  char psk[45] = {};              // preshared key, valid only when hasPsk
  char endpointHost[64] = {};
  uint16_t endpointPort = 0;
  char addressCidr[20] = {};      // this device's tunnel address, e.g. "10.13.13.2/24"
  char allowedIps[kWgMaxAllowedIps][20] = {};
  int allowedIpsCount = 0;
  uint32_t keepaliveS = 25;       // default per PROTOCOL.md-adjacent contract when field is absent
};

// Raw, already-extracted response fields (the Arduino-side caller owns the ArduinoJson parse).
// `allowedIps`/`allowedIpsCount` mirror the server's `peer.allowed_ips` array verbatim (pointers
// must stay valid for the call's duration only — nothing here is retained past the call).
// `psk` is nullptr for a JSON null or a wholly absent field (both mean "no PSK"), a non-null
// empty string is treated as a malformed PSK (rejected), and `keepaliveProvided=false` means the
// field was absent (use the default) as opposed to explicitly present as 0 (rejected — a server
// bug sending 0 must not silently produce a keepalive-less tunnel).
struct WgProvisionRaw {
  const char* serverPub = nullptr;
  const char* endpointHost = nullptr;
  int32_t endpointPort = -1;
  const char* tunnelAddress = nullptr;
  const char* const* allowedIps = nullptr;
  int allowedIpsCount = 0;
  const char* psk = nullptr;
  bool keepaliveProvided = false;
  int32_t keepaliveValue = 0;
};

// Validates a POST /vpn/v1/wireguard/{miner_key}/peer 2xx response against the documented
// contract. Every rejection reason is a short machine-readable token in rejectReason (e.g.
// "bad_server_pubkey", "bad_endpoint_host", "bad_port", "bad_tunnel_address",
// "allowed_ips_empty", "allowed_ips_too_many", "bad_allowed_ip", "bad_psk", "zero_keepalive").
WgProvisionConfig validateWgProvision(const WgProvisionRaw& raw);

// ── IPv4 helpers ─────────────────────────────────────────────────────────────────────────────

// Parses "a.b.c.d/nn" (0<=octets<=255, 0<=nn<=32). Returns false (leaving *ip/*prefix untouched)
// on any malformed input, extra characters, leading-zero-free-but-out-of-range octet, or a
// missing/out-of-range prefix.
bool parseIpv4Cidr(const char* s, uint32_t* ip, int* prefix);

// Network-order-agnostic: `ip` and the returned mask are both host-order uint32_t with the
// convention that bit 31 is the most significant octet (the first dotted component). prefix=0
// returns 0x00000000; prefix=32 returns 0xFFFFFFFF.
uint32_t prefixToMask(int prefix);

// Formats a host-order uint32_t as "a.b.c.d". Returns the number of characters written
// (excluding NUL), or 0 if outLen < 16.
size_t formatIpv4(uint32_t ip, char* out, size_t outLen);

// Formats "a.b.c.d/nn". Returns characters written (excluding NUL), or 0 if outLen < 19.
size_t formatIpv4Cidr(uint32_t ip, int prefix, char* out, size_t outLen);

// Inverse of prefixToMask: counts leading one-bits in a canonical mask (contiguous ones then
// contiguous zeros, e.g. 0xFFFFFF00 -> 24). Used to turn WiFi.subnetMask() into a prefix length
// for planWgRoutes' STA-capture check. A non-canonical mask (a zero bit before a one bit) yields
// the count of leading ones before the first zero — the best a caller can do with a malformed
// mask; this is not a validity check.
int maskToPrefix(uint32_t mask);

// ── Route planning ───────────────────────────────────────────────────────────────────────────

constexpr int kWgMaxPlannedRoutes = 3;  // CONFIG_WIREGUARD_MAX_SRC_IPS(4) - 1 for the device's
                                        // own /32, which esp_wireguard always occupies a slot with

struct WgRoutePlan {
  bool ok = false;
  char rejectReason[40] = {};
  char allowedCidr[kWgMaxPlannedRoutes][20] = {};
  int allowedCount = 0;
};

// Turns the server's raw `allowed_ips` list (already validated as well-formed CIDRs by
// validateWgProvision) into a bounded (<=3), de-duplicated, non-STA-capturing route plan.
// Candidates are processed in order, each going through this pipeline:
//   1. dropped outright if malformed or prefix < 8 (i.e. /0-/7 — "wider than a /8");
//   2. dropped if it exactly duplicates the network+prefix of an already-kept candidate;
//   3. LAN-CAPTURE REFUSAL: if its network contains the board's own STA address (staIp/staPrefix)
//      or its gateway (staGw), the candidate is narrowed — its prefix raised one bit at a time,
//      always keeping the half that excludes the offending address — until a sub-block excluding
//      BOTH remains; if even /32 can't exclude them (the candidate literally IS the STA's own
//      address), that one candidate is dropped, not the whole plan;
//   4. kept, until kWgMaxPlannedRoutes are kept (first-seen order — a later valid candidate is
//      simply not considered once the cap is reached).
// If nothing survives this pipeline, the plan defaults to `addressCidr`'s own network (e.g.
// "10.13.13.2/24" -> "10.13.13.0/24", never narrowed against the STA address, since the tunnel's
// own subnet is expected to legitimately include the device's own tunnel address), so a peer is
// never left with zero return routes.
// staPrefix <= 0 or staIp == 0 disables the STA-capture check entirely (e.g. WiFi not yet up
// when this is called in a context with no STA info available) — callers that have a real STA
// address should always pass it.
WgRoutePlan planWgRoutes(const char* addressCidr, const char* const* allowedIps, int allowedCount,
                          uint32_t staIp, int staPrefix, uint32_t staGw);

// ── HTTP outcome classification + retry schedule ────────────────────────────────────────────

enum class WgFetchOutcome {
  Ok,
  NoToken,           // fry_config::getDeviceToken() is empty — never falls back to a compiled token
  NoHeap,            // heap gate failed before a request was even attempted
  NoClock,           // NTP not synced yet
  TransientError,    // transport error, or a status this table doesn't otherwise name
  Unauthorized401,
  Forbidden403,
  Conflict409,
  RateLimited429,
  OtherClientError4xx,
  ServerError5xx,
};

// Checked in this order: token -> heap -> clock -> HTTP status. `httpStatus` is ignored (and may
// be any value, including <=0 for "no request was sent") whenever an earlier gate already fails.
WgFetchOutcome classifyWgFetch(bool hasToken, bool heapOk, bool clockOk, int32_t httpStatus);

struct WgRetrySchedule {
  uint32_t delayMs = 0;
};

// Wrap-safe: internally widens to uint64_t for the exponential branch before clamping back into
// uint32_t, so a very large attemptNumber saturates at the cap instead of overflowing to a short
// delay. `retryAfterHeaderS` is only consulted for Conflict409/RateLimited429 and is otherwise
// ignored; 0 means "no Retry-After header was present."
//   NoToken / NoHeap        -> 60,000 ms flat
//   NoClock                 -> 300,000 ms flat
//   TransientError / 5xx    -> 30,000 * 2^attemptNumber, capped at 1,800,000 ms
//   Unauthorized401         -> 900,000 ms flat
//   Forbidden403            -> 21,600,000 ms flat (deliberately long: a non-QA board that
//                               web-flashes this firmware gets "provisioning_not_open" and must
//                               never tight-loop against it)
//   Conflict409/RateLimited429 -> retryAfterHeaderS clamped to [60,000, 86,400,000] ms if >0,
//                               else 3,600,000 ms flat
//   OtherClientError4xx     -> 21,600,000 ms flat
WgRetrySchedule wgRetryDelayMs(WgFetchOutcome outcome, uint32_t attemptNumber,
                                uint32_t retryAfterHeaderS);

}  // namespace fry
