#pragma once
// Pure decision logic for recovering a dead WireGuard tunnel, zero Arduino includes, so it links
// into `pio test -e native` like wg_provision.h / boot_policy.h. The Arduino-side glue
// (src/esp32/vpn_wireguard.cpp recoverTick) feeds it plain inputs and performs the action.
//
// Why it exists: the whole WG config is cached in NVS (fry_vpn) and boot reuses it without ever
// re-POSTing; a hostname endpoint is resolved once per boot. When the server peer is removed or
// the endpoint IP changes, a 0.4.1 board re-initiates to the same cached endpoint forever.
//
// Recovery is staged and never reboots the device:
//   A  ReResolve    hostname endpoints only: tear the tunnel down and bring it up again, which
//                   re-resolves the name. If the IP changed the tunnel gets a fresh chance.
//   B  ReProvision  POST a NEW keypair (same install_id = a rotation the server allows) while the
//                   existing fry_vpn config stays untouched. The config is overwritten only after a
//                   validated 2xx response (wgRotationFinish), then the tunnel is rebuilt. A failed
//                   POST changes nothing. Reached directly for an IP-literal endpoint, or after
//                   stage A did not help.
//
// Constants (all in seconds):
//   kWgDeadAfterS 720     The handshake counts as dead after 12 min. esp_wireguard's peer_is_up goes
//                         false once the session is older than REJECT_AFTER_TIME (180 s) with no
//                         new handshake, and one rekey attempt lasts 90 s (REKEY_ATTEMPT_TIME), so
//                         720 s is well over two full give-up cycles (2 * 270 = 540 s) and ~29
//                         missed persistent keepalives (25 s). A Wi-Fi roam, a router reboot or a
//                         short ISP blip does not trigger it; a removed peer is acted on within
//                         a quarter hour.
//   kWgStageAWindowS 300  How long a re-resolved tunnel gets to handshake before stage B.
//   kWgStageBMinIntervalS 3600  At most one stage B per hour, PERSISTED (epoch seconds in NVS) so
//                         a reboot loop cannot hammer the server: a RAM limit resets every boot.
#include <cstddef>
#include <cstdint>

namespace fry {

constexpr uint32_t kWgDeadAfterS = 720;
constexpr uint32_t kWgStageAWindowS = 300;
constexpr uint32_t kWgStageBMinIntervalS = 3600;
constexpr uint32_t kWgApiFreshS = 300;   // a 2xx from hardwareapi this recent proves the API is up
constexpr uint32_t kWgJitterMaxS = 300;  // per-device stage-B delay, 0..300 s inclusive

enum class WgRecoverAction { None, ReResolve, ReProvision };

struct WgRecoverInput {
  bool armed = false;            // the tunnel was brought up (or stage A is in flight) this boot
  bool up = false;               // esp_wireguard_peer_is_up == ESP_OK (recent handshake)
  bool wifiUp = false;           // STA associated; an outage of our own uplink is not "dead"
  uint32_t nowMs = 0;            // millis(); wrap-safe
  bool hostnameEndpoint = false; // wgEndpointIsHostname(cached endpoint)
  bool otaBusy = false;          // an OTA image is pending/settling: never act
  bool clockSynced = false;      // NTP synced: required for stage B (the existing POST gate)
  bool provBlocked = false;      // wg_provision_client is inside a 401/403/429/... backoff
  bool apiReachable = false;     // wgApiRecent(fry_ota::heartbeatAgeS()): API answered 2xx lately
  uint32_t jitterS = 0;          // wgRecoverJitterS(device seed); delays stage B only
  uint32_t epochNow = 0;         // time(nullptr), meaningful only when clockSynced
  uint32_t lastStageBEpoch = 0;  // persisted epoch of the last stage B, 0 = never
};

class WgRecover {
 public:
  // Call every loop. Returns the action to perform now (None almost always). Stage A is returned
  // once per outage; stage B is returned once and the tracker then restarts from a fresh clock.
  WgRecoverAction decide(const WgRecoverInput& in);

  // The glue calls this after it performed stage A and the tunnel was brought up again.
  // ipChanged=true restarts the dead clock (the new endpoint gets a full threshold).
  void onReResolved(bool ipChanged, uint32_t nowMs);

 private:
  bool tracking_ = false;
  uint32_t deadSinceMs_ = 0;
  bool stageADone_ = false;
  uint32_t stageAAtMs_ = 0;
  bool futureSeen_ = false;       // a persisted stamp newer than the clock was observed
  uint32_t futureCapEpoch_ = 0;   // ...and is honoured for at most kWgStageBMinIntervalS from then
  bool stageBLimited(const WgRecoverInput& in);
  void reset();
};

// True for anything that is not an IPv4 dotted quad or an IPv6 literal (bracketed, or containing
// a ':'). Null/empty is not a hostname.
bool wgEndpointIsHostname(const char* endpoint);

// True if a 2xx hardwareapi answer was seen within kWgApiFreshS (heartbeatAgeS: -1 = none).
bool wgApiRecent(int32_t heartbeatAgeS);

// Deterministic per-device delay in [0, kWgJitterMaxS] (FNV-1a of the seed, e.g. the eFuse MAC),
// so a fleet that lost its peer at the same moment does not POST in the same second.
uint32_t wgRecoverJitterS(uint64_t seed);

// ── Tunnel teardown (M1) ─────────────────────────────────────────────────────────────────────
// esp_wireguard_connect() builds the lwIP netif, and with it the private key, only when
// ctx->netif == NULL, and a failed connect leaves that netif behind. So teardown must key off the
// netif, not off "initialized": a half-failed stage A would otherwise leave a stale old-key netif
// that a later stage B reuses.
class WgTunnelOps {
 public:
  virtual ~WgTunnelOps() = default;
  virtual bool hasNetif() = 0;
  virtual bool teardown() = 0;  // must run in the lwIP core context; true when it completed
};

// Tears the tunnel down iff a netif exists. Returns true when no netif remains afterwards; false
// means the caller must keep its "fresh netif required" flag and retry.
bool wgTearDownTunnel(WgTunnelOps& ops);

// ── Config rotation (M2) ─────────────────────────────────────────────────────────────────────
enum class WgRotationState { Idle, Pending, Committed, Failed };

class WgRotationWriter {
 public:
  virtual ~WgRotationWriter() = default;
  virtual void commit() = 0;  // persists the new keypair + validated config
};

// The only place the cached config may be replaced: commit() runs iff the response validated.
WgRotationState wgRotationFinish(bool responseValidated, WgRotationWriter* writer);

}  // namespace fry
