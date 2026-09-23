#pragma once
// Chip-agnostic persisted configuration. Namespaces and keys are fixed by the T3 contract and
// must match exactly across chips: fry_wifi{ssid,pass}, fry{wallet,minerKey,salt,installId,
// deviceToken,apiBase}, fry_vpn{wgPriv,wgPub,wgPeerPub,wgPsk,wgEndpoint,wgPort,wgAddr,socksPort,
// wgAllowed,wgKeepalive,wgProvAt}, fry_ota{pending,url,bootfails}.
#include <Arduino.h>

namespace fry_config {

// ── fry_wifi ──────────────────────────────────────────────────────────────
bool hasWifi();
bool getWifi(char* ssid, size_t ssidLen, char* pass, size_t passLen);
void setWifi(const char* ssid, const char* pass);
void clearWifi();

// ── fry (device identity) ────────────────────────────────────────────────
String getWallet();
void setWallet(const char* wallet);
bool hasWallet();
bool getMinerKey(char* out, size_t outLen);  // returns false if never generated
void setMinerKey(const char* key);
bool getSalt(uint8_t out[16]);  // returns false if never generated
void setSalt(const uint8_t salt[16]);
// fry/provDone — "these credentials were committed", set by a transport that has no wallet to
// store (Improv Serial). hasWallet() plays the same role for BLE/SoftAP. Cleared by factoryReset.
bool hasProvDone();
void setProvDone();
String getInstallId();
void setInstallId(const char* id);
bool hasInstallId();
String getDeviceToken();
void setDeviceToken(const char* token);
String getApiBase();  // falls back to the compiled HARDWAREAPI_BASE default if unset
void setApiBase(const char* base);

// ── fry_vpn ───────────────────────────────────────────────────────────────
String getWgPriv();
void setWgPriv(const char* v);
// This device's OWN WireGuard public key (paired with wgPriv) — distinct from wgPeerPub, which
// is the SERVER's key. Naming is deliberately parallel to the wgPriv/wgPeerPub pair: "ours" has
// no suffix, "theirs" is *Peer*.
String getWgPub();
void setWgPub(const char* v);
String getWgPeerPub();
void setWgPeerPub(const char* v);
String getWgPsk();
void setWgPsk(const char* v);
String getWgEndpoint();
void setWgEndpoint(const char* v);
uint32_t getWgPort();
void setWgPort(uint32_t v);
String getWgAddr();
void setWgAddr(const char* v);
uint32_t getSocksPort();
void setSocksPort(uint32_t v);
// `;`-joined planned allowed-ip CIDR list (lib/fry_core/wg_provision.h's planWgRoutes output,
// at most kWgMaxPlannedRoutes entries) — the routes vpn_wireguard.cpp adds via
// esp_wireguard_add_allowed_ip once the tunnel is up.
String getWgAllowed();
void setWgAllowed(const char* csv);
uint32_t getWgKeepalive();  // defaults to 25 (this codebase's historical hard-coded value)
void setWgKeepalive(uint32_t v);
// Epoch seconds of the last successful server-driven provisioning POST, 0 if never provisioned.
// Production ESP32 builds only trust a WireGuard config when this is non-zero (FRY_SERIAL_PROVISION
// lab builds are exempt — they keep trusting whatever the `set_wg` serial command wrote).
uint32_t getWgProvAt();
void setWgProvAt(uint32_t epochS);

// Persists a freshly generated keypair BEFORE the provisioning POST is sent, so a crash or
// reset between keygen and the server's response never orphans it — the server's 201/200
// idempotent-replay behavior recovers from posting the same public key again.
void setWgKeypair(const char* priv, const char* pub);

// The single entry point src/esp32/wg_provision_client.cpp calls after a successful POST.
// Writes every field, then wgPeerPub (hasVpnConfig()'s existing commit marker), then wgProvAt
// LAST — the new production trust gate in vpn_wireguard.cpp keys off wgProvAt, so a reset that
// interrupts this call always leaves either "nothing changed" or "fully committed", never a
// state the production gate would trust while some other field is still stale.
void setWgProvisioned(const char* peerPub, const char* psk, const char* endpointHost,
                      uint16_t endpointPort, const char* addrCidr, const char* allowedCsv,
                      uint32_t keepaliveS);

bool hasVpnConfig();
void clearVpn();

// ── fry_ota ───────────────────────────────────────────────────────────────
String getOtaPending();
void setOtaPending(const char* version);
void clearOtaPending();
String getOtaUrl();  // "" means: use the compiled OTA_MANIFEST_URL default
void setOtaUrl(const char* url);
uint8_t getOtaBootFails();
void setOtaBootFails(uint8_t v);
void clearOtaBootFails();

// Wipes fry_wifi, fry/wallet, fry/provDone, fry/installId, fry/deviceToken, fry_vpn and fry_ota.
// PRESERVES fry/salt and fry/minerKey so a re-provisioned board keeps one server identity
// (PROTOCOL.md section 7, factory_reset).
void factoryReset();

}  // namespace fry_config
