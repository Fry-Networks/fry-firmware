#pragma once
// Chip-agnostic persisted configuration. Namespaces and keys are fixed by the T3 contract and
// must match exactly across chips: fry_wifi{ssid,pass}, fry{wallet,minerKey,salt,installId,
// deviceToken,apiBase}, fry_vpn{wgPriv,wgPeerPub,wgPsk,wgEndpoint,wgPort,wgAddr,socksPort},
// fry_ota{pending,url,bootfails}.
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

// Wipes fry_wifi, fry/wallet, fry/installId, fry/deviceToken, fry_vpn and fry_ota.
// PRESERVES fry/salt and fry/minerKey so a re-provisioned board keeps one server identity
// (PROTOCOL.md section 7, factory_reset).
void factoryReset();

}  // namespace fry_config
