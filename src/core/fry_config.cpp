#include "fry_config.h"

#include <cstring>

#include "config.h"
#include "kv_store.h"

namespace fry_config {

// ── fry_wifi ──────────────────────────────────────────────────────────────

bool hasWifi() {
  KvStore p;
  p.begin("fry_wifi", true);
  bool has = p.isKey("ssid");
  p.end();
  return has;
}

bool getWifi(char* ssid, size_t ssidLen, char* pass, size_t passLen) {
  KvStore p;
  p.begin("fry_wifi", true);
  bool has = p.isKey("ssid");
  p.getString("ssid", ssid, ssidLen);
  p.getString("pass", pass, passLen);
  p.end();
  return has;
}

void setWifi(const char* ssid, const char* pass) {
  KvStore p;
  p.begin("fry_wifi", false);
  p.putString("ssid", ssid);
  p.putString("pass", pass ? pass : "");
  p.end();
}

void clearWifi() {
  KvStore p;
  p.begin("fry_wifi", false);
  p.clear();
  p.end();
}

// ── fry (device identity) ────────────────────────────────────────────────

String getWallet() {
  KvStore p;
  p.begin("fry", true);
  String v = p.getString("wallet", "");
  p.end();
  return v;
}

void setWallet(const char* wallet) {
  KvStore p;
  p.begin("fry", false);
  p.putString("wallet", wallet);
  p.end();
}

bool hasWallet() {
  KvStore p;
  p.begin("fry", true);
  bool has = p.isKey("wallet");
  p.end();
  return has;
}

bool getMinerKey(char* out, size_t outLen) {
  KvStore p;
  p.begin("fry", true);
  bool has = p.isKey("minerKey");
  p.getString("minerKey", out, outLen);
  p.end();
  return has;
}

void setMinerKey(const char* key) {
  KvStore p;
  p.begin("fry", false);
  p.putString("minerKey", key);
  p.end();
}

bool getSalt(uint8_t out[16]) {
  KvStore p;
  p.begin("fry", true);
  bool has = p.isKey("salt") && p.getBytesLength("salt") == 16;
  if (has) p.getBytes("salt", out, 16);
  p.end();
  return has;
}

void setSalt(const uint8_t salt[16]) {
  KvStore p;
  p.begin("fry", false);
  p.putBytes("salt", salt, 16);
  p.end();
}

String getInstallId() {
  KvStore p;
  p.begin("fry", true);
  String v = p.getString("installId", "");
  p.end();
  return v;
}

void setInstallId(const char* id) {
  KvStore p;
  p.begin("fry", false);
  p.putString("installId", id);
  p.end();
}

bool hasInstallId() {
  KvStore p;
  p.begin("fry", true);
  bool has = p.isKey("installId");
  p.end();
  return has;
}

String getDeviceToken() {
  KvStore p;
  p.begin("fry", true);
  String v = p.getString("deviceToken", "");
  p.end();
  return v;
}

void setDeviceToken(const char* token) {
  KvStore p;
  p.begin("fry", false);
  p.putString("deviceToken", token);
  p.end();
}

String getApiBase() {
  KvStore p;
  p.begin("fry", true);
  String v = p.getString("apiBase", "");
  p.end();
  if (v.length() == 0) return String(HARDWAREAPI_BASE);
  return v;
}

void setApiBase(const char* base) {
  KvStore p;
  p.begin("fry", false);
  p.putString("apiBase", base);
  p.end();
}

// ── fry_vpn ───────────────────────────────────────────────────────────────

String getWgPriv() {
  KvStore p;
  p.begin("fry_vpn", true);
  String v = p.getString("wgPriv", "");
  p.end();
  return v;
}
void setWgPriv(const char* v) {
  KvStore p;
  p.begin("fry_vpn", false);
  p.putString("wgPriv", v);
  p.end();
}

String getWgPeerPub() {
  KvStore p;
  p.begin("fry_vpn", true);
  String v = p.getString("wgPeerPub", "");
  p.end();
  return v;
}
void setWgPeerPub(const char* v) {
  KvStore p;
  p.begin("fry_vpn", false);
  p.putString("wgPeerPub", v);
  p.end();
}

String getWgPsk() {
  KvStore p;
  p.begin("fry_vpn", true);
  String v = p.getString("wgPsk", "");
  p.end();
  return v;
}
void setWgPsk(const char* v) {
  KvStore p;
  p.begin("fry_vpn", false);
  p.putString("wgPsk", v);
  p.end();
}

String getWgEndpoint() {
  KvStore p;
  p.begin("fry_vpn", true);
  String v = p.getString("wgEndpoint", "");
  p.end();
  return v;
}
void setWgEndpoint(const char* v) {
  KvStore p;
  p.begin("fry_vpn", false);
  p.putString("wgEndpoint", v);
  p.end();
}

uint32_t getWgPort() {
  KvStore p;
  p.begin("fry_vpn", true);
  uint32_t v = p.getUInt("wgPort", 51820);
  p.end();
  return v;
}
void setWgPort(uint32_t v) {
  KvStore p;
  p.begin("fry_vpn", false);
  p.putUInt("wgPort", v);
  p.end();
}

String getWgAddr() {
  KvStore p;
  p.begin("fry_vpn", true);
  String v = p.getString("wgAddr", "");
  p.end();
  return v;
}
void setWgAddr(const char* v) {
  KvStore p;
  p.begin("fry_vpn", false);
  p.putString("wgAddr", v);
  p.end();
}

uint32_t getSocksPort() {
  KvStore p;
  p.begin("fry_vpn", true);
  uint32_t v = p.getUInt("socksPort", SOCKS5_PORT);
  p.end();
  return v;
}
void setSocksPort(uint32_t v) {
  KvStore p;
  p.begin("fry_vpn", false);
  p.putUInt("socksPort", v);
  p.end();
}

bool hasVpnConfig() {
  KvStore p;
  p.begin("fry_vpn", true);
  bool has = p.isKey("wgPeerPub") && p.isKey("wgEndpoint");
  p.end();
  return has;
}

void clearVpn() {
  KvStore p;
  p.begin("fry_vpn", false);
  p.clear();
  p.end();
}

// ── fry_ota ───────────────────────────────────────────────────────────────

String getOtaPending() {
  KvStore p;
  p.begin("fry_ota", true);
  String v = p.getString("pending", "");
  p.end();
  return v;
}
void setOtaPending(const char* version) {
  KvStore p;
  p.begin("fry_ota", false);
  p.putString("pending", version);
  p.end();
}
void clearOtaPending() {
  KvStore p;
  p.begin("fry_ota", false);
  p.remove("pending");
  p.end();
}

String getOtaUrl() {
  KvStore p;
  p.begin("fry_ota", true);
  String v = p.getString("url", "");
  p.end();
  return v;
}
void setOtaUrl(const char* url) {
  KvStore p;
  p.begin("fry_ota", false);
  if (url && strlen(url) > 0) {
    p.putString("url", url);
  } else {
    p.remove("url");  // empty string restores the compiled default, per PROTOCOL.md section 7
  }
  p.end();
}

uint8_t getOtaBootFails() {
  KvStore p;
  p.begin("fry_ota", true);
  uint8_t v = p.getUChar("bootfails", 0);
  p.end();
  return v;
}
void setOtaBootFails(uint8_t v) {
  KvStore p;
  p.begin("fry_ota", false);
  p.putUChar("bootfails", v);
  p.end();
}
void clearOtaBootFails() {
  KvStore p;
  p.begin("fry_ota", false);
  p.remove("bootfails");
  p.end();
}

// ── factory reset ─────────────────────────────────────────────────────────

void factoryReset() {
  clearWifi();

  // fry namespace: remove wallet/installId/deviceToken but PRESERVE salt + minerKey.
  KvStore p;
  p.begin("fry", false);
  p.remove("wallet");
  p.remove("installId");
  p.remove("deviceToken");
  p.end();

  clearVpn();

  KvStore o;
  o.begin("fry_ota", false);
  o.clear();
  o.end();
}

}  // namespace fry_config
