#include "fry_config.h"

#include <cstring>
#include <ctime>

#ifndef ESP8266
#include <nvs.h>
#endif

#include "config.h"
#include "kv_guard.h"
#include "kv_store.h"

namespace fry_config {

namespace {
// Does the NVS namespace exist? Probed with a raw read-only nvs_open: it neither logs (Preferences::
// begin(ns, true) logs an [E] nvs_open NOT_FOUND on every call for a namespace never written) nor
// writes flash (a read-write open would create the namespace). A positive answer is cached per name:
// a namespace is never removed (clearVpn()/factoryReset() clear its keys only). Every read-only
// getter below goes through this plus the kv_guard.h templates, so an expected state (a namespace or
// an optional key that was never written) produces no [E] line (T8).
bool nsExists(const char* ns) {
#ifdef ESP8266
  (void)ns;
  return true;
#else
  static char seen[8][12];
  static int nseen = 0;
  for (int i = 0; i < nseen; i++) {
    if (std::strcmp(seen[i], ns) == 0) return true;
  }
  nvs_handle_t h;
  if (nvs_open(ns, NVS_READONLY, &h) != ESP_OK) return false;
  nvs_close(h);
  if (nseen < 8 && std::strlen(ns) < sizeof(seen[0])) std::strcpy(seen[nseen++], ns);
  return true;
#endif
}
}  // namespace

// ── fry_wifi ──────────────────────────────────────────────────────────────

bool hasWifi() {
  KvStore p;
  return fry::kvReadGuarded<bool>(nsExists, p, "fry_wifi", "ssid", false, [](KvStore&) { return true; });
}

bool getWifi(char* ssid, size_t ssidLen, char* pass, size_t passLen) {
  KvStore p;
  const bool has = fry::kvGetCStringGuarded(nsExists, p, "fry_wifi", "ssid", ssid, ssidLen);
  if (has) fry::kvGetCStringGuarded(nsExists, p, "fry_wifi", "pass", pass, passLen);
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
  return fry::kvGetStringGuarded<String>(nsExists, p, "fry", "wallet");  // T8: no [E] for a missing namespace/key
}

void setWallet(const char* wallet) {
  KvStore p;
  p.begin("fry", false);
  p.putString("wallet", wallet);
  p.end();
}

bool hasWallet() {
  KvStore p;
  return fry::kvReadGuarded<bool>(nsExists, p, "fry", "wallet", false, [](KvStore&) { return true; });
}

bool getMinerKey(char* out, size_t outLen) {
  KvStore p;
  return fry::kvGetCStringGuarded(nsExists, p, "fry", "minerKey", out, outLen);
}

void setMinerKey(const char* key) {
  KvStore p;
  p.begin("fry", false);
  p.putString("minerKey", key);
  p.end();
}

bool getSalt(uint8_t out[16]) {
  if (!nsExists("fry")) return false;
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

bool hasProvDone() {
  KvStore p;
  return fry::kvReadGuarded<bool>(nsExists, p, "fry", "provDone", false, [](KvStore& s) { return s.getBool("provDone", false); });
}

void setProvDone() {
  KvStore p;
  p.begin("fry", false);
  p.putBool("provDone", true);
  p.end();
}

String getInstallId() {
  KvStore p;
  return fry::kvGetStringGuarded<String>(nsExists, p, "fry", "installId");  // T8: no [E] for a missing namespace/key
}

void setInstallId(const char* id) {
  KvStore p;
  p.begin("fry", false);
  p.putString("installId", id);
  p.end();
}

bool hasInstallId() {
  KvStore p;
  return fry::kvReadGuarded<bool>(nsExists, p, "fry", "installId", false, [](KvStore&) { return true; });
}

String getDeviceToken() {
  KvStore p;
  return fry::kvGetStringGuarded<String>(nsExists, p, "fry", "deviceToken");  // T8: no [E] for a missing namespace/key
}

void setDeviceToken(const char* token) {
  KvStore p;
  p.begin("fry", false);
  p.putString("deviceToken", token);
  p.end();
}

String getApiBase() {
  KvStore p;
  String v = fry::kvGetStringGuarded<String>(nsExists, p, "fry", "apiBase");  // optional override; T8: no [E] when absent
  if (v.length() == 0) return String(HARDWAREAPI_BASE);
  return v;
}

void setApiBase(const char* base) {
  KvStore p;
  p.begin("fry", false);
  p.putString("apiBase", base);
  p.end();
}

bool getKeyOk() {
  KvStore p;
  return fry::kvReadGuarded<bool>(nsExists, p, "fry", "keyOk", false, [](KvStore& s) { return s.getBool("keyOk", false); });
}

void setKeyOk(bool ok) {
  KvStore p;
  p.begin("fry", false);
  p.putBool("keyOk", ok);
  p.end();
}

String getKeySrc() {
  KvStore p;
  return fry::kvGetStringGuarded<String>(nsExists, p, "fry", "keySrc");  // T8: no [E] for a missing namespace/key
}

void setKeySrc(const char* src) {
  KvStore p;
  p.begin("fry", false);
  p.putString("keySrc", src);
  p.end();
}

String getApCode() {
  KvStore p;
  return fry::kvGetStringGuarded<String>(nsExists, p, "fry", "apCode");  // T8: no [E] for a missing namespace/key
}

void setApCode(const char* code) {
  KvStore p;
  p.begin("fry", false);
  p.putString("apCode", code);
  p.end();
}

void clearInstallation() {
  KvStore p;
  p.begin("fry", false);
  p.remove("installId");
  p.remove("deviceToken");
  p.end();
}

// ── fry_vpn ───────────────────────────────────────────────────────────────


String getWgPriv() {
  KvStore p;
  return fry::kvGetStringGuarded<String>(nsExists, p, "fry_vpn", "wgPriv");  // no [E] for a missing namespace or key (T8)
}
void setWgPriv(const char* v) {
  KvStore p;
  p.begin("fry_vpn", false);
  p.putString("wgPriv", v);
  p.end();
}

String getWgPub() {
  KvStore p;
  return fry::kvGetStringGuarded<String>(nsExists, p, "fry_vpn", "wgPub");  // no [E] for a missing namespace or key (T8)
}
void setWgPub(const char* v) {
  KvStore p;
  p.begin("fry_vpn", false);
  p.putString("wgPub", v);
  p.end();
}

String getWgPeerPub() {
  KvStore p;
  return fry::kvGetStringGuarded<String>(nsExists, p, "fry_vpn", "wgPeerPub");  // no [E] for a missing namespace or key (T8)
}
void setWgPeerPub(const char* v) {
  KvStore p;
  p.begin("fry_vpn", false);
  p.putString("wgPeerPub", v);
  p.end();
}

String getWgPsk() {
  KvStore p;
  return fry::kvGetStringGuarded<String>(nsExists, p, "fry_vpn", "wgPsk");  // no [E] for a missing namespace or key (T8)
}
void setWgPsk(const char* v) {
  KvStore p;
  p.begin("fry_vpn", false);
  p.putString("wgPsk", v);
  p.end();
}

String getWgEndpoint() {
  KvStore p;
  return fry::kvGetStringGuarded<String>(nsExists, p, "fry_vpn", "wgEndpoint");  // no [E] for a missing namespace or key (T8)
}
void setWgEndpoint(const char* v) {
  KvStore p;
  p.begin("fry_vpn", false);
  p.putString("wgEndpoint", v);
  p.end();
}

uint32_t getWgPort() {
  if (!nsExists("fry_vpn")) return 51820;
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
  return fry::kvGetStringGuarded<String>(nsExists, p, "fry_vpn", "wgAddr");  // no [E] for a missing namespace or key (T8)
}
void setWgAddr(const char* v) {
  KvStore p;
  p.begin("fry_vpn", false);
  p.putString("wgAddr", v);
  p.end();
}

uint32_t getSocksPort() {
  if (!nsExists("fry_vpn")) return SOCKS5_PORT;
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

String getWgAllowed() {
  KvStore p;
  return fry::kvGetStringGuarded<String>(nsExists, p, "fry_vpn", "wgAllowed");  // no [E] when absent (T8)
}
void setWgAllowed(const char* csv) {
  KvStore p;
  p.begin("fry_vpn", false);
  p.putString("wgAllowed", csv);
  p.end();
}

uint32_t getWgKeepalive() {
  if (!nsExists("fry_vpn")) return 25;
  KvStore p;
  p.begin("fry_vpn", true);
  uint32_t v = p.getUInt("wgKeepalive", 25);
  p.end();
  return v;
}
void setWgKeepalive(uint32_t v) {
  KvStore p;
  p.begin("fry_vpn", false);
  p.putUInt("wgKeepalive", v);
  p.end();
}

uint32_t getWgProvAt() {
  if (!nsExists("fry_vpn")) return 0;
  KvStore p;
  p.begin("fry_vpn", true);
  uint32_t v = p.getUInt("wgProvAt", 0);
  p.end();
  return v;
}
void setWgProvAt(uint32_t epochS) {
  KvStore p;
  p.begin("fry_vpn", false);
  p.putUInt("wgProvAt", epochS);
  p.end();
}

void setWgKeypair(const char* priv, const char* pub) {
  KvStore p;
  p.begin("fry_vpn", false);
  p.putString("wgPriv", priv);
  p.putString("wgPub", pub);
  p.end();
}

#ifndef ESP8266
// Commit-in-progress marker (fry_wgrec/commit): the 8 fry_vpn writes of setWgProvisioned are not
// atomic, so a reset between them could leave old and new fields mixed under an old wgProvAt that
// the production gate trusts. The marker is written first and cleared last.
void setWgCommitMarker(bool on) {
  KvStore p;
  p.begin("fry_wgrec", false);
  if (on) p.putUChar("commit", 1); else p.remove("commit");
  p.end();
}
// On boot: a marker still set means the last commit was torn. Drop wgPeerPub and wgProvAt only, so
// the provisioning client POSTs again with the SAME keypair (wgPriv/wgPub stay) and writes a whole
// config. Returns true when a torn commit was found.
bool recoverTornWgCommit() {
  if (!nsExists("fry_wgrec")) return false;  // never written: nothing can be torn, and no flash write
  KvStore p;
  p.begin("fry_wgrec", true);
  const bool torn = p.isKey("commit");
  p.end();
  if (!torn) return false;
  KvStore v;
  v.begin("fry_vpn", false);
  v.remove("wgPeerPub");
  v.remove("wgProvAt");
  v.end();
  setWgCommitMarker(false);
  return true;
}
#endif

void setWgProvisioned(const char* peerPub, const char* psk, const char* endpointHost,
                      uint16_t endpointPort, const char* addrCidr, const char* allowedCsv,
                      uint32_t keepaliveS) {
#ifndef ESP8266
  setWgCommitMarker(true);  // first; cleared last. A marker still set at boot = an interrupted commit
#endif
  setWgPsk(psk);
  setWgEndpoint(endpointHost);
  setWgPort(endpointPort);
  setWgAddr(addrCidr);
  setWgAllowed(allowedCsv);
  setWgKeepalive(keepaliveS);
  setWgPeerPub(peerPub);  // hasVpnConfig()'s existing commit marker
  setWgProvAt(static_cast<uint32_t>(time(nullptr)));  // the new production-trust gate, written LAST
#ifndef ESP8266
  setWgCommitMarker(false);
#endif
}

#ifndef ESP8266
uint32_t getWgRecoverAt() {
  KvStore p;
  return fry::kvReadGuarded<uint32_t>(nsExists, p, "fry_wgrec", "at", 0, [](KvStore& s) { return s.getUInt("at", 0); });
}
void setWgRecoverAt(uint32_t epochS) {
  KvStore p;
  p.begin("fry_wgrec", false);
  p.putUInt("at", epochS);
  p.end();
}
bool getWgPendingKeypair(char priv[45], char pub[45]) {
  KvStore p;
  const bool has = fry::kvGetCStringGuarded(nsExists, p, "fry_wgrec", "pPriv", priv, 45) &&
                   fry::kvGetCStringGuarded(nsExists, p, "fry_wgrec", "pPub", pub, 45);
  return has && strlen(priv) == 44 && strlen(pub) == 44;
}
void setWgPendingKeypair(const char* priv, const char* pub) {
  KvStore p;
  p.begin("fry_wgrec", false);
  p.putString("pPriv", priv);
  p.putString("pPub", pub);
  p.end();
}
void clearWgPendingKeypair() {
  KvStore p;
  p.begin("fry_wgrec", false);
  p.remove("pPriv");
  p.remove("pPub");
  p.end();
}
// T7 migration state, own namespace fry_wgmig. Opened read-write even to read: a read-only open of
// a namespace that was never written logs an [E] nvs_open NOT_FOUND on every board's first boot.
void getWgMigVer(char* out, size_t outLen) {
  KvStore p;
  out[0] = 0;
  fry::kvGetCStringGuarded(nsExists, p, "fry_wgmig", "ver", out, outLen);
}
void setWgMigVer(const char* version) {
  KvStore p;
  p.begin("fry_wgmig", false);
  p.putString("ver", version);
  p.end();
}
uint32_t getWgMigTries() {
  KvStore p;
  return fry::kvReadGuarded<uint32_t>(nsExists, p, "fry_wgmig", "tries", 0, [](KvStore& s) { return s.getUInt("tries", 0); });
}
void setWgMigTries(uint32_t n) {
  KvStore p;
  p.begin("fry_wgmig", false);
  p.putUInt("tries", n);
  p.end();
}
#endif

bool hasVpnConfig() {
  if (!nsExists("fry_vpn")) return false;
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
  return fry::kvGetStringGuarded<String>(nsExists, p, "fry_ota", "pending");  // T8: no [E] for a missing namespace/key
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
  return fry::kvGetStringGuarded<String>(nsExists, p, "fry_ota", "url");  // T8: no [E] for a missing namespace/key
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
  return fry::kvReadGuarded<uint8_t>(nsExists, p, "fry_ota", "bootfails", 0, [](KvStore& s) { return s.getUChar("bootfails", 0); });
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

String getOtaBadVer() {
  KvStore p;
  return fry::kvGetStringGuarded<String>(nsExists, p, "fry_ota", "badver");  // T8: no [E] for a missing namespace/key
}
uint8_t getOtaBadN() {
  KvStore p;
  return fry::kvReadGuarded<uint8_t>(nsExists, p, "fry_ota", "badn", 0, [](KvStore& s) { return s.getUChar("badn", 0); });
}
void setOtaStrikes(const char* version, uint8_t strikes) {
  KvStore p;
  p.begin("fry_ota", false);
  if (version && version[0]) {
    p.putString("badver", version);
    p.putUChar("badn", strikes);
  } else {
    p.remove("badver");
    p.remove("badn");
  }
  p.end();
}

bool getOtaPlannedRestart() {
  KvStore p;
  return fry::kvReadGuarded<bool>(nsExists, p, "fry_ota", "planrst", false, [](KvStore& s) { return s.getBool("planrst", false); });
}
void setOtaPlannedRestart(bool planned) {
  KvStore p;
  p.begin("fry_ota", false);
  if (planned) {
    p.putBool("planrst", true);
  } else {
    p.remove("planrst");
  }
  p.end();
}

bool getOtaRolledBack() {
  KvStore p;
  return fry::kvReadGuarded<bool>(nsExists, p, "fry_ota", "rbk", false, [](KvStore& s) { return s.getBool("rbk", false); });
}
void setOtaRolledBack(bool rolledBack) {
  KvStore p;
  p.begin("fry_ota", false);
  if (rolledBack) {
    p.putBool("rbk", true);
  } else {
    p.remove("rbk");
  }
  p.end();
}

// ── factory reset ─────────────────────────────────────────────────────────

void factoryReset() {
  clearWifi();

  // fry namespace: remove wallet/provDone/installId/deviceToken but PRESERVE salt + minerKey.
  KvStore p;
  p.begin("fry", false);
  p.remove("wallet");
  p.remove("provDone");
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
