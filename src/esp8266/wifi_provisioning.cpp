// SoftAP + captive HTTP provisioning transport for ESP8266. PROTOCOL.md section 3.
#include "../core/provisioning_transport.h"

#include <DNSServer.h>
#include <ESP8266WebServer.h>
#include <ESP8266WiFi.h>

#include <cstdio>
#include <cstring>

#include "../core/fry_config.h"
#include "../core/miner_key.h"
#include "../core/status_snapshot.h"
#include "config.h"
#include "device_status.h"
#include "key_policy.h"
#include "provisioning_commit.h"

#ifndef FRY_FIRMWARE_VERSION
#define FRY_FIRMWARE_VERSION "0.0.0-dev"
#endif

namespace fry_provisioning {

namespace {

const int kMaxScanEntries = 24;

fry::ProvisioningFsm s_fsm;
ESP8266WebServer s_server(80);
DNSServer s_dns;
bool s_apActive = false;
unsigned long s_connectedAtMs = 0;
bool s_connectedAtMsSet = false;

char s_deviceName[32] = {0};
char s_apName[24] = {0};
// PROTOCOL.md section 11.6: a board WITHOUT a key runs a WPA2 AP whose passphrase (fry/apCode) is
// shown only over USB, so the key the owner types into /provision never crosses an open network.
// A board with a key keeps the open AP of v1 and refuses a key over it.
bool s_apSecure = false;
char s_apCode[9] = {0};

struct ScanEntry {
  String ssid;
  int32_t rssi;
  bool enc;
};
ScanEntry s_scanCache[kMaxScanEntries];
int s_scanCount = 0;

// <4KB, zero external resources — required by PROTOCOL.md section 3.
const char PORTAL_HTML[] PROGMEM = R"HTML(<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Fry Setup</title>
<style>body{font-family:sans-serif;max-width:420px;margin:24px auto;padding:0 16px}
input,select,button{width:100%;padding:8px;margin:6px 0;box-sizing:border-box}
button{background:#222;color:#fff;border:0;border-radius:4px;padding:10px}
#msg{margin-top:10px;font-weight:bold}</style></head><body>
<h2>Fry Device Setup</h2>
<div>Device: <span id="dn">...</span></div>
<div>Miner key: <span id="mk">...</span></div>
<input id="key" placeholder="Your miner key FEM-... (36 characters)" style="display:none">
<label>WiFi network</label>
<select id="ssidSel"><option value="">-- scan results --</option></select>
<input id="ssid" placeholder="SSID">
<input id="pass" type="password" placeholder="WiFi password (blank if open)">
<input id="wallet" placeholder="Algorand wallet address (58 chars)">
<button onclick="submitForm()">Connect</button>
<div id="msg"></div>
<script>
function scan(){fetch('/api/scan').then(function(r){return r.json();}).then(function(d){
 var s=document.getElementById('ssidSel');
 (d.nets||[]).forEach(function(n){var o=document.createElement('option');o.value=n.ssid;
  o.text=n.ssid+' ('+n.rssi+'dBm'+(n.enc?', locked':'')+')';s.appendChild(o);});
});}
document.getElementById('ssidSel').onchange=function(){document.getElementById('ssid').value=this.value;};
fetch('/info').then(function(r){return r.json();}).then(function(d){
 document.getElementById('dn').textContent=d.deviceName;
 document.getElementById('mk').textContent=d.keySet?d.minerKey:'not set - enter yours below';
 if(!d.keySet)document.getElementById('key').style.display='';});
scan();
function submitForm(){
 var b='ssid='+encodeURIComponent(document.getElementById('ssid').value)+
       '&pass='+encodeURIComponent(document.getElementById('pass').value)+
       '&wallet='+encodeURIComponent(document.getElementById('wallet').value);
 var k=document.getElementById('key').value.trim();if(k)b+='&key='+encodeURIComponent(k);
 document.getElementById('msg').textContent='Connecting...';
 fetch('/provision',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b})
 .then(function(r){return r.json();}).then(function(d){
   document.getElementById('msg').textContent=d.ok?'OK - joining WiFi, this page will stop responding':('Error: '+d.err);});
}
</script></body></html>)HTML";

void cacheScan() {
  int n = WiFi.scanNetworks(false, true);
  s_scanCount = 0;
  for (int i = 0; i < n && s_scanCount < kMaxScanEntries; i++) {
    s_scanCache[s_scanCount].ssid = WiFi.SSID(i);
    s_scanCache[s_scanCount].rssi = WiFi.RSSI(i);
    s_scanCache[s_scanCount].enc = WiFi.encryptionType(i) != ENC_TYPE_NONE;
    s_scanCount++;
  }
  WiFi.scanDelete();
}

void handleRoot() { s_server.send_P(200, "text/html", PORTAL_HTML); }

void handleInfo() {
  fry::DeviceStatus st;
  fry_status::snapshot(st);
  String out = "{\"deviceName\":\"";
  out += s_deviceName;
  out += "\",\"minerKey\":\"";
  out += st.keyMasked;  // never the whole key on an unauthenticated surface
  out += "\",\"fw\":\"" FRY_FIRMWARE_VERSION "\",\"chip\":\"ESP8266\",\"proto\":2,"
         "\"caps\":[\"key_write\",\"error_reset\",\"errs_v2\"],\"keySet\":";
  out += st.keySet ? "true" : "false";
  out += "}";
  s_server.send(200, "application/json; charset=utf-8", out);
}

void handleScan() {
  String out = "{\"nets\":[";
  for (int i = 0; i < s_scanCount; i++) {
    if (i) out += ",";
    out += "{\"ssid\":\"";
    out += s_scanCache[i].ssid;
    out += "\",\"rssi\":";
    out += String(s_scanCache[i].rssi);
    out += ",\"enc\":";
    out += (s_scanCache[i].enc ? "true" : "false");
    out += "}";
  }
  out += "]}";
  s_server.send(200, "application/json", out);
}

void sendProvisionError(int http, const char* reason) {
  String out = "{\"ok\":false,\"err\":\"";
  out += reason;
  out += "\",\"status\":";
  out += String(static_cast<unsigned>(s_fsm.state()));
  out += "}";
  s_server.send(http, "application/json", out);
}

// A refused key write: the FSM reports it (status 4, detail 7/8) and the response says which.
void refuseKey(fry::KeyWriteVerdict verdict) {
  fry::ProvInputs in;
  in.detail = fry::keyVerdictProvErr(verdict);
  s_fsm.feed(fry::ProvEvent::KeyRejected, in);
  if (verdict == fry::KeyWriteVerdict::BadKey) {
    sendProvisionError(400, "bad_key");
  } else if (verdict == fry::KeyWriteVerdict::NeedsSecureAp) {
    sendProvisionError(403, "key_needs_secure_ap");
  } else {
    sendProvisionError(403, "key_locked");
  }
}

void handleProvision() {
  // A join already in flight (or done) is not restarted from here; Error is not a dead end any
  // more: the SSID write below resets it (PROTOCOL.md section 11.2, error_reset).
  const fry::ProvState before = s_fsm.state();
  if (before == fry::ProvState::Connecting || before == fry::ProvState::Connected) {
    sendProvisionError(409, "busy");
    return;
  }

  String ssid = s_server.arg("ssid");
  String pass = s_server.arg("pass");
  String wallet = s_server.arg("wallet");
  String key = s_server.arg("key");  // byte-exact (C-1): the portal trims, the firmware never does

  fry::ProvInputs ssidIn;
  ssidIn.ssidValid = (ssid.length() >= 1 && ssid.length() <= 32);
  s_fsm.feed(fry::ProvEvent::SsidWritten, ssidIn);
  if (!ssidIn.ssidValid) {
    sendProvisionError(400, "bad_ssid");
    return;
  }

  fry::ProvInputs walletIn;
  walletIn.walletValid = (wallet.length() == 58);
  if (!walletIn.walletValid) {
    s_fsm.feed(fry::ProvEvent::WalletWritten, walletIn);  // -> Error / BadWallet
    sendProvisionError(400, "bad_wallet");
    return;
  }

  const fry::KeyTransport transport =
      s_apSecure ? fry::KeyTransport::SoftApSecure : fry::KeyTransport::SoftApOpen;
  if (key.length() > 0) {
    const fry::KeyWriteVerdict verdict = fry_identity::setOwnerKey(key.c_str(), transport, nullptr);
    if (verdict != fry::KeyWriteVerdict::Accept) {
      refuseKey(verdict);  // nothing persisted
      return;
    }
  } else {
    char stored[40] = {0};
    fry_identity::ensureMinerKey(stored, sizeof(stored));
    if (!fry::keyAllowsJoin(fry::kBuildKeyModel, stored[0] != 0)) {
      Serial.println("[prov] refused: no miner key - set it with the web setup page (USB) or app>=0.4");
      s_fsm.feed(fry::ProvEvent::KeyMissing, walletIn);
      sendProvisionError(422, "key_required");
      return;
    }
  }

  // Commit semantics per PROTOCOL.md section 1 (shared with BLE): the wallet write commits.
  fry::commitOnWallet(s_fsm, walletIn, [&]() {
    fry_config::setWifi(ssid.c_str(), pass.c_str());
    optimistic_yield(1000);  // feed the WDT — LittleFS-JSON writes plus JSON (re)serialization
    fry_config::setWallet(wallet.c_str());
    optimistic_yield(1000);
  });
  s_server.send(200, "application/json", "{\"ok\":true,\"status\":2}");
}

void handleStatus() {
  fry::DeviceStatus st;
  fry_status::snapshot(st);
  char buf[256];
  // "err" stays the v1 byte (0-5) for old clients; "detail" carries the v1.1 code.
  snprintf(buf, sizeof(buf),
           "{\"status\":%u,\"err\":%u,\"detail\":%u,\"minerKey\":\"%s\",\"keySet\":%s,\"reg\":%d,"
           "\"hb\":%ld,\"fw\":\"%s\",\"ota\":\"%s\",\"ip\":\"%s\"}",
           static_cast<unsigned>(st.state), static_cast<unsigned>(fry::statusLegacyErr(st)),
           static_cast<unsigned>(fry::statusDetailErr(st)), st.keyMasked, st.keySet ? "true" : "false",
           st.regHttp, static_cast<long>(st.hbAgeS), st.fw, st.ota,
           WiFi.localIP().toString().c_str());
  s_server.send(200, "application/json; charset=utf-8", buf);
}

void ensureApCode() {
  String code = fry_config::getApCode();
  if (code.length() == 8) {
    strncpy(s_apCode, code.c_str(), sizeof(s_apCode) - 1);
    return;
  }
  fry::makeSetupCode(ESP.random(), ESP.random(), s_apCode, sizeof(s_apCode));
  fry_config::setApCode(s_apCode);
}

void startAp() {
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  // Open without a key question to ask (matches the BLE-without-PIN trust model of v1); WPA2 with
  // the setup code while the owner still has to type a key in.
  WiFi.softAP(s_apName, s_apSecure ? s_apCode : nullptr);
  s_dns.setErrorReplyCode(DNSReplyCode::NoError);
  s_dns.start(53, "*", IPAddress(192, 168, 4, 1));
}

}  // namespace

void init(const char* deviceName, const char* minerKey) {
  strncpy(s_deviceName, deviceName, sizeof(s_deviceName) - 1);
  s_apSecure = !fry::keyAllowsJoin(fry::kBuildKeyModel, minerKey && minerKey[0]);
  if (s_apSecure) ensureApCode();

  // Pre-scan in STA mode BEFORE bringing the AP up — scanning after the AP starts is unreliable
  // on ESP8266 (the radio is already busy servicing the softAP).
  WiFi.mode(WIFI_STA);
  cacheScan();

  uint8_t mac[6];
  WiFi.macAddress(mac);
  snprintf(s_apName, sizeof(s_apName), "FRY-SETUP-%02X%02X%02X", mac[3], mac[4], mac[5]);

  startAp();
  s_apActive = true;

  s_server.on("/", HTTP_GET, handleRoot);
  s_server.on("/info", HTTP_GET, handleInfo);
  s_server.on("/api/scan", HTTP_GET, handleScan);
  s_server.on("/provision", HTTP_POST, handleProvision);
  s_server.on("/status", HTTP_GET, handleStatus);
  s_server.onNotFound(handleRoot);  // captive-portal catch-all
  s_server.begin();

  if (s_apSecure) {
    // The one place the setup code is shown besides Improv 0xF1: this is the USB serial log.
    Serial.printf("AP started %s ip=192.168.4.1 wpa2 setup-code=%s (no miner key yet)\n", s_apName,
                  s_apCode);
  } else {
    Serial.printf("AP started %s ip=192.168.4.1\n", s_apName);
  }
}

bool commitWifiOnlyCredentials(const char* ssid, const char* pass) {
  if (!ssid) return false;
  // See the ESP32 transport: an Improv client may retry after a failed join, so clear an Error
  // parked by the previous attempt. The captive portal's own path is untouched.
  if (s_fsm.state() == fry::ProvState::Error) {
    s_fsm.feed(fry::ProvEvent::Reset, {});
  }

  const size_t ssidLen = strlen(ssid);
  fry::ProvInputs in;
  in.ssidValid = (ssidLen >= 1 && ssidLen <= 32);
  s_fsm.feed(fry::ProvEvent::SsidWritten, in);
  if (!in.ssidValid) return false;

  fry::commitWifiOnly(s_fsm, [&]() {
    fry_config::setWifi(ssid, pass ? pass : "");
    optimistic_yield(1000);  // feed the WDT — the LittleFS-JSON store rewrites the whole file
    fry_config::setProvDone();
    optimistic_yield(1000);
  });
  return s_fsm.readyToConnect();
}

void loop() {
  if (s_apActive) {
    for (int i = 0; i < 8; i++) s_dns.processNextRequest();  // bounded — never blocks the loop
  }
  s_server.handleClient();
}

fry::ProvState state() { return s_fsm.state(); }
fry::ProvErr lastError() { return s_fsm.error(); }
bool readyToConnect() { return s_fsm.readyToConnect(); }

void notifyWifiUp() {
  s_fsm.feed(fry::ProvEvent::WifiUp, {});
}
// fry_wifi::connect() drops the softAP to join as a station. When that join fails the board goes
// back to AwaitingProvisioning, where the portal is the only way to reach it - bring it back.
void restoreApAfterFailedJoin() {
  if (!s_apActive || (WiFi.getMode() & WIFI_AP)) return;
  startAp();
  Serial.printf("AP restarted %s after the failed join - /provision accepts a new attempt\n", s_apName);
}

void notifyWifiAuthFail() {
  s_fsm.feed(fry::ProvEvent::WifiAuthFail, {});
  restoreApAfterFailedJoin();
}
void notifyWifiNoIp() {
  s_fsm.feed(fry::ProvEvent::WifiNoIp, {});
  restoreApAfterFailedJoin();
}
void notifyApiOk() {
  if (s_fsm.feed(fry::ProvEvent::ApiOk, {}) && s_fsm.state() == fry::ProvState::Connected) {
    s_connectedAtMs = millis();
    s_connectedAtMsSet = true;
  }
}
void notifyApiFail(fry::ProvErr detail) {
  fry::ProvInputs in;
  in.detail = detail;
  s_fsm.feed(fry::ProvEvent::ApiFail, in);
}
void notifyKeyMissing() {
  s_fsm.feed(fry::ProvEvent::KeyMissing, {});
}

void tick() {
  if (s_apActive && s_connectedAtMsSet && (millis() - s_connectedAtMs) >= AP_TEARDOWN_MS) {
    s_dns.stop();
    WiFi.softAPdisconnect(true);
    s_apActive = false;
    Serial.println("AP torn down (status=3, teardown window elapsed)");
  }
}

}  // namespace fry_provisioning
