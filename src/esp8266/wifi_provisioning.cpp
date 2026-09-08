// SoftAP + captive HTTP provisioning transport for ESP8266. PROTOCOL.md section 3.
#include "../core/provisioning_transport.h"

#include <DNSServer.h>
#include <ESP8266WebServer.h>
#include <ESP8266WiFi.h>

#include <cstdio>
#include <cstring>

#include "../core/fry_config.h"
#include "config.h"

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
char s_minerKey[40] = {0};

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
 document.getElementById('dn').textContent=d.deviceName;document.getElementById('mk').textContent=d.minerKey;});
scan();
function submitForm(){
 var b='ssid='+encodeURIComponent(document.getElementById('ssid').value)+
       '&pass='+encodeURIComponent(document.getElementById('pass').value)+
       '&wallet='+encodeURIComponent(document.getElementById('wallet').value);
 document.getElementById('msg').textContent='Connecting...';
 fetch('/provision',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b})
 .then(function(r){return r.json();}).then(function(d){
   document.getElementById('msg').textContent=d.ok?'OK - check status':('Error: '+d.err);});
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
  String out = "{\"deviceName\":\"";
  out += s_deviceName;
  out += "\",\"minerKey\":\"";
  out += s_minerKey;
  out += "\",\"fw\":\"" FRY_FIRMWARE_VERSION "\",\"chip\":\"ESP8266\"}";
  s_server.send(200, "application/json", out);
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

void sendProvisionError(const char* reason) {
  String out = "{\"ok\":false,\"err\":\"";
  out += reason;
  out += "\"}";
  s_server.send(400, "application/json", out);
}

void handleProvision() {
  String ssid = s_server.arg("ssid");
  String pass = s_server.arg("pass");
  String wallet = s_server.arg("wallet");

  fry::ProvInputs ssidIn;
  ssidIn.ssidValid = (ssid.length() >= 1 && ssid.length() <= 32);
  s_fsm.feed(fry::ProvEvent::SsidWritten, ssidIn);
  if (!ssidIn.ssidValid) {
    sendProvisionError("bad_ssid");
    return;
  }

  fry::ProvInputs walletIn;
  walletIn.walletValid = (wallet.length() == 58);
  bool changed = s_fsm.feed(fry::ProvEvent::WalletWritten, walletIn);
  if (!walletIn.walletValid) {
    sendProvisionError("bad_wallet");
    return;
  }

  if (changed && s_fsm.state() == fry::ProvState::Connecting) {
    // Commit semantics per PROTOCOL.md section 1 (shared with BLE): the wallet write commits.
    fry_config::setWifi(ssid.c_str(), pass.c_str());
    optimistic_yield(1000);  // feed the WDT — LittleFS-JSON writes plus JSON (re)serialization
    fry_config::setWallet(wallet.c_str());
    optimistic_yield(1000);
  }
  s_server.send(200, "application/json", "{\"ok\":true}");
}

void handleStatus() {
  char buf[128];
  uint8_t err = (s_fsm.state() == fry::ProvState::Error) ? static_cast<uint8_t>(s_fsm.error()) : 0;
  snprintf(buf, sizeof(buf), "{\"status\":%u,\"err\":%u,\"minerKey\":\"%s\",\"ip\":\"%s\"}",
           static_cast<unsigned>(s_fsm.state()), static_cast<unsigned>(err), s_minerKey,
           WiFi.localIP().toString().c_str());
  s_server.send(200, "application/json", buf);
}

}  // namespace

void init(const char* deviceName, const char* minerKey) {
  strncpy(s_deviceName, deviceName, sizeof(s_deviceName) - 1);
  strncpy(s_minerKey, minerKey, sizeof(s_minerKey) - 1);

  // Pre-scan in STA mode BEFORE bringing the AP up — scanning after the AP starts is unreliable
  // on ESP8266 (the radio is already busy servicing the softAP).
  WiFi.mode(WIFI_STA);
  cacheScan();

  char apName[24];
  uint8_t mac[6];
  WiFi.macAddress(mac);
  snprintf(apName, sizeof(apName), "FRY-SETUP-%02X%02X%02X", mac[3], mac[4], mac[5]);

  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  WiFi.softAP(apName);  // open network, matches the peripheral trust model of BLE-without-PIN

  s_dns.setErrorReplyCode(DNSReplyCode::NoError);
  s_dns.start(53, "*", IPAddress(192, 168, 4, 1));
  s_apActive = true;

  s_server.on("/", HTTP_GET, handleRoot);
  s_server.on("/info", HTTP_GET, handleInfo);
  s_server.on("/api/scan", HTTP_GET, handleScan);
  s_server.on("/provision", HTTP_POST, handleProvision);
  s_server.on("/status", HTTP_GET, handleStatus);
  s_server.onNotFound(handleRoot);  // captive-portal catch-all
  s_server.begin();

  Serial.printf("AP started %s ip=192.168.4.1\n", apName);
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
void notifyWifiAuthFail() {
  s_fsm.feed(fry::ProvEvent::WifiAuthFail, {});
}
void notifyWifiNoIp() {
  s_fsm.feed(fry::ProvEvent::WifiNoIp, {});
}
void notifyApiOk() {
  if (s_fsm.feed(fry::ProvEvent::ApiOk, {}) && s_fsm.state() == fry::ProvState::Connected) {
    s_connectedAtMs = millis();
    s_connectedAtMsSet = true;
  }
}
void notifyApiFail() {
  s_fsm.feed(fry::ProvEvent::ApiFail, {});
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
