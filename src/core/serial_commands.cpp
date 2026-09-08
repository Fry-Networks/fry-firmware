#include "serial_commands.h"

#ifdef FRY_SERIAL_PROVISION

#include <ArduinoJson.h>

#include <cstring>

#include "config.h"
#include "fry_config.h"
#include "miner_key.h"

#ifndef FRY_FIRMWARE_VERSION
#define FRY_FIRMWARE_VERSION "0.0.0-dev"
#endif
#ifndef FRY_CHIP
#define FRY_CHIP "UNKNOWN"
#endif

// Implemented by the hardwareapi client (T5) and the OTA module (T7) respectively. Weakly
// defined here so this file — and any *_lab build that predates those modules — still links;
// a later TU providing a strong (non-weak) definition overrides these at link time.
extern "C" __attribute__((weak)) void fry_trigger_poc_now() {
  Serial.println("[serial] poc_now: hardwareapi client not built yet");
}
extern "C" __attribute__((weak)) void fry_trigger_ota_now() {
  Serial.println("[serial] ota_now: OTA module not built yet");
}

namespace {

String s_lineBuf;

// A redacted count is printed instead of the actual secret, e.g. "<12 chars>".
String redactedLen(const char* s) {
  char buf[24];
  snprintf(buf, sizeof(buf), "<%u chars>", s ? static_cast<unsigned>(strlen(s)) : 0);
  return String(buf);
}

void respond(const char* status, const char* cmd, const String& extraJson = "") {
  String out = "{\"status\":\"";
  out += status;
  out += "\",\"cmd\":\"";
  out += cmd;
  out += "\"";
  if (extraJson.length()) {
    out += ",";
    out += extraJson;
  }
  out += "}";
  Serial.print("[serial] ");
  Serial.println(out);
}

void respondError(const char* cmd, const char* reason) {
  String extra = "\"reason\":\"";
  extra += reason;
  extra += "\"";
  respond("error", cmd, extra);
}

void cmdSetWifi(JsonDocument& doc) {
  const char* ssid = doc["ssid"] | "";
  const char* pass = doc["password"] | "";
  if (strlen(ssid) == 0 || strlen(ssid) > 32) {
    respondError("set_wifi", "bad_ssid");
    return;
  }
  fry_config::setWifi(ssid, pass);
  Serial.printf("[serial] set_wifi: ssid='%s' password=%s\n", ssid, redactedLen(pass).c_str());
  respond("ok", "set_wifi");
}

void cmdSetWallet(JsonDocument& doc) {
  const char* addr = doc["addr"] | "";
  if (strlen(addr) != 58) {
    respondError("set_wallet", "bad_wallet_length");
    return;
  }
  fry_config::setWallet(addr);
  respond("ok", "set_wallet");
}

void cmdSetWg(JsonDocument& doc) {
  const char* endpoint = doc["endpoint"] | "";
  const char* peerPub = doc["peer_pub"] | "";
  const char* priv = doc["priv"] | "";
  const char* psk = doc["psk"] | "";
  const char* addr = doc["addr"] | "";

  if (strlen(endpoint) == 0 || strlen(peerPub) == 0 || strlen(priv) == 0) {
    respondError("set_wg", "missing_field");
    return;
  }
  // psk is REQUIRED: linuxserver/wireguard writes a PresharedKey into every peer config.
  if (strlen(psk) == 0) {
    respondError("set_wg", "psk_required");
    return;
  }
  // addr must be a /24, never /32 — with /32 the NAT return path never re-enters the tunnel.
  const char* slash = strchr(addr, '/');
  if (!slash || strcmp(slash, "/24") != 0) {
    respondError("set_wg", "addr_must_be_slash24");
    return;
  }

  fry_config::setWgEndpoint(endpoint);
  fry_config::setWgPeerPub(peerPub);
  fry_config::setWgPriv(priv);
  fry_config::setWgPsk(psk);
  fry_config::setWgAddr(addr);
  Serial.printf("[serial] set_wg: endpoint='%s' peer_pub=%s priv=%s psk=%s addr='%s'\n", endpoint,
                redactedLen(peerPub).c_str(), redactedLen(priv).c_str(), redactedLen(psk).c_str(), addr);
  respond("ok", "set_wg");
}

void cmdSetOtaUrl(JsonDocument& doc) {
  const char* url = doc["url"] | "";
  fry_config::setOtaUrl(url);  // empty string restores the compiled default
  respond("ok", "set_ota_url");
}

void cmdOtaNow() {
  respond("ok", "ota_now");
  fry_trigger_ota_now();
}

void cmdPocNow() {
  respond("ok", "poc_now");
  fry_trigger_poc_now();
}

void cmdGetInfo() {
  char minerKey[40] = "";
  fry_identity::ensureMinerKey(minerKey, sizeof(minerKey));
  char deviceName[32] = "";
  fry_identity::getDeviceName(deviceName, sizeof(deviceName));
  String wallet = fry_config::getWallet();

  String extra = "\"minerKey\":\"";
  extra += minerKey;
  extra += "\",\"deviceName\":\"";
  extra += deviceName;
  extra += "\",\"wallet\":\"";
  extra += wallet;
  extra += "\",\"chip\":\"" FRY_CHIP "\",\"firmware\":\"" FRY_FIRMWARE_VERSION "\"";
  respond("ok", "get_info", extra);
}

void cmdFactoryReset() {
  // Preserves fry/salt and fry/minerKey per PROTOCOL.md section 7.
  fry_config::factoryReset();
  respond("ok", "factory_reset");
}

void dispatch(const String& line) {
  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, line);
  if (err) {
    respondError("unknown", "bad_json");
    return;
  }
  const char* cmd = doc["cmd"] | "";
  if (!strcmp(cmd, "set_wifi")) {
    cmdSetWifi(doc);
  } else if (!strcmp(cmd, "set_wallet")) {
    cmdSetWallet(doc);
  } else if (!strcmp(cmd, "set_wg")) {
    cmdSetWg(doc);
  } else if (!strcmp(cmd, "set_ota_url")) {
    cmdSetOtaUrl(doc);
  } else if (!strcmp(cmd, "ota_now")) {
    cmdOtaNow();
  } else if (!strcmp(cmd, "poc_now")) {
    cmdPocNow();
  } else if (!strcmp(cmd, "get_info")) {
    cmdGetInfo();
  } else if (!strcmp(cmd, "factory_reset")) {
    cmdFactoryReset();
  } else {
    respondError("unknown", "unknown_cmd");
  }
}

}  // namespace

void fry_serial_init() {
  s_lineBuf.reserve(256);
  Serial.println("[serial] ready");
}

void fry_serial_poll() {
  while (Serial.available()) {
    char c = static_cast<char>(Serial.read());
    if (c == '\n') {
      s_lineBuf.trim();
      if (s_lineBuf.length() > 0) dispatch(s_lineBuf);
      s_lineBuf = "";
    } else if (c != '\r') {
      if (s_lineBuf.length() < 512) s_lineBuf += c;  // bounded — never grows unbounded on garbage
    }
  }
}

#endif  // FRY_SERIAL_PROVISION
