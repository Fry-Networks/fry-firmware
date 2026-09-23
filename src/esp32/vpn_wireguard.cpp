// WireGuard VPN endpoint for ESP32/S3/C3, using droscy/esp_wireguard (verified Arduino-usable:
// plain extern "C" API over lwIP's netif, library.json declares "frameworks": ["espidf",
// "arduino"], and esp_wireguard_connect() does NOT install the WG interface as the default route
// on its own — esp_wireguard_set_default() is a separate, deliberate call that this file never
// makes, satisfying the "must not kill the relay" constraint).
#include "../core/vpn_relay.h"

#include <WiFi.h>
#include <esp_wireguard.h>
#include <lwip/opt.h>

#include <cstring>

#include "../core/fry_config.h"
#include "../core/hardwareapi_client.h"
#include "socks5_parse.h"
#include "wg_provision.h"
#include "wg_provision_client.h"

#if IP_NAPT
#include <lwip/lwip_napt.h>
#endif

// esp_wireguard 0.4.5 defaults WIREGUARD_MAX_SRC_IPS to 1 (wireguard-platform.h), filled
// unconditionally with the device's OWN tunnel /32. That leaves zero room for a route back to
// the server's own tunnel IP, so every reply the server sends gets ERR_RTE: the handshake
// reports "up" but no data ever crosses (seen on the bench as a live tunnel that never answers a
// ping). [esp32common] in platformio.ini raises this to 4 - one slot for the device's own /32
// (which esp_wireguard always fills) plus lib/fry_core/wg_provision.h's kWgMaxPlannedRoutes (3).
// This is a compile-time check that the flag actually landed, not just a runtime assumption.
#ifndef CONFIG_WIREGUARD_MAX_SRC_IPS
#error "CONFIG_WIREGUARD_MAX_SRC_IPS is unset - see the comment above and [esp32common] in platformio.ini"
#elif CONFIG_WIREGUARD_MAX_SRC_IPS != 4
#error "CONFIG_WIREGUARD_MAX_SRC_IPS must be exactly 4 - see the comment above"
#endif

namespace fry_vpn {

namespace {

wireguard_config_t s_wgConfig;
wireguard_ctx_t s_wgCtx;
bool s_initialized = false;
bool s_wasUp = false;
volatile uint32_t s_relayedBytes = 0;

// Config strings must outlive the wireguard_config_t (esp_wireguard keeps the pointers, does
// not copy them), so these are file-scope statics rather than locals in init().
String s_priv, s_pub, s_psk, s_addr, s_netmask, s_endpoint;

#if !IP_NAPT
// Fallback when this build's lwIP has no NAPT compiled in. This is not a build-flag choice we
// could flip — it is structurally impossible on this framework, confirmed two independent ways
// (v0.2.0):
//   1. `CONFIG_LWIP_IP_FORWARD is not set` in the baked sdkconfig for every ESP32-family chip
//      this project targets (esp32, esp32c3, esp32s2, esp32s3 — framework-arduinoespressif32's
//      tools/sdk/<chip>/sdkconfig), which is what lwipopts.h's IP_NAPT macro (CONFIG_LWIP_IPV4_NAPT)
//      ultimately gates.
//   2. A byte scan of the prebuilt tools/sdk/esp32/lib/liblwip.a shows the NAPT symbols
//      themselves — ip_napt_enable, ip_napt_init, ip4_napt_forward — are ALL ABSENT (zero
//      matches). lwip_napt.h ships as a header, but the corresponding .c was never compiled into
//      this static library, so no #define or build_flag on our side can turn NAPT on; it would
//      need a rebuilt liblwip.a, which is outside this firmware repo.
// Since transparent IP-level NAT isn't possible, this runs a "simple in-tunnel TCP forwarder": a
// SOCKS5 CONNECT relay (the same
// tested parser as the ESP8266 endpoint) on its own FreeRTOS task so it can block on socket I/O
// without stalling the main loop(). A tunnel peer that knows the device's WG address can reach
// this relay and ask it to CONNECT out via the STA uplink — a reduced-scope substitute for full
// transparent NAT, not a general-purpose router.
void relayTaskFn(void*) {
  uint16_t port = static_cast<uint16_t>(fry_config::getSocksPort());
  WiFiServer server(port);
  server.begin();
  Serial.printf("socks5: listening :%u\n", port);

  for (;;) {
    WiFiClient client = server.accept();
    if (!client) {
      vTaskDelay(pdMS_TO_TICKS(50));
      continue;
    }

    uint8_t buf[262];
    size_t bufLen = 0;
    bool greeted = false;
    unsigned long start = millis();
    while (client.connected() && millis() - start < 5000) {
      if (client.available()) {
        int n = client.read(buf + bufLen, sizeof(buf) - bufLen);
        if (n > 0) bufLen += n;
      }
      fry::Socks5Greeting greeting;
      size_t consumed = 0;
      fry::Socks5Result r = fry::parseGreeting(buf, bufLen, greeting, consumed);
      if (r == fry::Socks5Result::Ok) {
        uint8_t ok[2] = {0x05, 0x00};
        client.write(ok, 2);
        bufLen = 0;
        greeted = true;
        break;
      } else if (r != fry::Socks5Result::NeedMoreData) {
        uint8_t fail[2] = {0x05, 0xFF};
        client.write(fail, 2);
        break;
      }
      vTaskDelay(pdMS_TO_TICKS(10));
    }
    if (!greeted) {
      client.stop();
      continue;
    }

    WiFiClient upstream;
    bool connected = false;
    start = millis();
    while (client.connected() && millis() - start < 5000) {
      if (client.available()) {
        int n = client.read(buf + bufLen, sizeof(buf) - bufLen);
        if (n > 0) bufLen += n;
      }
      fry::Socks5ConnectRequest req;
      size_t consumed = 0;
      fry::Socks5Result r = fry::parseConnectRequest(buf, bufLen, req, consumed);
      if (r == fry::Socks5Result::Ok) {
        connected = upstream.connect(req.host, req.port);
        uint8_t reply[10] = {0x05, static_cast<uint8_t>(connected ? 0x00 : 0x01), 0x00, 0x01,
                              0, 0, 0, 0, 0, 0};
        client.write(reply, sizeof(reply));
        break;
      } else if (r != fry::Socks5Result::NeedMoreData) {
        uint8_t reply[10] = {0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        client.write(reply, sizeof(reply));
        break;
      }
      vTaskDelay(pdMS_TO_TICKS(10));
    }

    if (connected) {
      uint8_t copyBuf[512];
      unsigned long lastActivity = millis();
      while (client.connected() && upstream.connected() && (millis() - lastActivity) < 30000) {
        bool activity = false;
        int avail = client.available();
        if (avail > 0) {
          int n = client.read(copyBuf, avail > 512 ? 512 : avail);
          if (n > 0) {
            upstream.write(copyBuf, n);
            s_relayedBytes += n;
            activity = true;
          }
        }
        avail = upstream.available();
        if (avail > 0) {
          int n = upstream.read(copyBuf, avail > 512 ? 512 : avail);
          if (n > 0) {
            client.write(copyBuf, n);
            s_relayedBytes += n;
            activity = true;
          }
        }
        if (activity) {
          lastActivity = millis();
        } else {
          vTaskDelay(pdMS_TO_TICKS(5));
        }
      }
      upstream.stop();
    }
    client.stop();
  }
}
#endif  // !IP_NAPT

}  // namespace

// esp_wireguard_connect() returns ESP_ERR_RETRY (0x201) while the endpoint's asynchronous
// DNS resolution is still in flight. It is an advisory to call again, not a failure - the
// library starts a second resolution itself in case the first ran too early. Treating it as
// fatal is why the tunnel never came up (seen as: wg: connect failed err=513).
static constexpr int      WG_CONNECT_ATTEMPTS = 10;
static constexpr uint32_t WG_CONNECT_RETRY_MS = 500;

// How often tick() retries loadConfig()+bringUp() while neither has succeeded yet (e.g. NTP
// isn't synced yet at boot, or the fetch client hasn't provisioned a config yet). This governs
// only the LOCAL esp_wireguard bring-up attempt, which has no HTTP-style failure to classify;
// the network FETCH itself (src/esp32/wg_provision_client.cpp) uses
// lib/fry_core/wg_provision.h's classifyWgFetch/wgRetryDelayMs schedule instead.
static constexpr unsigned long WG_BRINGUP_RETRY_MS = 5000;

namespace {
bool s_initAttempted = false;  // esp_wireguard_init() must never be called more than once ever
unsigned long s_lastBringUpAttemptMs = 0;
}  // namespace

// True once a config exists AND this build trusts it. Production ESP32 builds only trust a
// SERVER-provisioned config (wgProvAt != 0, set by wg_provision_client.cpp after a successful
// POST); FRY_SERIAL_PROVISION lab builds keep trusting whatever the `set_wg` serial command
// wrote, exactly as before this change (wgProvAt is never set on that path).
bool provisioningGateOpen() {
#ifdef FRY_SERIAL_PROVISION
  return true;
#else
  return fry_config::getWgProvAt() != 0;
#endif
}

// Loads the persisted config into the file-scope String/wgConfig fields. Returns false (and logs
// exactly the historical message) when no config is stored yet at all.
bool loadConfig() {
  s_priv = fry_config::getWgPriv();
  s_pub = fry_config::getWgPeerPub();
  s_psk = fry_config::getWgPsk();
  s_addr = fry_config::getWgAddr();  // e.g. "10.13.13.2/24"
  s_endpoint = fry_config::getWgEndpoint();

  if (s_priv.length() == 0 || s_pub.length() == 0 || s_endpoint.length() == 0) {
    Serial.println("wg: no VPN config - skipping");
    return false;
  }

  uint32_t addrIp;
  int addrPrefix;
  char netmaskBuf[16];
  if (fry::parseIpv4Cidr(s_addr.c_str(), &addrIp, &addrPrefix) &&
      fry::formatIpv4(fry::prefixToMask(addrPrefix), netmaskBuf, sizeof(netmaskBuf)) > 0) {
    s_netmask = netmaskBuf;
  } else {
    // Historical fallback: the lab `set_wg` serial command has always required a literal
    // "/24" address (serial_commands.cpp's cmdSetWg rejects anything else), so a config
    // written before this change - or any value that fails to parse - keeps behaving exactly
    // as it always did rather than failing closed.
    s_netmask = "255.255.255.0";
  }
  int slash = s_addr.indexOf('/');
  s_addr = (slash >= 0) ? s_addr.substring(0, slash) : s_addr;
  return true;
}

// Applies lib/fry_core/wg_provision.h's planned route list (persisted as a `;`-joined CIDR
// string) via esp_wireguard_add_allowed_ip, once the tunnel is up. This is the runtime half of
// the WIREGUARD_MAX_SRC_IPS fix - the build-time half is the static_assert-equivalent #error
// block above requiring CONFIG_WIREGUARD_MAX_SRC_IPS == 4.
void applyAllowedIps() {
  String csv = fry_config::getWgAllowed();
  int start = 0;
  while (start <= static_cast<int>(csv.length())) {
    int sep = csv.indexOf(';', start);
    String entry = (sep < 0) ? csv.substring(start) : csv.substring(start, sep);
    if (entry.length() > 0) {
      uint32_t ip;
      int prefix;
      if (fry::parseIpv4Cidr(entry.c_str(), &ip, &prefix)) {
        char ipStr[16];
        char maskStr[16];
        fry::formatIpv4(ip, ipStr, sizeof(ipStr));
        fry::formatIpv4(fry::prefixToMask(prefix), maskStr, sizeof(maskStr));
        esp_err_t err = esp_wireguard_add_allowed_ip(&s_wgCtx, ipStr, maskStr);
        Serial.printf("wg: allowed-ip %s/%s %s\n", ipStr, maskStr,
                      err == ESP_OK ? "ok" : "FAILED");
      }
    }
    if (sep < 0) break;
    start = sep + 1;
  }
}

// The actual esp_wireguard init/connect. Safe to call repeatedly while it keeps failing (NTP not
// synced yet, or a transient connect failure) - esp_wireguard_init() itself only ever runs once
// per boot, guarded by s_initAttempted, per the "never init twice" rule.
bool bringUp() {
  // A WireGuard handshake with an unset clock cannot succeed, so honour the result rather
  // than discarding it - proceeding would spend the retry budget on a misleading error.
  if (!fry_hwapi::ensureNtpSynced()) {  // PROTOCOL.md / T6
    Serial.println("wg: NTP not synced - skipping handshake");
    return false;
  }

  memset(&s_wgConfig, 0, sizeof(s_wgConfig));
  s_wgConfig.private_key = s_priv.c_str();
  s_wgConfig.public_key = s_pub.c_str();
  s_wgConfig.preshared_key = s_psk.length() ? s_psk.c_str() : nullptr;
  s_wgConfig.address = s_addr.c_str();
  s_wgConfig.netmask = s_netmask.c_str();
  s_wgConfig.endpoint = s_endpoint.c_str();
  s_wgConfig.port = static_cast<uint16_t>(fry_config::getWgPort());
  s_wgConfig.persistent_keepalive = static_cast<uint16_t>(fry_config::getWgKeepalive());

  esp_err_t err;
  if (!s_initAttempted) {
    s_initAttempted = true;
    err = esp_wireguard_init(&s_wgConfig, &s_wgCtx);
    if (err != ESP_OK) {
      Serial.printf("wg: init failed err=%d\n", static_cast<int>(err));
      return false;
    }
  }
  for (int attempt = 1; attempt <= WG_CONNECT_ATTEMPTS; ++attempt) {
    err = esp_wireguard_connect(&s_wgCtx);
    if (err != ESP_ERR_RETRY) break;  // success, or a real failure worth reporting
    Serial.printf("wg: endpoint DNS pending, retry %d/%d\n", attempt, WG_CONNECT_ATTEMPTS);
    delay(WG_CONNECT_RETRY_MS);
  }
  if (err != ESP_OK) {
    Serial.printf("wg: connect failed err=%d\n", static_cast<int>(err));
    return false;
  }
  // Deliberately NEVER call esp_wireguard_set_default(&s_wgCtx) — that would make the WG
  // interface the default route and kill this device's own STA-routed traffic (T6 constraint).
  s_initialized = true;
  applyAllowedIps();

#if IP_NAPT
  ip_addr_t staIp = {};
  staIp.type = IPADDR_TYPE_V4;
  staIp.u_addr.ip4.addr = static_cast<uint32_t>(WiFi.localIP());
  ip_napt_enable(staIp, 1);
  Serial.println("wg: NAPT enabled");
#else
  Serial.println("wg: NAPT not compiled into this framework's liblwip.a (CONFIG_LWIP_IP_FORWARD "
                  "unset) - falling back to the SOCKS5 tunnel-only relay");
  xTaskCreate(relayTaskFn, "fry_relay", 4096, nullptr, 1, nullptr);
#endif
  return true;
}

void init() {
  if (!loadConfig()) return;
  if (!provisioningGateOpen()) {
    Serial.println("wg: config present but not yet server-provisioned - deferring bring-up");
    return;  // tick() retries once the fetch client (or, in a lab build, `set_wg`) commits one
  }
  bringUp();
}

void tick() {
  if (!s_initialized) {
#ifndef FRY_SERIAL_PROVISION
    // Drives its own retry/backoff schedule (lib/fry_core/wg_provision.h's
    // classifyWgFetch/wgRetryDelayMs); a no-op once a config already exists. Lab builds skip
    // this entirely - they only ever get a config from the `set_wg` serial command.
    fry_wg_provision::tick();
#endif
    unsigned long now = millis();
    if (now - s_lastBringUpAttemptMs < WG_BRINGUP_RETRY_MS) return;
    s_lastBringUpAttemptMs = now;
    if (!loadConfig()) return;
    if (!provisioningGateOpen()) return;
    bringUp();
    return;
  }
  bool up = (esp_wireguard_peer_is_up(&s_wgCtx) == ESP_OK);
  if (up && !s_wasUp) {
    char pub8[9] = {0};
    strncpy(pub8, s_wgConfig.public_key, 8);
    Serial.printf("wg: handshake ok peer=%s endpoint=%s:%u\n", pub8, s_wgConfig.endpoint,
                  s_wgConfig.port);
  }
  s_wasUp = up;
}

bool isUp() { return s_initialized && s_wasUp; }
uint32_t relayedBytes() { return s_relayedBytes; }

}  // namespace fry_vpn

extern "C" void fry_trigger_start_vpn() { fry_vpn::init(); }
