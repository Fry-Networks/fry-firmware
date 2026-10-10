// WireGuard VPN endpoint for ESP32/S3/C3, using droscy/esp_wireguard (verified Arduino-usable:
// plain extern "C" API over lwIP's netif, library.json declares "frameworks": ["espidf",
// "arduino"], and esp_wireguard_connect() does NOT install the WG interface as the default route
// on its own — esp_wireguard_set_default() is a separate, deliberate call that this file never
// makes, satisfying the "must not kill the relay" constraint).
#include "../core/vpn_relay.h"

#include <WiFi.h>
#include <esp_wireguard.h>
#include <freertos/semphr.h>
#include <lwip/opt.h>
#include <lwip/tcpip.h>

#include <cstring>
#include <ctime>

#include "../core/fry_config.h"
#include "../core/hardwareapi_client.h"
#include "../core/ota_client.h"
#include "../core/wifi_station.h"
#include "dest_filter.h"
#include "kv_guard.h"
#include "socks5_parse.h"
#include "wg_provision.h"
#include "wg_provision_client.h"
#include "wg_recover.h"
#include "wg_recover2.h"

#ifndef FRY_FIRMWARE_VERSION
#define FRY_FIRMWARE_VERSION "0.0.0-dev"
#endif

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
bool s_relayStarted = false;  // the SOCKS5 task must start once; bringUp() can now run again
volatile uint32_t s_relayedBytes = 0;

// Config strings must outlive the wireguard_config_t (esp_wireguard keeps the pointers, does
// not copy them), so these are file-scope statics rather than locals in init().
String s_priv, s_pub, s_psk, s_addr, s_netmask, s_endpoint;

uint32_t ipToHostOrder(const IPAddress& ip) {
  return (static_cast<uint32_t>(ip[0]) << 24) | (static_cast<uint32_t>(ip[1]) << 16) |
         (static_cast<uint32_t>(ip[2]) << 8) | static_cast<uint32_t>(ip[3]);
}
fry::DestCtx relayDestCtx() {
  fry::DestCtx c;
  c.selfIp = ipToHostOrder(WiFi.localIP());
  c.selfMask = ipToHostOrder(WiFi.subnetMask());
  c.gateway = ipToHostOrder(WiFi.gatewayIP());
  return c;
}

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
        // Destination filter (lib/fry_core/dest_filter.h). The host is ALWAYS reduced to one IPv4
        // address first, that address is checked, and the connect goes to THAT address, never to
        // the host string (lwIP would read "012.0.0.1" as octal 10.0.0.1). Non-canonical numeric
        // forms come back blocked. 0x02 = not allowed by ruleset, 0x04 = host unreachable (DNS).
        uint32_t dst = 0;
        bool haveIp = false;
        bool dnsFailed = false;
        bool literal = false;
        const fry::DestCtx ctx = relayDestCtx();
        bool allowed = fry::destFilterText(req.host, ctx, &literal);
        if (literal) {
          haveIp = allowed && fry::destParseV4(req.host, &dst);  // an IPv6 literal cannot be dialled here
        } else {
          IPAddress resolved;
          if (WiFi.hostByName(req.host, resolved) == 1) {
            dst = ipToHostOrder(resolved);
            haveIp = fry::destFilterV4(dst, ctx);
          } else {
            dnsFailed = true;
          }
        }
        if (haveIp) {
          connected = upstream.connect(IPAddress(dst >> 24, (dst >> 16) & 0xFF, (dst >> 8) & 0xFF, dst & 0xFF), req.port);
        } else if (!dnsFailed) {
          Serial.printf("socks5: destination blocked (blocked=%u allowed=%u)\n",
                        static_cast<unsigned>(fry::destCounters().blocked),
                        static_cast<unsigned>(fry::destCounters().allowed));
        }
        uint8_t reply[10] = {0x05, static_cast<uint8_t>(connected ? 0x00 : (dnsFailed ? 0x04 : (haveIp ? 0x01 : 0x02))),
                              0x00, 0x01, 0, 0, 0, 0, 0, 0};
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

// Dead-tunnel recovery (lib/fry_core/wg_recover.h). RAM-only; the stage-B rate limit is the
// persisted fry_wgrec/at stamp.
fry::WgRecover2 s_recover;
fry::WgTrial s_trial;                         // T3: a refreshed config on trial until it handshakes
fry_wg_provision::PendingConfig s_trialCfg;   // RAM-only; the old config stays in NVS meanwhile
bool s_migActive = false;                     // T7: a post-OTA endpoint refresh is still owed
uint32_t s_migTries = 0;
fry::OnceFlag s_noConfigLog;
bool s_recovering = false;     // stage A tore the tunnel down and it has not been up since
bool s_stageAPending = false;  // waiting for bringUp() to report whether the endpoint IP changed
uint32_t s_stageAOldIp = 0;

// True when the next bringUp() must start from a NEW netif: esp_wireguard_connect() builds the
// netif (and bakes the private key into it) only while ctx->netif == NULL, and a failed connect
// leaves the old one behind. Set by both stages, cleared once teardown has completed.
bool s_freshNetifRequired = false;

// esp_wireguard_disconnect() runs netif_remove/udp_remove/wireguardif_fini/sys_untimeout, which
// the WG timers and UDP input in the tcpip thread race with (wireguardif.c wireguardif_shutdown).
// CONFIG_LWIP_TCPIP_CORE_LOCKING is NOT set in this framework's sdkconfig for esp32/esp32c3
// (tools/sdk/<chip>/sdkconfig), so LOCK_TCPIP_CORE() expands to nothing and cannot be used.
// tcpip_callback() (lwip/tcpip.h) posts the call to the tcpip thread regardless of that flag; the
// loop task blocks on a semaphore until it ran, so no other code touches the netif meanwhile.
SemaphoreHandle_t s_teardownDone = nullptr;
void teardownInTcpipThread(void*) {
  // A stalled tcpip thread can queue two callbacks; the second finds the netif already gone, and
  // esp_wireguard_disconnect(netif_set_ipaddr) would dereference NULL.
  if (s_wgCtx.netif != nullptr) esp_wireguard_disconnect(&s_wgCtx);
  xSemaphoreGive(s_teardownDone);
}
bool runTeardownInTcpipThread() {
  if (s_teardownDone == nullptr) s_teardownDone = xSemaphoreCreateBinary();
  if (s_teardownDone == nullptr) return false;
  xSemaphoreTake(s_teardownDone, 0);  // drop a stale give from an earlier timed-out attempt
  if (tcpip_callback(teardownInTcpipThread, nullptr) != ERR_OK) return false;
  return xSemaphoreTake(s_teardownDone, pdMS_TO_TICKS(3000)) == pdTRUE;
}

class TunnelOps : public fry::WgTunnelOps {
 public:
  bool hasNetif() override { return s_wgCtx.netif != nullptr; }
  bool teardown() override { return runTeardownInTcpipThread(); }
};

// Tears down iff a netif exists (keyed on the netif, not on s_initialized). False = still pending.
bool settleTeardown() {
  TunnelOps ops;
  if (!fry::wgTearDownTunnel(ops)) {
    Serial.println("wg: teardown pending - will retry");
    return false;
  }
  s_freshNetifRequired = false;
  return true;
}

// Persisted stage-B attempt stamp (fry_wgrec/at), cached in RAM after the first read: reading a
// namespace that was never written logs an nvs_open NOT_FOUND error, so it must not run per tick.
// If the NVS write fails the cached value still rate-limits for this boot (RAM fallback).
bool s_stampLoaded = false;
uint32_t s_stampCache = 0;
uint32_t recoverStamp() {
  if (!s_stampLoaded) {
    s_stampCache = fry_config::getWgRecoverAt();
    s_stampLoaded = true;
  }
  return s_stampCache;
}
void setRecoverStamp(uint32_t epochS) {
  fry_config::setWgRecoverAt(epochS);
  s_stampCache = epochS;
  s_stampLoaded = true;
  if (fry_config::getWgRecoverAt() != epochS) {
    Serial.println("wg: recover stamp NOT persisted - rate limit is RAM-only this boot");
  }
}
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
  s_priv = fry_config::getWgPriv();  // the keypair is never replaced, trial or not
  if (s_trial.active()) {
    s_pub = s_trialCfg.serverPub;
    s_psk = s_trialCfg.hasPsk ? s_trialCfg.psk : "";
    s_addr = s_trialCfg.addressCidr;
    s_endpoint = s_trialCfg.endpointHost;
  } else {
    s_pub = fry_config::getWgPeerPub();
    s_psk = fry_config::getWgPsk();
    s_addr = fry_config::getWgAddr();  // e.g. "10.13.13.2/24"
    s_endpoint = fry_config::getWgEndpoint();
  }

  if (s_priv.length() == 0 || s_pub.length() == 0 || s_endpoint.length() == 0) {
    if (s_noConfigLog.first()) {  // T8: an expected state, one INFO line per boot
      Serial.println("wg: no VPN config - skipping");
    }
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
  String csv = s_trial.active() ? String(s_trialCfg.allowedCsv) : fry_config::getWgAllowed();
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
  if (s_freshNetifRequired && !settleTeardown()) return false;
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
  s_wgConfig.port = static_cast<uint16_t>(s_trial.active() ? s_trialCfg.endpointPort : fry_config::getWgPort());
  s_wgConfig.persistent_keepalive = static_cast<uint16_t>(s_trial.active() ? s_trialCfg.keepaliveS : fry_config::getWgKeepalive());

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
  if (s_stageAPending) {
    s_stageAPending = false;
    bool changed = s_wgConfig.endpoint_ip.u_addr.ip4.addr != s_stageAOldIp;
    Serial.printf("wg: recover A re-resolved endpoint, ip %s\n", changed ? "changed" : "unchanged");
    s_recover.onReResolved(changed, millis());
  }

#if IP_NAPT
  ip_addr_t staIp = {};
  staIp.type = IPADDR_TYPE_V4;
  staIp.u_addr.ip4.addr = static_cast<uint32_t>(WiFi.localIP());
  ip_napt_enable(staIp, 1);
  Serial.println("wg: NAPT enabled");
#else
  Serial.println("wg: NAPT not compiled into this framework's liblwip.a (CONFIG_LWIP_IP_FORWARD "
                  "unset) - falling back to the SOCKS5 tunnel-only relay");
  if (!s_relayStarted) {
    s_relayStarted = true;
    xTaskCreate(relayTaskFn, "fry_relay", 4096, nullptr, 1, nullptr);
  }
#endif
  return true;
}

#ifndef FRY_SERIAL_PROVISION
static constexpr unsigned long WG_RECOVER_TICK_MS = 5000;

// The provisioning host (T1 gate): can DNS answer for it right now? Cached for 30 s and only asked
// once the tunnel has been down for the dead threshold, so a down tunnel costs at most one
// bounded lookup per 30 s.
bool apiHostResolves(unsigned long nowMs) {
  static unsigned long checkedMs = 0;
  static bool cached = false;
  if (checkedMs != 0 && nowMs - checkedMs < 30000) return cached;
  checkedMs = nowMs ? nowMs : 1;
  String base = fry_config::getApiBase();  // https://host[:port][/path]
  int h = base.indexOf("://");
  String host = h >= 0 ? base.substring(h + 3) : base;
  int cut = host.indexOf('/');
  if (cut >= 0) host = host.substring(0, cut);
  cut = host.indexOf(':');
  if (cut >= 0) host = host.substring(0, cut);
  IPAddress ip;
  cached = host.length() > 0 && WiFi.hostByName(host.c_str(), ip) == 1;
  return cached;
}

// Runs every tick (initialized or not). Lab builds are excluded: their config comes from the
// `set_wg` serial command and cannot be re-provisioned by the server.
void recoverTick() {
  static unsigned long lastMs = 0;
  static unsigned long downSinceMs = 0;
  unsigned long nowMs = millis();
  if (nowMs - lastMs < WG_RECOVER_TICK_MS) return;  // the NVS reads below are not loop()-cheap
  lastMs = nowMs;

  const bool up =
      s_initialized && s_wgCtx.netif != nullptr && esp_wireguard_peer_is_up(&s_wgCtx) == ESP_OK;
  if (up) s_recovering = false;

  // T3: a refreshed config runs as a trial. It is persisted only after it handshakes; if it never
  // does, the old config is reloaded and the T5 backoff applies.
  if (s_trial.active()) {
    switch (s_trial.tick(up, nowMs, fry_wifi::isConnected())) {
      case fry::WgTrialEvent::Commit:
        fry_wg_provision::commitPending(s_trialCfg);
        Serial.println("wg: recover trial handshook - new config persisted");
        if (s_migActive) {
          s_migActive = false;
          fry_config::setWgMigVer(FRY_FIRMWARE_VERSION);
          fry_config::setWgMigTries(0);
          Serial.println("wg: migration done - endpoint refreshed after the update");
        }
        break;
      case fry::WgTrialEvent::Rollback:
        Serial.println("wg: recover trial did not handshake - old config restored, backing off");
        fry_wg_provision::noteTrialFailed();
        s_recovering = true;
        s_freshNetifRequired = true;
        s_initialized = false;  // tick() reloads the persisted config and brings it up
        s_wasUp = false;
        settleTeardown();
        break;
      case fry::WgTrialEvent::None:
        break;
    }
    return;
  }

  fry::WgRecover2Input in;
  in.armed = s_initialized || s_recovering;
  in.up = up;
  in.wifiUp = fry_wifi::isConnected();
  in.nowMs = nowMs;
  if (in.armed && in.wifiUp && !up) {
    if (downSinceMs == 0) downSinceMs = nowMs ? nowMs : 1;
  } else {
    downSinceMs = 0;
  }
  if ((in.armed && !up) || s_migActive) {  // the rest only matters while down or a migration is owed
    in.hostnameEndpoint = fry::wgEndpointIsHostname(fry_config::getWgEndpoint().c_str());
    // An image that is PENDING_VERIFY (settling after an OTA: ota_client.cpp s_confirmPending,
    // reported by imageStateName) or an unconsumed fry_ota/pending flag means an update is in
    // flight. checkNow()'s download itself is synchronous inside loop(), so it cannot overlap.
    in.otaBusy = strcmp(fry_ota::imageStateName(), "pending") == 0 ||
                 fry_config::getOtaPending().length() > 0;
    in.clockSynced = fry_hwapi::ensureNtpSynced(/*timeoutMs=*/1);
    in.provBlocked = fry_wg_provision::backoffActive();
    in.hostResolves = (downSinceMs != 0 && nowMs - downSinceMs >= fry::kWg2DeadAfterS * 1000UL)
                          ? apiHostResolves(nowMs)
                          : true;
    in.jitterS = fry::wgRecoverJitterS(ESP.getEfuseMac());
    if (in.jitterS > fry::kWg2JitterMaxS) in.jitterS = in.jitterS % (fry::kWg2JitterMaxS + 1);
    in.epochNow = static_cast<uint32_t>(time(nullptr));
    in.lastStageBEpoch = recoverStamp();
  }

  fry::WgRecoverAction act = s_recover.decide(in);
  bool fromMigration = false;
  // T7: one refresh owed after an OTA. Same gates as stage B plus a boot-settling delay; the T5
  // backoff paces failures and the persisted attempt counter bounds them (24, then give up).
  if (act == fry::WgRecoverAction::None && s_migActive && in.wifiUp && in.clockSynced &&
      !in.provBlocked && !in.otaBusy && nowMs > 60000UL &&
      (in.lastStageBEpoch == 0 || in.epochNow < in.lastStageBEpoch ||
       in.epochNow - in.lastStageBEpoch >= fry::kWg2StageBFloorS)) {
    fry::WgMigrationInput mi;
    char lastVer[16] = {0};
    fry_config::getWgMigVer(lastVer, sizeof(lastVer));
    mi.lastVer = lastVer;
    mi.curVer = FRY_FIRMWARE_VERSION;
    mi.hasConfig = true;
    mi.rawIpEndpoint = !in.hostnameEndpoint;
    mi.tries = s_migTries;
    fry::WgMigrationAction ma = fry::wgMigrationDecide(mi);
    if (ma == fry::WgMigrationAction::GiveUp) {
      s_migActive = false;
      fry_config::setWgMigVer(FRY_FIRMWARE_VERSION);
      fry_config::setWgMigTries(0);
      Serial.printf("wg: migration gave up after %u attempts\n", static_cast<unsigned>(s_migTries));
    } else if (ma == fry::WgMigrationAction::RecordVersion) {
      s_migActive = false;
      fry_config::setWgMigVer(FRY_FIRMWARE_VERSION);
    } else if (ma == fry::WgMigrationAction::Refresh) {
      s_migTries++;
      fry_config::setWgMigTries(s_migTries);  // persisted BEFORE the attempt: a reboot loop is bounded
      act = fry::WgRecoverAction::ReProvision;
      fromMigration = true;
    }
  }

  switch (act) {
    case fry::WgRecoverAction::None:
      return;
    case fry::WgRecoverAction::ReResolve:
      Serial.println("wg: recover A - no handshake, re-resolving endpoint");
      s_stageAOldIp = s_wgConfig.endpoint_ip.u_addr.ip4.addr;
      s_stageAPending = true;
      s_recovering = true;
      s_freshNetifRequired = true;
      s_initialized = false;  // tick() now retries loadConfig()+bringUp(), which re-resolves
      s_wasUp = false;
      settleTeardown();       // a failed teardown is retried by bringUp() via the flag
      return;
    case fry::WgRecoverAction::ReProvision:
      Serial.printf("wg: recover B - %s, re-provisioning with the same keypair\n",
                    fromMigration ? "post-update endpoint refresh" : "no handshake");
      setRecoverStamp(in.epochNow);  // persisted BEFORE the attempt: a crash never loops
      fry_wg_provision::requestRotation();
      fry_wg_provision::tick();  // one bounded blocking POST (8 s), like the boot-time provisioning call
      if (fry_wg_provision::rotationState() != fry::WgRotationState::Committed ||
          !fry_wg_provision::takePending(s_trialCfg)) {
        Serial.println("wg: recover B failed - old config kept, tunnel untouched");
        return;
      }
      Serial.println("wg: recover B response validated - trialling the new config, old one kept");
      s_trial.begin(millis());
      s_recovering = true;
      s_stageAPending = false;
      s_freshNetifRequired = true;
      s_initialized = false;
      s_wasUp = false;
      settleTeardown();
      return;
  }
}
#endif

void init() {
#ifndef FRY_SERIAL_PROVISION
  if (fry_config::recoverTornWgCommit()) {
    Serial.println("wg: interrupted config commit found - dropping the peer key, re-provisioning with the same keypair");
  }
#endif
  if (!loadConfig()) return;
#ifndef FRY_SERIAL_PROVISION
  // T7: the first boot after an OTA owes ONE endpoint refresh when the cached endpoint is a raw IP.
  {
    fry::WgMigrationInput mi;
    char lastVer[16] = {0};
    fry_config::getWgMigVer(lastVer, sizeof(lastVer));
    mi.lastVer = lastVer;
    mi.curVer = FRY_FIRMWARE_VERSION;
    mi.hasConfig = true;
    mi.rawIpEndpoint = !fry::wgEndpointIsHostname(s_endpoint.c_str());
    s_migTries = fry_config::getWgMigTries();
    mi.tries = s_migTries;
    switch (fry::wgMigrationDecide(mi)) {
      case fry::WgMigrationAction::None:
        break;
      case fry::WgMigrationAction::RecordVersion:
        fry_config::setWgMigVer(FRY_FIRMWARE_VERSION);
        fry_config::setWgMigTries(0);
        break;
      case fry::WgMigrationAction::Refresh:
        s_migActive = true;
        Serial.println("wg: first boot after an update with a raw-IP endpoint - one refresh owed");
        break;
      case fry::WgMigrationAction::GiveUp:
        fry_config::setWgMigVer(FRY_FIRMWARE_VERSION);
        Serial.printf("wg: migration gave up after %u attempts\n", static_cast<unsigned>(s_migTries));
        break;
    }
  }
#endif
  if (!provisioningGateOpen()) {
    Serial.println("wg: config present but not yet server-provisioned - deferring bring-up");
    return;  // tick() retries once the fetch client (or, in a lab build, `set_wg`) commits one
  }
  bringUp();
}

void tick() {
#ifndef FRY_SERIAL_PROVISION
  recoverTick();
#endif
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
  bool up = (s_wgCtx.netif != nullptr && esp_wireguard_peer_is_up(&s_wgCtx) == ESP_OK);
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
