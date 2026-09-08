#pragma once
// Fry firmware — compile-time defaults. Every constant is #ifndef-guarded so a
// board-specific build_flags override (-D<NAME>=<value>) always wins over this file.

// PoC (proof-of-connectivity) report cadence to hardwareapi.
#ifndef POC_INTERVAL_MS
#define POC_INTERVAL_MS 600000UL          // 10 min
#endif

// Installation heartbeat (POST .../installations/{miner_key}/installations/{install_id}).
#ifndef INSTALL_HEARTBEAT_MS
#define INSTALL_HEARTBEAT_MS 3600000UL    // 1 h
#endif

// hardwareapi lease duration, seconds (see PROTOCOL.md section 5).
#ifndef LEASE_SECONDS
#define LEASE_SECONDS 900
#endif

// OTA manifest poll interval.
#ifndef OTA_CHECK_MS
#define OTA_CHECK_MS 21600000UL           // 6 h
#endif

// WiFi station connect timeout before falling back to provisioning / retry.
#ifndef WIFI_CONNECT_TIMEOUT_MS
#define WIFI_CONNECT_TIMEOUT_MS 20000UL
#endif

// SoftAP (ESP8266 captive portal) teardown delay after status reaches Connected (3).
#ifndef AP_TEARDOWN_MS
#define AP_TEARDOWN_MS 10000UL
#endif

// [health] log line cadence.
#ifndef HEALTH_LOG_MS
#define HEALTH_LOG_MS 30000UL
#endif

// Consecutive post-OTA boots without a confirmed-good marker before rollback triggers.
#ifndef OTA_BOOT_FAIL_LIMIT
#define OTA_BOOT_FAIL_LIMIT 3
#endif

// ESP8266 SOCKS5 relay listen port.
#ifndef SOCKS5_PORT
#define SOCKS5_PORT 1080
#endif

// Minimum free-heap gate before attempting a TLS handshake (bytes).
#ifndef HEAP_GATE_TLS
#define HEAP_GATE_TLS 15000
#endif

// Minimum free-heap gate before attempting an OTA download (bytes).
#ifndef HEAP_GATE_OTA
#define HEAP_GATE_OTA 20000
#endif
