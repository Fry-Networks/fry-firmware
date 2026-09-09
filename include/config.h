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

// Minimum LARGEST-CONTIGUOUS-BLOCK gate before attempting an OTA download over the non-MFLN
// BearSSL path (src/esp8266/http_tls.cpp), which allocates one 16384-byte rx + 512-byte tx
// buffer as a single iobuf. HEAP_GATE_OTA (total free heap) is not sufficient on its own: a
// board can show plenty of *total* free heap while it is fragmented into blocks too small for
// that allocation. Field evidence: a board with 42,712 B free and a 34,152-byte largest block
// passed the 20,000 B total-free gate, allocated the 16 KB buffer, and still died — the 34 KB
// block wasn't enough once BearSSL's session/certificate scratch space and lwIP's receive pbufs
// were also carved out of it during the handshake. ~2x the 16384-byte buffer (34-37 KB) matches
// the same "double the raw TLS buffer" rule of thumb already used for this exact BearSSL
// configuration in the sibling sensmos-firmware project (see its MONITORS_HTTP_MIN_HEAP / "TLS
// wymaga ~34KB CIAGLEGO bloku" comment), rounded up past the 34,152 B block that still crashed.
#ifndef HEAP_GATE_OTA_BLOCK
#define HEAP_GATE_OTA_BLOCK 36864
#endif
