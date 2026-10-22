#pragma once
// ESP8266 OTA heap budget: what the HTTPS manifest check was MEASURED to need, and the gate derived from it.
//
// The gate used to be 36864 / 20000, a number from field crashes on a 16384/512 session (include/config.h). The check no
// longer opens that session (lib/fry_core/tls_sizing.h, Medium 8192/512), so its need was measured again on the bench:
// the real 3-hop GitHub chain (github.com -> github.com -> release-assets.githubusercontent.com) on esp8266_heapsweep_med,
// with the heap forced to a chosen LARGEST FREE BLOCK after the TLS clients exist ("post-constructor"), 3 attempts each:
//
//   post-ctor blk   free    result
//   29176           29344   PASS 1/1  (unforced)
//   23992           24160   PASS 3/3
//   21992           22160   PASS 3/3
//   19992           20160   PASS 3/3
//   18992           19160   PASS 3/3
//   17992           18160   FAIL -1 x2, CRASH x1   (sweep stopped here)
//
// Lines: lo/c1-c2a-123102.lines.txt and lo/c1-c2b-123905.lines.txt of the esp6 run. The need is therefore in (17992, 18992]
// post-ctor blk; the upper bound is used. The crash is `Unhandled C++ exception: OOM`, last failed alloc 1496 B at
// BearSSL::WiFiClientSecureCtx::_installClientX509Validator()+0x2f: core's throwing make_shared<br_x509_insecure_context>
// (the same call site and size as the 16384/512 sweep's reset cause 2) - the core panics on a failed `new`, nothing in
// this firmware can turn that into an error return, so the gate has to keep the heap out of that band.
//
// The gate samples BEFORE the clients exist (checkNow()), the sweep forced the heap AFTER, so the gate is the need plus the
// safety margin plus what the constructors then take: BearSSL's stack thunk (the first WiFiClientSecure mallocs 6200 B,
// 6208 in the allocator) and the clients block (<= kOtaClientsBytes, static_assert'ed in ota_client.cpp).
//
// ESP8266 and host only. The ESP32 family has no BearSSL thunk and keeps include/config.h's HEAP_GATE_OTA(_BLOCK).
#if !defined(ARDUINO) || defined(ARDUINO_ARCH_ESP8266)

#include <cstdint>

#include "tls_sizing.h"

namespace fry {
namespace ota_heap {

// Headroom over the measured need. Not a measurement: the gate SAMPLES the heap, it does not reserve it, and everything
// that allocates between the sample and the handshake (lwIP pbufs, the JSON of the previous request, a WiFi event) eats
// into it.
constexpr uint32_t kMarginBytes = 4096;

// Manifest check, Medium 8192/512 session, post-constructor (the table above).
constexpr uint32_t kManifestPassBlk = 18992;   // lowest forced largest free block that passed 3/3
constexpr uint32_t kManifestPassFree = 19160;  // total free at that point
constexpr uint32_t kManifestFailBlk = 17992;   // first forced block that failed (FAIL -1 x2, CRASH x1)
constexpr uint32_t kManifestNeedBlk = kManifestPassBlk;
constexpr uint32_t kManifestNeedFree = kManifestPassFree;

// What the constructors take between the gate's sample and the handshake.
constexpr uint32_t kCtorBytes = kBearsslStackThunkBytes + kOtaClientsBytes;

// The gate, in the units checkNow() samples (heap before the clients exist). 29808 / 29976.
constexpr uint32_t kManifestGateBlock = kManifestNeedBlk + kMarginBytes + kCtorBytes;
constexpr uint32_t kManifestGateFree = kManifestNeedFree + kMarginBytes + kCtorBytes;

// Image download, Big 16384/512 session (release-assets.githubusercontent.com sends 16400 B application records for the
// body: host probe c1/tools/record_sizes.py, c1/logs/record-sizes-asset.log - 34 of 60 records over 16384 - so no smaller
// receive buffer can carry it; the manifest's Medium buffer cannot). Measured by sweep C (lo/c1-c9-115327.lines.txt,
// lo/c1-c9b-120136.lines.txt, 05ffb66 tree + trace, the same 3-hop GitHub chain with every hop on 16384/512), post-ctor:
//
//   post-ctor blk   free    result
//   28912           29528   PASS 1/1  (unforced)
//   27992           28608   PASS 3/3
//   25992           26608   PASS 1/3, CRASH 2/3 (reset cause 4, OOM panic)
//   23992           24368   CRASH (reset cause 2)
//
// The download's own chain has one hop fewer than the manifest's (github.com -> release-assets), so the 3-hop figure is an
// upper bound on its need. The stack thunk is normally already held when downloadAndApply() runs (checkNow()'s manifest
// clients are still alive), so its begin-time sample is "post-constructor" in exactly the sweep's sense.
constexpr uint32_t kDownloadPassBlk = 27992;   // lowest forced largest free block that passed 3/3
constexpr uint32_t kDownloadPassFree = 28608;  // total free at that point
constexpr uint32_t kDownloadFailBlk = 25992;   // PASS 1/3, CRASH 2/3
constexpr uint32_t kDownloadNeedBlk = kDownloadPassBlk;
constexpr uint32_t kDownloadNeedFree = kDownloadPassFree;
// In the same pre-constructor units as the manifest gate; beginHttpsUrl() sees them through tlsFloorsAtBegin().
constexpr uint32_t kDownloadGateBlock = kDownloadNeedBlk + kMarginBytes + kCtorBytes;  // 38808
constexpr uint32_t kDownloadGateFree = kDownloadNeedFree + kMarginBytes + kCtorBytes;  // 39424

// After the connect: BearSSL's contexts and its 16 KB input buffer are ALREADY allocated, so a contiguous-block gate
// there (the old 36864) measures a heap this session itself just consumed and can never pass. What streaming still
// allocates is its own 1024 B buffer (new(nothrow) in downloadAndApply) and the Updater's buffer (new(nothrow), 4096 B when
// more than 8192 B are free, else 256 B): both fail cleanly, nothing there reaches the OOM panic. Need = 1024 + 256.
constexpr uint32_t kStreamNeedBytes = 1024 + 256;
constexpr uint32_t kStreamGateFree = kStreamNeedBytes + kMarginBytes;  // 5376

static_assert(kManifestFailBlk < kManifestPassBlk, "the sweep fails below it and passes at it");
static_assert(kDownloadFailBlk < kDownloadPassBlk, "the sweep fails below it and passes at it");
static_assert(kDownloadGateBlock >= kDownloadPassBlk + kMarginBytes + kBearsslStackThunkBytes, "gate below need + margin");
static_assert(kManifestGateBlock >= kManifestPassBlk + kMarginBytes + kBearsslStackThunkBytes, "gate below need + margin");

}  // namespace ota_heap
}  // namespace fry

#endif  // !ARDUINO || ARDUINO_ARCH_ESP8266
