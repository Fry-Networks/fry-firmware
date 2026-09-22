#pragma once
// Pure C++ implementation of PROTOCOL.md section 4 (Identity): device name grammar and the
// miner-key derivation. Zero Arduino includes so it is unit-testable under `pio test -e native`.
// The Arduino-side wrapper (src/core/miner_key.*) supplies the MAC bytes, the persisted salt,
// and NVS storage; this module only implements the byte-exact algorithm.
#include <cstddef>
#include <cstdint>

namespace fry {

// SHA256(mac6 || salt) truncated to 16 bytes, hex-encoded uppercase and prefixed "FEM-".
// outKey must be at least 37 bytes ("FEM-" + 32 hex chars + NUL).
//
// The prefix was "IOT-" until 2026-09-18. There is now a single key namespace: every device
// is FEM-, whatever the board or OS. The product type is carried by the miner CODE
// (FRY_MINER_CODE, still "IOTVPN" for these boards), which is independent of the key prefix.
// Note this only affects devices that have never generated a key — ensureMinerKey persists
// on first call and never regenerates, so an existing board keeps whatever prefix it was
// born with until its stored identity is cleared.
void computeMinerKey(const uint8_t mac6[3], const uint8_t salt[16], char* outKey, size_t outKeyLen);

// ^FEM-[0-9A-F]{32}$ — exact length and character class, case-sensitive.
bool isValidMinerKey(const char* key);

// ^IOT-[0-9A-Fa-f]{32}$ — a key generated before the 2026-09-18 prefix change. Accepts either
// hex case because that is what boards in the field actually hold; isValidMinerKey stays strict.
bool isLegacyMinerKey(const char* key);

// Rewrites a legacy "IOT-<hex>" key as "FEM-<same hex>", preserving the hex digits exactly
// (case included) so the device keeps its identity — only the namespace prefix changes.
// Returns false, leaving `out` untouched, for anything that is not a legacy key and for
// outLen < 37 ("FEM-" + 32 hex chars + NUL). Idempotent by refusal: migrating an already
// migrated key returns false.
bool migrateLegacyMinerKey(const char* in, char* out, size_t outLen);

// "FRY-<chipTag>-<MAC6 as 6 uppercase hex chars>". chipTag is one of
// "ESP8266" | "ESP32" | "ESP32-S3" | "ESP32-C3". outName must be at least 32 bytes.
void formatDeviceName(const char* chipTag, const uint8_t mac6[3], char* outName, size_t outNameLen);

// ^FRY-(ESP8266|ESP32|ESP32-S3|ESP32-C3)-[0-9A-F]{6}$
bool isValidDeviceName(const char* name);

}  // namespace fry
