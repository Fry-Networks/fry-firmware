#pragma once
// Arduino-side wrapper around lib/fry_core/miner_identity.h: supplies the station MAC, generates
// and persists the one-time salt on first boot, and persists the derived miner key. The actual
// byte-exact algorithm lives in the pure lib/fry_core module (unit tested under -e native).
#include <Arduino.h>

namespace fry_identity {

// Reads the last 3 bytes of the station MAC address into mac6[3].
void getMac6(uint8_t mac6[3]);

// Returns the persisted miner key ("IOT-<32 hex>"), generating + persisting salt and key on
// first call if they do not exist yet. Never regenerates once persisted (PROTOCOL.md section 4).
// outKey must be at least 37 bytes.
void ensureMinerKey(char* outKey, size_t outKeyLen);

// "FRY-<CHIP>-<MAC6>" per PROTOCOL.md section 4. outName must be at least 32 bytes.
void getDeviceName(char* outName, size_t outNameLen);

}  // namespace fry_identity
