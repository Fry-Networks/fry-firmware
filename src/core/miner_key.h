#pragma once
// Arduino-side wrapper around lib/fry_core/miner_identity.h: supplies the station MAC, generates
// and persists the one-time salt on first boot, and persists the derived miner key. The actual
// byte-exact algorithm lives in the pure lib/fry_core module (unit tested under -e native).
#include <Arduino.h>

#include "key_policy.h"

namespace fry_identity {

// Reads the last 3 bytes of the station MAC address into mac6[3].
void getMac6(uint8_t mac6[3]);

// Returns the persisted miner key, migrating a legacy IOT- prefix in place. With no stored key a
// DEVICE_KEEPS build generates + persists salt and key (PROTOCOL.md section 4); a USER_SUPPLIED
// build (the default, lib/fry_core/key_policy.h) returns "" and logs once that it is waiting for
// the owner's key. Never replaces a stored key. outKey must be at least 37 bytes.
void ensureMinerKey(char* outKey, size_t outKeyLen);

// The policy verdict for writing `key` over `transport`, without writing anything.
fry::KeyWriteVerdict checkOwnerKey(const char* key, fry::KeyTransport transport);

// Validates and persists an owner-supplied key (PROTOCOL.md section 11.1), reading it back through
// a fresh store handle. When it differs from the stored key the old installation is dropped
// (fry/installId, fry/deviceToken, fry_vpn) and the key is marked keySrc=user, keyOk=false.
// Returns Accept once the key is stored (or was already the stored one); *changed, if given, says
// whether it differs from before.
fry::KeyWriteVerdict setOwnerKey(const char* key, fry::KeyTransport transport, bool* changed);

// "FRY-<CHIP>-<MAC6>" per PROTOCOL.md section 4. outName must be at least 32 bytes.
void getDeviceName(char* outName, size_t outNameLen);

// Returns the persisted hardwareapi install_id (fry.installId), generating a random 32-hex-char
// identifier and persisting it on first call. Never regenerates once persisted — a new install_id
// would orphan the installation record on hardwareapi. outId must be at least 33 bytes.
void ensureInstallId(char* outId, size_t outIdLen);

}  // namespace fry_identity
