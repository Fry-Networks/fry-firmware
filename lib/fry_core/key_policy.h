#pragma once
// Miner-key policy (PROTOCOL.md section 11.1): which key a board runs on, which keys an owner may
// write, and over which transport. Pure C++ with zero Arduino includes so `pio test -e native`
// covers every rule; src/core/miner_key.cpp supplies the storage and the transport.
//
// Two models, chosen at compile time with -DFRY_KEY_MODEL (platformio.ini [embedded]):
//   1 USER_SUPPLIED (default) - the owner brings the FEM- key they already hold (dashboard or FEM
//     PC) and writes it over USB, BLE or the WPA2 setup AP. A board without one waits; it never
//     mints its own.
//   0 DEVICE_KEEPS - the pre-0.4 behaviour: the board mints FEM-<hex> on first boot and refuses
//     every write.
// Either way a board that already holds a key keeps it: fielded boards are never re-keyed by an
// update.
#include <cstddef>
#include <cstdint>

#include "provisioning_fsm.h"

#ifndef FRY_KEY_MODEL
#define FRY_KEY_MODEL 1
#endif

namespace fry {

enum class KeyModel : uint8_t {
  DeviceKeeps = 0,
  UserSupplied = 1,
};

constexpr KeyModel kBuildKeyModel = (FRY_KEY_MODEL) ? KeyModel::UserSupplied : KeyModel::DeviceKeeps;

// ^FEM-[A-Za-z0-9]{32}$, byte-exact and case-sensitive - the write-path validator. It is wider
// than isValidMinerKey (uppercase hex only, still what this firmware mints) because the dashboard
// mints base36 keys and migrated boards hold lowercase hex. Nothing is trimmed or case-folded.
bool isAcceptableOwnerKey(const char* key);

enum class BootKeyAction : uint8_t {
  Keep,           // run on the stored key as it is
  MigrateLegacy,  // IOT-<hex> -> FEM-<same hex>, then keep
  Mint,           // DEVICE_KEEPS only: generate and persist a key
  Wait,           // USER_SUPPLIED only: no key until the owner writes one
  Recover,        // round 2: re-derive the key this board minted, from its surviving salt
};

// What the boot sequence does with the stored key. `present` is whether one is stored at all; an
// empty stored value counts as none. A stored key is never replaced, whatever its shape.
BootKeyAction decideBootKey(KeyModel model, bool present, const char* stored);

// Round 2 (PROTOCOL.md 11.8): the same, plus recovery. A board that lost fry/minerKey but still
// holds fry/salt, and whose key was never written by its owner (keySrc != "user"), minted that key
// as SHA256(mac6 || salt): Recover derives the SAME key again (0.3.x did the same on every boot).
// It never mints a new one and never touches an owner's key.
BootKeyAction decideBootKey(KeyModel model, bool present, const char* stored, bool saltPresent,
                            bool keySrcUser);

// Whether the boot sequence may leave provisioning and join Wi-Fi. A USER_SUPPLIED board without a
// key stays provisionable so the owner can still write one.
bool keyAllowsJoin(KeyModel model, bool hasKey);

enum class KeyTransport : uint8_t {
  Usb,           // Improv Serial 0xF0 - physical access
  Ble,           // characteristic 09, LE Secure Connections
  SoftApSecure,  // ESP8266 WPA2 setup AP (setup code shown over USB only)
  SoftApOpen,    // ESP8266 open AP - never carries a key
};

enum class KeyWriteVerdict : uint8_t {
  Accept,
  BadKey,         // not ^FEM-[A-Za-z0-9]{32}$
  Locked,         // DEVICE_KEEPS, or replacing a key a 2xx registration confirmed, over the air
  NeedsSecureAp,  // a key offered over the open AP
  StoreFailed,    // policy said yes but the store would not take it (Arduino side only)
};

// `valid` is isAcceptableOwnerKey(new key); `sameAsStored` is new key == stored key, which is a
// no-op that is always allowed (an app re-provisioning Wi-Fi writes the key it already holds).
KeyWriteVerdict mayWriteKey(KeyModel model, KeyTransport transport, bool hasKey, bool keyConfirmed,
                            bool valid, bool sameAsStored = false);

// The status/error code a verdict is reported as (PROTOCOL.md section 11.2): 7 BadKey, 8 KeyLocked
// (NeedsSecureAp and StoreFailed included), None for Accept.
ProvErr keyVerdictProvErr(KeyWriteVerdict v);

// "FEM-AB" + U+2026 (UTF-8 E2 80 A6): the first 6 characters and an ellipsis, the only form of a
// key any unauthenticated surface shows. Writes "" and returns 0 for an empty/short key or a buffer
// under 10 bytes; otherwise returns 9.
size_t maskMinerKey(const char* key, char* out, size_t outCap);

// 8 characters from ABCDEFGHJKLMNPQRSTUVWXYZ23456789 (no 0/O/1/I), taken from 40 bits of r0/r1:
// the WPA2 passphrase of the ESP8266 setup AP. Returns false if outCap < 9.
bool makeSetupCode(uint32_t r0, uint32_t r1, char* out, size_t outCap);

}  // namespace fry
