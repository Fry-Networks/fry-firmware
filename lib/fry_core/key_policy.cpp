#include "key_policy.h"

#include <cstring>

#include "miner_identity.h"

namespace fry {

namespace {

bool isAlnum(char c) {
  return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

const char kSetupAlphabet[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";  // 32 symbols, 5 bits each

}  // namespace

bool isAcceptableOwnerKey(const char* key) {
  if (!key) return false;
  if (strlen(key) != 36) return false;  // "FEM-" + 32
  if (strncmp(key, "FEM-", 4) != 0) return false;
  for (int i = 4; i < 36; i++) {
    if (!isAlnum(key[i])) return false;
  }
  return true;
}

BootKeyAction decideBootKey(KeyModel model, bool present, const char* stored) {
  if (present && stored && stored[0]) {
    return isLegacyMinerKey(stored) ? BootKeyAction::MigrateLegacy : BootKeyAction::Keep;
  }
  return model == KeyModel::DeviceKeeps ? BootKeyAction::Mint : BootKeyAction::Wait;
}

BootKeyAction decideBootKey(KeyModel model, bool present, const char* stored, bool saltPresent,
                            bool keySrcUser) {
  const BootKeyAction action = decideBootKey(model, present, stored);
  if ((action == BootKeyAction::Wait || action == BootKeyAction::Mint) && saltPresent && !keySrcUser) {
    return BootKeyAction::Recover;
  }
  return action;
}

bool keyAllowsJoin(KeyModel model, bool hasKey) {
  return model == KeyModel::DeviceKeeps || hasKey;
}

KeyWriteVerdict mayWriteKey(KeyModel model, KeyTransport transport, bool hasKey, bool keyConfirmed,
                            bool valid, bool sameAsStored) {
  // Checked first: a key must not be solicited in the clear, whatever else is true.
  if (transport == KeyTransport::SoftApOpen) return KeyWriteVerdict::NeedsSecureAp;
  if (!valid) return KeyWriteVerdict::BadKey;
  if (hasKey && sameAsStored) return KeyWriteVerdict::Accept;
  if (model == KeyModel::DeviceKeeps) return KeyWriteVerdict::Locked;
  // Once hardwareapi accepted the key, only someone holding the board may swap it.
  if (hasKey && keyConfirmed && transport != KeyTransport::Usb) return KeyWriteVerdict::Locked;
  return KeyWriteVerdict::Accept;
}

ProvErr keyVerdictProvErr(KeyWriteVerdict v) {
  switch (v) {
    case KeyWriteVerdict::Accept:
      return ProvErr::None;
    case KeyWriteVerdict::BadKey:
      return ProvErr::BadKey;
    case KeyWriteVerdict::Locked:
    case KeyWriteVerdict::NeedsSecureAp:
    case KeyWriteVerdict::StoreFailed:
      return ProvErr::KeyLocked;
  }
  return ProvErr::KeyLocked;
}

size_t maskMinerKey(const char* key, char* out, size_t outCap) {
  if (!out || outCap == 0) return 0;
  out[0] = 0;
  if (!key || strlen(key) < 6 || outCap < 10) return 0;
  memcpy(out, key, 6);
  out[6] = static_cast<char>(0xE2);  // U+2026 HORIZONTAL ELLIPSIS
  out[7] = static_cast<char>(0x80);
  out[8] = static_cast<char>(0xA6);
  out[9] = 0;
  return 9;
}

bool makeSetupCode(uint32_t r0, uint32_t r1, char* out, size_t outCap) {
  if (!out || outCap < 9) return false;
  const uint64_t bits = (static_cast<uint64_t>(r0) << 32) | r1;
  for (int i = 0; i < 8; i++) {
    out[i] = kSetupAlphabet[(bits >> (5 * i)) & 31u];
  }
  out[8] = 0;
  return true;
}

}  // namespace fry
