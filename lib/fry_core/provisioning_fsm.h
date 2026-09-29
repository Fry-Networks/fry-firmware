#pragma once
// Pure C++ provisioning state machine — zero Arduino includes so it compiles and runs
// identically under `pio test -e native` and on every embedded target.
// State/error/event numbering matches PROTOCOL.md section 2 exactly (BLE characteristic 06
// and the ESP8266 GET /status payload both serialize ProvState/ProvErr as raw bytes).
#include <cstddef>
#include <cstdint>

namespace fry {

enum class ProvState : uint8_t {
  Idle = 0,
  Provisioning = 1,
  Connecting = 2,
  Connected = 3,
  Error = 4,
};

enum class ProvErr : uint8_t {
  None = 0,
  BadSsid = 1,
  WifiAuth = 2,
  NoIp = 3,
  ApiFail = 4,
  BadWallet = 5,
  // PROTOCOL.md section 11.2 (v1.1), append-only. Clients older than v1.1 read only the legacy
  // byte, so every code from 6 up reaches them as 4, "registration failed" (legacyProvErr()).
  KeyRequired = 6,   // wallet commit with no miner key (USER_SUPPLIED)
  BadKey = 7,        // key write not ^FEM-[A-Za-z0-9]{32}$
  KeyLocked = 8,     // key write refused by policy (lib/fry_core/key_policy.h)
  Reg401 = 9,
  Reg403 = 10,
  Reg409 = 11,       // key active on another install
  RegOther4xx = 12,
  Unreachable = 13,  // transport error, 5xx or 429 after the quick retry; the device keeps trying
};

enum class ProvEvent : uint8_t {
  SsidWritten,
  PassWritten,
  WalletWritten,
  WifiUp,
  WifiAuthFail,
  WifiNoIp,
  ApiOk,
  ApiFail,
  Reset,
  // Improv Serial (src/core/improv_serial_glue.cpp) commits with WiFi credentials only: its
  // protocol has no wallet field. Appended at the end - ProvEvent is internal and is never
  // serialized, unlike ProvState/ProvErr whose numbering PROTOCOL.md section 2 fixes.
  WifiOnlyCommit,
  // v1.1. A wallet commit refused for want of a miner key, or a joined board that has none to
  // register with (Improv commits Wi-Fi only).
  KeyMissing,
  // v1.1. A miner-key write refused; ProvInputs::detail says why (BadKey or KeyLocked).
  KeyRejected,
};

struct ProvInputs {
  bool ssidValid = false;
  bool walletValid = false;
  // v1.1. The specific cause carried by ApiFail (Reg401..Unreachable) and KeyRejected (BadKey,
  // KeyLocked). None keeps the generic code.
  ProvErr detail = ProvErr::None;
  // Round 2 (PROTOCOL.md 11.8). False for a write that arrived over an UNENCRYPTED BLE link or the
  // OPEN ESP8266 AP. Such a write cannot re-provision a board that is running (Wi-Fi joined this
  // boot) and only in an API-side Error; see acceptsUntrustedWrites(). USB, an encrypted BLE link
  // and the WPA2 setup AP are trusted, and so is every caller that does not say otherwise.
  bool linkTrusted = true;
};

// The error byte a pre-v1.1 client understands: 0-5 unchanged, 6 and up reported as 4.
uint8_t legacyProvErr(ProvErr e);

// Status characteristic 06 / GET /status bytes: [state], or [4][legacy][detail] in Error.
// Returns the length written (1 or 3), 0 if outCap is too small for it.
size_t encodeProvStatus(ProvState state, ProvErr err, uint8_t* out, size_t outCap);

class ProvisioningFsm {
 public:
  ProvState state() const { return _state; }
  ProvErr error() const { return _err; }

  // Feeds one event into the machine. Returns true iff state() changed as a result.
  // Events that do not apply to the current state (out-of-order events) are ignored
  // and return false; internal bookkeeping (e.g. the wifiUp latch) may still update.
  bool feed(ProvEvent ev, const ProvInputs& in);

  // True exactly while state() == Connecting — the caller's cue to start the WiFi join.
  bool readyToConnect() const { return _state == ProvState::Connecting; }

  // False while the board is in Error with Wi-Fi joined this boot and only the API side failed
  // (4, 6, 9-13, or a key refusal raised after the join): the 0.3.x rule that such a board is not
  // re-provisioned by a stranger in radio range. Transports drop untrusted writes while it holds;
  // Wi-Fi-class errors still accept them, so a failed join never needs a reboot.
  bool acceptsUntrustedWrites() const { return !runningError(); }

 private:
  bool runningError() const;
  ProvState _state = ProvState::Idle;
  ProvErr _err = ProvErr::None;
  bool _wifiUp = false;
};

}  // namespace fry
