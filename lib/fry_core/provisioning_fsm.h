#pragma once
// Pure C++ provisioning state machine — zero Arduino includes so it compiles and runs
// identically under `pio test -e native` and on every embedded target.
// State/error/event numbering matches PROTOCOL.md section 2 exactly (BLE characteristic 06
// and the ESP8266 GET /status payload both serialize ProvState/ProvErr as raw bytes).
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
};

struct ProvInputs {
  bool ssidValid = false;
  bool walletValid = false;
};

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

 private:
  ProvState _state = ProvState::Idle;
  ProvErr _err = ProvErr::None;
  bool _wifiUp = false;
};

}  // namespace fry
