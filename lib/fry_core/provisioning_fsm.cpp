#include "provisioning_fsm.h"

namespace fry {

bool ProvisioningFsm::feed(ProvEvent ev, const ProvInputs& in) {
  const ProvState prev = _state;

  switch (_state) {
    case ProvState::Idle:
      if (ev == ProvEvent::SsidWritten) {
        if (in.ssidValid) {
          _state = ProvState::Provisioning;
          _err = ProvErr::None;
        } else {
          _state = ProvState::Error;
          _err = ProvErr::BadSsid;
        }
      }
      break;

    case ProvState::Provisioning:
      if (ev == ProvEvent::SsidWritten) {
        // Re-writing the SSID while still provisioning is allowed (no state change on
        // success); an invalid value is always an error regardless of which state raised it.
        if (!in.ssidValid) {
          _state = ProvState::Error;
          _err = ProvErr::BadSsid;
        }
      } else if (ev == ProvEvent::WalletWritten) {
        // Commit semantics per PROTOCOL.md section 1: writing WALLET commits provisioning.
        if (in.walletValid) {
          _state = ProvState::Connecting;
          _err = ProvErr::None;
          _wifiUp = false;
        } else {
          _state = ProvState::Error;
          _err = ProvErr::BadWallet;
        }
      }
      break;

    case ProvState::Connecting:
      if (ev == ProvEvent::WifiUp) {
        _wifiUp = true;  // internal latch only — Connected requires WiFi up AND api ok
      } else if (ev == ProvEvent::WifiAuthFail) {
        _state = ProvState::Error;
        _err = ProvErr::WifiAuth;
      } else if (ev == ProvEvent::WifiNoIp) {
        _state = ProvState::Error;
        _err = ProvErr::NoIp;
      } else if (ev == ProvEvent::ApiOk) {
        if (_wifiUp) {
          _state = ProvState::Connected;
          _err = ProvErr::None;
        }
      } else if (ev == ProvEvent::ApiFail) {
        _state = ProvState::Error;
        _err = ProvErr::ApiFail;
      }
      break;

    case ProvState::Connected:
      // Terminal except for an explicit Reset (handled below, shared with Error).
      break;

    case ProvState::Error:
      break;
  }

  // Reset is valid from any state and always returns to Idle.
  if (ev == ProvEvent::Reset && _state != ProvState::Idle) {
    _state = ProvState::Idle;
    _err = ProvErr::None;
    _wifiUp = false;
  }

  return _state != prev;
}

}  // namespace fry
