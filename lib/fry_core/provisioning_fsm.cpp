#include "provisioning_fsm.h"

namespace fry {

namespace {

bool isRegDetail(ProvErr e) { return e >= ProvErr::Reg401 && e <= ProvErr::Unreachable; }

// Errors raised after the Wi-Fi join worked: a later successful registration clears them.
bool isApiClassErr(ProvErr e) {
  return e == ProvErr::ApiFail || e == ProvErr::KeyRequired || isRegDetail(e);
}

ProvErr keyDetail(ProvErr e) { return e == ProvErr::KeyLocked ? ProvErr::KeyLocked : ProvErr::BadKey; }

bool isKeyErr(ProvErr e) { return e == ProvErr::BadKey || e == ProvErr::KeyLocked; }

}  // namespace

bool ProvisioningFsm::runningError() const {
  // A key refusal can only coexist with the Wi-Fi latch when it was raised after the join (every
  // path back to Provisioning clears the latch), so it belongs to the running case as well.
  return _state == ProvState::Error && _wifiUp && (isApiClassErr(_err) || isKeyErr(_err));
}

uint8_t legacyProvErr(ProvErr e) {
  const uint8_t v = static_cast<uint8_t>(e);
  return v < static_cast<uint8_t>(ProvErr::KeyRequired) ? v : static_cast<uint8_t>(ProvErr::ApiFail);
}

size_t encodeProvStatus(ProvState state, ProvErr err, uint8_t* out, size_t outCap) {
  if (!out) return 0;
  if (state != ProvState::Error) {
    if (outCap < 1) return 0;
    out[0] = static_cast<uint8_t>(state);
    return 1;
  }
  if (outCap < 3) return 0;
  out[0] = static_cast<uint8_t>(state);
  out[1] = legacyProvErr(err);
  out[2] = static_cast<uint8_t>(err);
  return 3;
}

bool ProvisioningFsm::feed(ProvEvent ev, const ProvInputs& in) {
  const ProvState prev = _state;

  // v1.1 error_reset: an SSID write in Error starts a fresh attempt, exactly as it would from
  // Idle. Before this the only way out of Error was a reboot.
  // Round 2: not from an untrusted link while the board is running (acceptsUntrustedWrites()).
  if (_state == ProvState::Error && ev == ProvEvent::SsidWritten &&
      (in.linkTrusted || !runningError())) {
    _state = ProvState::Idle;
    _err = ProvErr::None;
    _wifiUp = false;
  }

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
      } else if (ev == ProvEvent::KeyRejected) {
        _state = ProvState::Error;  // a key write (09) may come before the SSID
        _err = keyDetail(in.detail);
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
      } else if (ev == ProvEvent::WifiOnlyCommit) {
        // Same commit point as a wallet write, minus the wallet: the Improv client has already
        // sent everything it carries. The wallet-less marker persisted alongside the credentials
        // (fry/provDone) is what lets the NEXT boot skip provisioning without one.
        _state = ProvState::Connecting;
        _err = ProvErr::None;
        _wifiUp = false;
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
      } else if (ev == ProvEvent::KeyMissing) {
        _state = ProvState::Error;
        _err = ProvErr::KeyRequired;
      } else if (ev == ProvEvent::KeyRejected) {
        _state = ProvState::Error;
        _err = keyDetail(in.detail);
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
        _err = isRegDetail(in.detail) ? in.detail : ProvErr::ApiFail;
      } else if (ev == ProvEvent::KeyMissing) {
        _state = ProvState::Error;
        _err = ProvErr::KeyRequired;
      }
      break;

    case ProvState::Connected:
      // Terminal except for an explicit Reset (handled below, shared with Error).
      break;

    case ProvState::Error:
      // v1.1: Wi-Fi is up and only the API side failed. Registration keeps retrying on its own
      // schedule, so its later success (or a different failure) must reach the status too.
      // A key refusal raised meanwhile (round 2) does not take that away: runningError().
      if (runningError()) {
        if (ev == ProvEvent::ApiOk) {
          _state = ProvState::Connected;
          _err = ProvErr::None;
        } else if (ev == ProvEvent::ApiFail) {
          _err = isRegDetail(in.detail) ? in.detail : ProvErr::ApiFail;
        }
      }
      if (ev == ProvEvent::KeyRejected) {
        _err = keyDetail(in.detail);
      }
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
