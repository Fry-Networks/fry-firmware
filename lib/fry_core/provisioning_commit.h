#pragma once
// Commit ordering for the WALLET write (PROTOCOL.md section 1: writing WALLET commits
// provisioning). The transport callback runs on the BLE host task while the Arduino loop task
// polls ProvisioningFsm::readyToConnect() and then reads the credentials back from NVS. The
// FSM must therefore only report Connecting AFTER the credentials are persisted; feeding the
// event first let the loop win the race and join WiFi with an empty SSID.
#include "provisioning_fsm.h"

namespace fry {

// Persists (via `persist`) exactly when the FSM would accept this wallet write — i.e. it is
// currently Provisioning and the wallet is valid — and only then feeds WalletWritten.
// Returns what ProvisioningFsm::feed returned (true iff the state changed).
template <typename Persist>
bool commitOnWallet(ProvisioningFsm& fsm, const ProvInputs& in, Persist persist) {
  if (fsm.state() == ProvState::Provisioning && in.walletValid) {
    persist();
  }
  return fsm.feed(ProvEvent::WalletWritten, in);
}

// The same rule for the wallet-less Improv Serial commit: persist first (the loop task reads the
// credentials straight back out of the store the moment the FSM says Connecting), then feed the
// event. There is no wallet to validate, so the only precondition is that the FSM is Provisioning
// - i.e. a valid SSID was accepted first.
template <typename Persist>
bool commitWifiOnly(ProvisioningFsm& fsm, Persist persist) {
  if (fsm.state() == ProvState::Provisioning) {
    persist();
  }
  return fsm.feed(ProvEvent::WifiOnlyCommit, ProvInputs{});
}

// Improv 0x01 is accepted in every phase (PROTOCOL.md section 11.8, round 2 F8): before its SSID is
// fed, a board that is past Provisioning - in Error, or Connected / Connecting on settings committed
// earlier this boot - starts over, as an explicit Reset would. Idle and Provisioning need none: the
// SSID write is already valid there. The join itself never overlaps an Improv command (it blocks the
// loop that polls the UART), so nothing in flight is cut short.
inline void resetForWifiOnlyCommit(ProvisioningFsm& fsm) {
  const ProvState st = fsm.state();
  if (st != ProvState::Idle && st != ProvState::Provisioning) {
    fsm.feed(ProvEvent::Reset, ProvInputs{});
  }
}

}  // namespace fry
