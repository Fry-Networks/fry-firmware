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

}  // namespace fry
