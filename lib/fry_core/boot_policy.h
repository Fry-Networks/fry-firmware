// BootPolicy — decides when the provisioning transport has to be running.
//
// The device must stay re-provisionable for its whole life, not just on its first boot. Stored
// WiFi credentials go stale for ordinary reasons: the operator changes the router password, the
// AP is replaced, the board is carried to a different site, or a bad password was persisted in
// the first place. When that happens the provisioning transport (ESP32 BLE advertising, ESP8266
// softAP) is the ONLY channel a phone can still reach the board on — there is no network path and
// no display. If it is not running, the board is invisible and the user has no recovery short of
// re-flashing over USB.
//
// Pure logic with no Arduino dependency, so the native Unity suite covers it. See PROTOCOL.md
// sections 1 and 3 for the two transports this governs.
#pragma once

#include <stdint.h>

namespace fry {

enum class BootPhase : uint8_t {
  AwaitingProvisioning = 0,
  ConnectingWifi = 1,
  Ready = 2,
};

// The phase a boot starts in. Credentials already in storage mean the WiFi join can be attempted
// straight away; without them there is nothing to do but wait to be provisioned.
BootPhase initialBootPhase(bool hasCredentials);

// Whether stored configuration is complete enough to skip provisioning on this boot.
//
// WiFi credentials alone are not enough: a board that stored an SSID but was never committed
// would boot straight into a join it has no business attempting. The commit marker is a wallet
// for the BLE/SoftAP transports (PROTOCOL.md section 1: the WALLET write commits) and the
// wallet-less fry/provDone flag for Improv Serial, whose protocol carries no wallet field.
bool hasBootCredentials(bool hasWifi, bool hasWallet, bool hasProvDone);

// Tracks whether the provisioning transport has been brought up, and answers the single question
// the boot sequence asks on every phase entry: "must I start it now?".
//
// Starting is deliberately lazy rather than unconditional-at-boot. On ESP8266 the transport is a
// softAP, and bringing it up switches the radio to WIFI_AP — doing that at boot would knock a
// perfectly healthy provisioned device off its network. Starting only when a phase actually needs
// it is correct on both chips.
class BootPolicy {
 public:
  // Call on entry to `phase`. Returns true when the caller must start the transport now. Never
  // returns true twice in a row, so the caller can act on it without tracking state itself.
  bool onPhaseEntry(BootPhase phase);

  bool transportStarted() const { return _started; }

 private:
  bool _started = false;
};

}  // namespace fry
