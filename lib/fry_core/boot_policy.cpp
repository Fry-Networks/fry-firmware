#include "boot_policy.h"

namespace fry {

BootPhase initialBootPhase(bool hasCredentials) {
  return hasCredentials ? BootPhase::ConnectingWifi : BootPhase::AwaitingProvisioning;
}

bool hasBootCredentials(bool hasWifi, bool hasWallet, bool hasProvDone) {
  return hasWifi && (hasWallet || hasProvDone);
}

bool BootPolicy::onPhaseEntry(BootPhase phase) {
  // AwaitingProvisioning is the only phase that needs the transport, but it is reached twice:
  // once on an unprovisioned first boot, and again whenever a WiFi join fails (src/main.cpp:82
  // sets the phase back). The second case is the one that matters — it is how a board with stale
  // credentials stays reachable instead of going dark.
  if (phase != BootPhase::AwaitingProvisioning) return false;

  // NimBLE init and softAP bring-up are not idempotent, so report the need to start exactly once.
  if (_started) return false;
  _started = true;
  return true;
}

}  // namespace fry
