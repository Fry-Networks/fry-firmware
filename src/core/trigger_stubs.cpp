// Weak default implementations of the cross-task trigger hooks (see trigger_hooks.h). Always
// compiled (unconditional — no #ifdef) so every build variant links even before the task that
// implements a given hook for real has landed.
#include <Arduino.h>

#include "trigger_hooks.h"

extern "C" __attribute__((weak)) void fry_trigger_poc_now() {
  Serial.println("[serial] poc_now: hardwareapi client not built yet");
}

extern "C" __attribute__((weak)) void fry_trigger_ota_now() {
  Serial.println("[serial] ota_now: OTA module not built yet");
}

extern "C" __attribute__((weak)) void fry_trigger_register_now() {
  Serial.println("api: registration client not built yet");
}

extern "C" __attribute__((weak)) void fry_trigger_start_vpn() {
  Serial.println("wg: VPN module not built yet");
}

extern "C" __attribute__((weak)) void fry_trigger_report_loop_tick() {
  // no-op until T5 wires PoC/heartbeat cadence in here
}
