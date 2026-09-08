#pragma once
// Cross-task trigger hooks. main.cpp (T4) and serial_commands.cpp (T3, lab-only) call these;
// trigger_stubs.cpp provides a weak default for each so every build links standalone before the
// later task that implements it for real lands. A later TU's STRONG (non-weak) definition
// overrides the corresponding stub at link time — no caller-side changes needed when that happens.
extern "C" {

void fry_trigger_poc_now();        // T5: hardwareapi PoC report, out of cadence
void fry_trigger_ota_now();        // T7: OTA manifest check, out of cadence
void fry_trigger_register_now();   // T5: hardwareapi installation registration
void fry_trigger_start_vpn();      // T6: bring up the WireGuard / SOCKS5 endpoint
void fry_trigger_report_loop_tick();  // T5: PoC/heartbeat cadence, called every loop()

}  // extern "C"
