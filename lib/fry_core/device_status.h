#pragma once
// One snapshot of what a board reports about itself (PROTOCOL.md section 11): the BLE 0A status
// JSON, Improv 0xF1 and the ESP8266 /status fields are all built from this, so the three surfaces
// cannot disagree. Pure C++; src/core/status_snapshot.cpp fills it on the device.
#include <cstddef>
#include <cstdint>

#include "provisioning_fsm.h"

namespace fry {

struct DeviceStatus {
  ProvState state = ProvState::Idle;  // provisioning session state (Idle on a board that booted
                                      // straight into its network)
  ProvErr err = ProvErr::None;        // full code; reported only while state == Error
  bool keySet = false;
  bool keyConfirmed = false;          // accepted by a 2xx registration
  char keyMasked[12] = {0};           // maskMinerKey(): "FEM-AB" + U+2026, "" without a key
  int regHttp = 0;                    // last registration HTTP status, 0 if none this boot
  int32_t hbAgeS = -1;                // seconds since the last 2xx heartbeat, -1 if none
  const char* fw = "";
  const char* ota = "valid";          // otaImageStateName()
  const char* apCode = "";            // ESP8266 WPA2 setup code; "" otherwise. USB surfaces only.
};

// Error byte pair as the status surfaces carry it: legacy (0-5) and detail (0-13); both 0 outside
// Error.
uint8_t statusLegacyErr(const DeviceStatus& s);
uint8_t statusDetailErr(const DeviceStatus& s);

const size_t kStatusJsonMax = 160;

// BLE characteristic 0A:
// {"v":1,"proto":2,"caps":["key_write","error_reset","errs_v2"],"s":..,"e":..,"d":..,"k":..,
//  "kc":..,"reg":..,"hb":..,"fw":"..","ota":".."}
// No key, masked or not, and no setup code. Returns the length, or 0 (and "") if it would exceed
// kStatusJsonMax or outCap, or if fw/ota hold a character that would need JSON escaping.
size_t buildStatusJson(const DeviceStatus& s, char* out, size_t outCap);

}  // namespace fry
