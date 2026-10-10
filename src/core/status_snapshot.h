#pragma once
// Fills lib/fry_core/device_status.h's DeviceStatus from the live board: provisioning state, key
// presence and confirmation, last registration status, heartbeat age, OTA image state and (ESP8266
// without a key) the setup-AP code. BLE 0A, Improv 0xF1 and ESP8266 /status all read it here.
#include <Arduino.h>

#include "device_status.h"

namespace fry_status {

void snapshot(fry::DeviceStatus& out);

}  // namespace fry_status
