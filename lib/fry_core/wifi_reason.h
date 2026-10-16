#pragma once
// Wi-Fi station disconnect reason -> the ProvErr a failed join is reported as. Pure C++ so the
// native suite pins it; the reason itself is read from the chip's disconnect event in
// src/esp32/wifi_connect.cpp and src/esp8266/wifi_connect.cpp.
#include <cstdint>

#include "provisioning_fsm.h"

namespace fry {

// WIFI_REASON_NO_AP_FOUND (201: no AP answered for that SSID) -> BadSsid. Everything else,
// including 203 ASSOC_FAIL (the AP exists and refused) and an undiagnosed 0, -> WifiAuth.
ProvErr classifyWifiDisconnect(uint8_t reason);

}  // namespace fry
