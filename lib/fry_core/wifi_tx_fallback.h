#pragma once
// ESP32-C3 reduced-TX join fallback decision. Pure C++ so the native suite pins it; the retry itself
// lives in src/esp32/wifi_connect.cpp behind CONFIG_IDF_TARGET_ESP32C3.
//
// Some C3 boards associate at the default TX power but never finish the handshake. A join that failed
// AFTER association with an auth/handshake-class disconnect reason gets exactly one retry at a lower
// TX power. A join that never associated (wrong SSID, out of range) or that failed for any other
// reason is left alone, and so is every join that succeeds, so a healthy board never reaches this.
#include <cstdint>

namespace fry {

// WIFI_REASON_AUTH_EXPIRE (2), 4WAY_HANDSHAKE_TIMEOUT (15), AUTH_FAIL (202), ASSOC_FAIL (203),
// HANDSHAKE_TIMEOUT (204).
inline bool isHandshakeClassReason(uint8_t reason) {
  return reason == 2 || reason == 15 || reason == 202 || reason == 203 || reason == 204;
}

inline bool shouldRetryLowTx(uint8_t reason, bool associated, bool alreadyRetried) {
  return associated && !alreadyRetried && isHandshakeClassReason(reason);
}

}  // namespace fry
