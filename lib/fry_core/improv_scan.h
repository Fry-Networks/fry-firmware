#pragma once
// Reduces a chip's raw Wi-Fi scan to the rows an Improv "request scanned Wi-Fi networks" reply
// carries. Pure C++ so the native suite pins the rules; the scan itself runs in
// src/core/improv_serial_glue.cpp.
#include <cstddef>
#include <cstdint>

namespace fry {
namespace improv {

struct ScanRow {
  char ssid[33];
  int rssi;
  bool secure;
};

// At most kMax rows, one per SSID (the strongest sighting), strongest first. Hidden networks
// (empty SSID) are dropped: a client can not offer a network it can not name.
class ScanList {
 public:
  static const size_t kMax = 24;  // same bound as the captive portal's scan cache

  // True when the sighting is kept. Over-long SSIDs are truncated to 32 bytes.
  bool add(const char* ssid, int rssi, bool secure);
  size_t count() const { return n_; }
  const ScanRow& at(size_t i) const { return rows_[i]; }

 private:
  ScanRow rows_[kMax];
  size_t n_ = 0;
};

void formatRssi(int rssi, char* out, size_t outLen);
const char* authCell(bool secure);  // "YES" / "NO", the same cells the ESP32 path sends

}  // namespace improv
}  // namespace fry
