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
  void clear() { n_ = 0; }  // lets a long-lived instance be reused without a stack copy
  size_t count() const { return n_; }
  const ScanRow& at(size_t i) const { return rows_[i]; }

 private:
  ScanRow rows_[kMax];
  size_t n_ = 0;
};

void formatRssi(int rssi, char* out, size_t outLen);
const char* authCell(bool secure);  // "YES" / "NO", the same cells the ESP32 path sends

// The Arduino WiFi.scanNetworks() / scanComplete() sentinels, spelled here so the native suite
// needs no Wi-Fi header.
const int kScanRunning = -1;  // WIFI_SCAN_RUNNING
const int kScanFailed = -2;   // WIFI_SCAN_FAILED

// Whether an Improv "request scanned Wi-Fi networks" is answered with a scan.
enum class ScanAdmit : uint8_t { Run, Refuse };

// A running board's scan stalls the radio for the seconds it takes, so it is spaced out.
const unsigned long kRunningScanMinIntervalMs = 30000;

// transportRunning (the board is provisionable): always Run, as before. Otherwise (a board that
// joined its network) Run only when the station is joined (a scan started while it is joining
// would disconnect it), the last running-phase scan is at least kRunningScanMinIntervalMs old
// (haveLast=false: none yet; unsigned subtraction, so a millis() wrap is harmless), and the
// largest free heap block is at least minBlock. Refuse is answered with Improv error 4.
ScanAdmit admitScan(bool transportRunning, bool staConnected, bool haveLast, unsigned long nowMs,
                    unsigned long lastScanMs, uint32_t maxFreeBlock, uint32_t minBlock);

// What WiFi.scanNetworks() returned when the glue started the scan.
enum class ScanStart : uint8_t { Started, Failed };
ScanStart classifyScanStart(int rc);

// What WiFi.scanComplete() reports while the glue waits for the scan.
enum class ScanPoll : uint8_t { Wait, Failed, Done };
ScanPoll classifyScanPoll(int n);

}  // namespace improv
}  // namespace fry
