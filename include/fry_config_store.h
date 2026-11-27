// UI/app-shared facade over the existing fry_config accessors. Abstract Store so native tests inject an
// in-memory fake. Declarations only; no Arduino include (host-compilable).
#ifndef FRY_CONFIG_STORE_H
#define FRY_CONFIG_STORE_H

#include <stdint.h>

namespace fry {
namespace cfg {

enum class DisplayMode : uint8_t { Auto = 0, None = 1, Screen = 2, Touch = 3 };

struct Snapshot {
  char ssid[33];
  bool hasWifi;
  bool hasPass;
  char minerKeyLast4[5];
  bool hasMinerKey;
  char wallet[65];
  bool provDone;
  DisplayMode displayMode;
  uint8_t boardPreset;
  uint32_t generation;
};

struct Store {
  virtual bool load(Snapshot& out) = 0;
  virtual bool saveWifi(const char* ssid, const char* pass) = 0;  // as provisioning commitWifiOnlyCredentials
  virtual bool saveMinerKey(const char* key) = 0;                 // as Improv vendor 0xF0 (setMinerKey + keySrc "user"); validates FEM- format
  virtual bool saveWallet(const char* wallet) = 0;
  virtual bool saveDisplayMode(DisplayMode m, uint8_t preset) = 0;  // namespace "fry_ui" keys dispMode, dispPreset (NEW keys only)
  virtual bool saveTouchCal(const int16_t cal[8]) = 0;              // "fry_ui" key tcal
  virtual bool loadTouchCal(int16_t cal[8]) = 0;
  virtual bool factoryReset() = 0;  // == fry_config::factoryReset semantics
  virtual ~Store() {}
};

// FNV-1a over ssid, hasPass, hasMinerKey, minerKeyLast4, wallet, provDone, displayMode (lib/fry_ui/config_snapshot.cpp).
uint32_t snapshotGeneration(const Snapshot& s);
// FEM- + 32 alphanumerics, exactly 36 bytes, case-sensitive (PROTOCOL.md 11.1; same rule as fry::isAcceptableOwnerKey).
bool validMinerKey(const char* k);
// Real implementation over fry_config/KvStore (src/ui/config_store_device.cpp).
Store& deviceStore();

}  // namespace cfg
}  // namespace fry

#endif  // FRY_CONFIG_STORE_H
