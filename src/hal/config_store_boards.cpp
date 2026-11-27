// Built only by the Pico / BK7231N envs (platformio.boards.ini defines FRY_BOARDS_PORT); the ESP envs compile all of src/.
#if defined(FRY_BOARDS_PORT)
// fry::cfg::Store (include/fry_config_store.h) for the Pico and BK7231N boards: the UI/app-shared facade over the existing
// fry_config accessors. WiFi, wallet and miner key go through the same writers as the provisioning transports; the display
// settings use the new "fry_ui" namespace (keys dispMode, dispPreset, tcal) only.
#include <Arduino.h>

#include <string.h>

#include "../../lib/fry_ui/config_snapshot.h"
#include "../core/fry_config.h"
#include "../core/kv_store.h"
#include "../core/miner_key.h"
#include "../core/provisioning_transport.h"
#include "key_policy.h"

namespace fry {
namespace cfg {

namespace {

class BoardStore : public Store {
 public:
  bool load(Snapshot& out) override {
    memset(&out, 0, sizeof(out));
    char pass[65] = {0};
    out.hasWifi = fry_config::getWifi(out.ssid, sizeof(out.ssid), pass, sizeof(pass)) && out.ssid[0];
    out.hasPass = pass[0] != 0;
    memset(pass, 0, sizeof(pass));
    char key[40] = {0};
    out.hasMinerKey = fry_config::getMinerKey(key, sizeof(key)) && key[0];
    const size_t kl = strlen(key);
    if (out.hasMinerKey && kl >= 4) memcpy(out.minerKeyLast4, key + kl - 4, 4);
    memset(key, 0, sizeof(key));
    const String wallet = fry_config::getWallet();
    strncpy(out.wallet, wallet.c_str(), sizeof(out.wallet) - 1);
    out.provDone = fry_config::hasProvDone();
    KvStore r;
    r.begin("fry_ui", true);
    uint8_t mode = r.getUChar("dispMode", 0);
    out.displayMode = mode <= 3 ? static_cast<DisplayMode>(mode) : DisplayMode::Auto;
    out.boardPreset = r.getUChar("dispPreset", 0);
    r.end();
    out.generation = snapshotGeneration(out);
    return true;
  }

  bool saveWifi(const char* ssid, const char* pass) override {
    return fry_provisioning::commitWifiOnlyCredentials(ssid, pass);
  }

  bool saveMinerKey(const char* key) override {
    if (!validMinerKey(key)) return false;
    bool changed = false;
    return fry_identity::setOwnerKey(key, fry::KeyTransport::Usb, &changed) == fry::KeyWriteVerdict::Accept;
  }

  bool saveWallet(const char* wallet) override {
    if (!wallet) return false;
    fry_config::setWallet(wallet);
    return fry_config::getWallet() == String(wallet);
  }

  bool saveDisplayMode(DisplayMode m, uint8_t preset) override {
    KvStore w;
    if (!w.begin("fry_ui", false)) return false;
    const bool ok = w.putUChar("dispMode", static_cast<uint8_t>(m)) > 0 && w.putUChar("dispPreset", preset) > 0;
    w.end();
    return ok;
  }

  bool saveTouchCal(const int16_t cal[8]) override {
    if (!cal) return false;
    KvStore w;
    if (!w.begin("fry_ui", false)) return false;
    const bool ok = w.putBytes("tcal", cal, 8 * sizeof(int16_t)) == 8 * sizeof(int16_t);
    w.end();
    return ok;
  }

  bool loadTouchCal(int16_t cal[8]) override {
    if (!cal) return false;
    KvStore r;
    if (!r.begin("fry_ui", true)) return false;
    const bool ok = r.getBytes("tcal", cal, 8 * sizeof(int16_t)) == 8 * sizeof(int16_t);
    r.end();
    return ok;
  }

  bool factoryReset() override {
    fry_config::factoryReset();
    return true;
  }
};

}  // namespace

#ifndef FRY_UI_PROVIDES_DEVICE_STORE
Store& deviceStore() {
  static BoardStore s;
  return s;
}
#endif

}  // namespace cfg
}  // namespace fry
#endif  // FRY_BOARDS_PORT
