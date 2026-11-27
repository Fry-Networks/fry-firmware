#pragma once
// KV backend of the Pico boards: one LittleFS file per key ("/kv_<ns>.<key>"), written to a .tmp and renamed over the old one so a
// reset mid-write leaves the old or the new blob, never a torn one (the same rule as src/esp8266/prefs_store.cpp).
#include <LittleFS.h>

#include <string.h>

namespace fry_boards {

struct LittleFsBackend {
  static bool mount() {
    static int state = 0;  // 0 untried, 1 mounted, 2 failed
    if (state == 0) {
      bool ok = LittleFS.begin();
      if (!ok) {  // blank flash: format once and retry
        LittleFS.format();
        ok = LittleFS.begin();
      }
      state = ok ? 1 : 2;
      if (ok) dropTmp();
    }
    return state == 1;
  }

  static int size(const char* flat) {
    char path[48];
    if (!pathOf(flat, path, sizeof(path), false)) return -1;
    File f = LittleFS.open(path, "r");
    if (!f) return -1;
    const int n = static_cast<int>(f.size());
    f.close();
    return n;
  }

  static int read(const char* flat, uint8_t* buf, size_t cap) {
    char path[48];
    if (!pathOf(flat, path, sizeof(path), false)) return -1;
    File f = LittleFS.open(path, "r");
    if (!f) return -1;
    const size_t n = f.read(buf, cap);
    f.close();
    return static_cast<int>(n);
  }

  static bool write(const char* flat, const uint8_t* buf, size_t len) {
    char path[48], tmp[48];
    if (!pathOf(flat, path, sizeof(path), false) || !pathOf(flat, tmp, sizeof(tmp), true)) return false;
    File f = LittleFS.open(tmp, "w");
    if (!f) return false;
    const size_t w = len ? f.write(buf, len) : 0;
    f.close();
    if (w != len) {
      LittleFS.remove(tmp);
      return false;
    }
    if (LittleFS.exists(path)) LittleFS.remove(path);
    return LittleFS.rename(tmp, path);
  }

  static bool erase(const char* flat) {
    char path[48];
    if (!pathOf(flat, path, sizeof(path), false)) return false;
    if (!LittleFS.exists(path)) return true;
    return LittleFS.remove(path);
  }

  static void each(void (*cb)(const char*, void*), void* ctx) {
    Dir d = LittleFS.openDir("/");
    while (d.next()) {
      String n = d.fileName();
      if (n.startsWith("kv_") && !n.endsWith(".tmp")) cb(n.c_str() + 3, ctx);
    }
  }

 private:
  static bool pathOf(const char* flat, char* out, size_t cap, bool tmp) {
    if (!flat) return false;
    const int n = snprintf(out, cap, "/kv_%s%s", flat, tmp ? ".tmp" : "");
    return n > 0 && static_cast<size_t>(n) < cap;
  }
  static void dropTmp() {
    Dir d = LittleFS.openDir("/");
    String stale[4];
    int k = 0;
    while (d.next() && k < 4) {
      String n = d.fileName();
      if (n.startsWith("kv_") && n.endsWith(".tmp")) stale[k++] = String("/") + n;
    }
    for (int i = 0; i < k; i++) LittleFS.remove(stale[i]);
  }
};

}  // namespace fry_boards
