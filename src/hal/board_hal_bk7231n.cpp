// Built only by the Pico / BK7231N envs (platformio.boards.ini defines FRY_BOARDS_PORT); the ESP envs compile all of src/.
#if defined(FRY_BOARDS_PORT)
// fry::board::BoardHal for the Beken BK7231N on LibreTiny.
#if defined(FRY_BOARD_BK7231N)
#include <Arduino.h>
#include <WiFi.h>
#include <libretiny.h>

#include "fry_board_hal.h"

#ifndef FRY_CHIP
#define FRY_CHIP "BK7231N"
#endif
#ifndef FRY_BUILD_ENV
#define FRY_BUILD_ENV "bk7231n"
#endif

namespace fry {
namespace board {

const char* chipTag() { return FRY_CHIP; }
const char* buildEnv() { return FRY_BUILD_ENV; }
uint32_t uptimeMs() { return millis(); }
void restart() {
  lt_reboot();
  for (;;) {
  }
}
uint32_t freeHeap() { return lt_heap_get_free(); }
uint32_t maxFreeBlock() { return lt_heap_get_max_alloc(); }

bool macAddress(uint8_t out[6]) {
  if (!out) return false;
  WiFi.macAddress(out);
  return true;
}

extern "C" int os_get_random(unsigned char* buf, size_t len);  // Beken SDK (hostapd os layer), the SDK's own random source

// Random word for the one-time salt (hashed with the MAC, never sent). The SDK's os_get_random is the source; the libc rand() word
// and the free-running microsecond counter are mixed in so a failed SDK call still yields a different value every boot.
uint32_t random32() {
  uint8_t b[4] = {0, 0, 0, 0};
  const bool ok = os_get_random(b, sizeof(b)) == 0;
  uint8_t r[4];
  lt_rand_bytes(r, sizeof(r));
  uint32_t v = static_cast<uint32_t>(b[0]) << 24 | static_cast<uint32_t>(b[1]) << 16 | static_cast<uint32_t>(b[2]) << 8 | b[3];
  v ^= static_cast<uint32_t>(r[0]) << 24 | static_cast<uint32_t>(r[1]) << 16 | static_cast<uint32_t>(r[2]) << 8 | r[3];
  if (!ok) v ^= micros() * 2654435761u;
  return v;
}

const char* resetReason() {
  switch (lt_get_reboot_reason()) {
    case REBOOT_REASON_POWER: return "poweron";
    case REBOOT_REASON_BROWNOUT: return "brownout";
    case REBOOT_REASON_HARDWARE: return "external";
    case REBOOT_REASON_SOFTWARE: return "software";
    case REBOOT_REASON_WATCHDOG: return "wdt";
    case REBOOT_REASON_CRASH: return "panic";
    default: return "unknown";
  }
}

FlashInfo flashInfo() {
  static FlashInfo cached = {0, 0, 0, 0};
  static bool have = false;
  if (!have) {
    cached.realSize = lt_flash_get_size();
    cached.ideSize = cached.realSize;
    // The Tuya QFN32 layout (boards/_base/beken-7231n-tuya.json): app 0x119000 bytes, download 0xA6000. The UF2 stream is written
    // into the download area, so that is the room for the next image; the running image is the app partition's used part, which
    // the SDK does not report, so the partition size stands in.
    cached.otaFreeBytes = 0xA6000;
    cached.sketchSize = 0x119000;
    have = true;
  }
  return cached;
}

void feedWatchdog() { lt_wdt_feed(); }

bool readButton(int pin) {
  if (pin < 0) return false;
  return digitalRead(pin) == LOW;
}

}  // namespace board
}  // namespace fry
#endif  // FRY_BOARD_BK7231N
#endif  // FRY_BOARDS_PORT
