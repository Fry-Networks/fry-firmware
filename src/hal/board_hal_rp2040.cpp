// Built only by the Pico / BK7231N envs (platformio.boards.ini defines FRY_BOARDS_PORT); the ESP envs compile all of src/.
#if defined(FRY_BOARDS_PORT)
// fry::board::BoardHal for the Raspberry Pi Pico W (RP2040) and Pico 2 W (RP2350) on arduino-pico.
#if defined(FRY_BOARD_PICO)
#include <Arduino.h>
#include <LittleFS.h>
#include <WiFi.h>
#include <hardware/watchdog.h>

#include "fry_board_hal.h"

#ifndef FRY_CHIP
#define FRY_CHIP "RP2040"
#endif
#ifndef FRY_BUILD_ENV
#define FRY_BUILD_ENV "rp2040"
#endif
#ifndef PICO_FLASH_SIZE_BYTES
#define PICO_FLASH_SIZE_BYTES (2 * 1024 * 1024)
#endif

extern "C" char __flash_binary_end;  // end of the running image in flash (pico-sdk linker script)

namespace fry {
namespace board {

const char* chipTag() { return FRY_CHIP; }
const char* buildEnv() { return FRY_BUILD_ENV; }
uint32_t uptimeMs() { return millis(); }
void restart() {
  rp2040.reboot();
  for (;;) {
  }
}
uint32_t freeHeap() { return static_cast<uint32_t>(rp2040.getFreeHeap()); }
// newlib's mallinfo has no largest-free-block figure; the total free heap is the upper bound a gate can use here.
uint32_t maxFreeBlock() { return static_cast<uint32_t>(rp2040.getFreeHeap()); }

bool macAddress(uint8_t out[6]) {
  if (!out) return false;
  WiFi.macAddress(out);
  return true;
}

uint32_t random32() { return rp2040.hwrand32(); }

// The ROM latches whether the last reset came from the watchdog (also what rp2040.reboot() uses); everything else is a power-on.
const char* resetReason() { return watchdog_caused_reboot() ? "wdt" : "poweron"; }

FlashInfo flashInfo() {
  static FlashInfo cached = {0, 0, 0, 0};
  static bool have = false;
  if (!have) {
    cached.realSize = PICO_FLASH_SIZE_BYTES;
    cached.ideSize = PICO_FLASH_SIZE_BYTES;
    cached.sketchSize = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&__flash_binary_end) - XIP_BASE);
    have = true;
  }
  // The next image is staged in LittleFS (arduino-pico Updater), so the room for it is the filesystem's free space. Read fresh:
  // it changes as the KV files are written.
  FlashInfo f = cached;
  FSInfo info;
  if (LittleFS.begin() && LittleFS.info(info) && info.totalBytes > info.usedBytes) {
    f.otaFreeBytes = static_cast<uint32_t>(info.totalBytes - info.usedBytes);
  }
  return f;
}

// The hardware watchdog is not armed on these boards (the TLS handshake and the image download block for seconds); a pet is
// harmless when it is not.
void feedWatchdog() {}

bool readButton(int pin) {
  if (pin < 0) return false;
  return digitalRead(pin) == LOW;
}

}  // namespace board
}  // namespace fry
#endif  // FRY_BOARD_PICO
#endif  // FRY_BOARDS_PORT
