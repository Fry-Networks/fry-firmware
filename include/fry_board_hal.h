// Board HAL: the platform services new-chip code needs, declared once and implemented per platform in
// src/hal/board_hal_<plat>.cpp. Declarations only; no Arduino include (host-compilable).
#ifndef FRY_BOARD_HAL_H
#define FRY_BOARD_HAL_H

#include <stdint.h>

namespace fry {
namespace board {

const char* chipTag();   // "ESP8266","ESP32","ESP32-S3","ESP32-C3","RP2040","RP2350","BK7231N"
const char* buildEnv();  // FRY_BUILD_ENV string (the heartbeat os value)
uint32_t uptimeMs();
void restart();  // never returns
uint32_t freeHeap();
uint32_t maxFreeBlock();
bool macAddress(uint8_t out[6]);
uint32_t random32();  // hardware RNG
const char* resetReason();  // short token

struct FlashInfo {
  uint32_t realSize, ideSize, otaFreeBytes, sketchSize;
};
FlashInfo flashInfo();

void feedWatchdog();
bool readButton(int pin);  // active-low reset button helper

}  // namespace board
}  // namespace fry

#endif  // FRY_BOARD_HAL_H
