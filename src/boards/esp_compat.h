#pragma once
// The ESP-named platform calls the shared core files make (ESP.getFreeHeap(), ESP.getFreeSketchSpace() ...), answered by the board
// HAL. Included by the wrap_*.cpp translation units in this directory, which then #include the unchanged src/core / lib/fry_core
// source: no core file is edited, and the macro exists only inside those translation units.
//   ESP.getFreeHeap / getMaxAllocHeap   -> fry::board::freeHeap / maxFreeBlock
//   ESP.getFlashChipSize / RealSize     -> FlashInfo.ideSize / realSize
//   ESP.getFreeSketchSpace / SketchSize -> FlashInfo.otaFreeBytes / sketchSize
//   ESP.restart                         -> fry::board::restart
#include <Arduino.h>

#include "fry_board_hal.h"

struct FryEspShim {
  uint32_t getFreeHeap() const { return fry::board::freeHeap(); }
  uint32_t getMaxAllocHeap() const { return fry::board::maxFreeBlock(); }
  uint32_t getFlashChipSize() const { return fry::board::flashInfo().ideSize; }
  uint32_t getFlashChipRealSize() const { return fry::board::flashInfo().realSize; }
  uint32_t getFreeSketchSpace() const { return fry::board::flashInfo().otaFreeBytes; }
  uint32_t getSketchSize() const { return fry::board::flashInfo().sketchSize; }
  void restart() const { fry::board::restart(); }
};
static const FryEspShim fry_esp_shim = {};
#define ESP fry_esp_shim

#if defined(FRY_BOARD_BK7231N)
// LibreTiny's HTTPClient has no getString() (commented out in its header) and no configTime(): both are supplied here, for the
// translation units that include this header only. The real type is subclassed AFTER http_tls.h declared its functions on it, so
// the shared helpers still take it by reference.
#include <StreamString.h>

#include "../core/http_tls.h"
#include "ntp_compat.h"

class FryHttpClient : public HTTPClient {
 public:
  String getString() {
    StreamString s;
    const int n = getSize();
    if (n > 0 && n < 65536) s.reserve(static_cast<unsigned>(n) + 1);
    writeToStream(&s);
    return String(s);
  }
};
#define HTTPClient FryHttpClient
#endif
