#pragma once
// src/core/hardwareapi_client.cpp sends esp_reset_reason() as the heartbeat reset_reason (PROTOCOL.md 11.10). The numbering is the
// ESP32 one (1 power-on, 3 software, 5/6/7 watchdog, 9 brown-out); `os` says which chip's table applies.
#include <stdint.h>

#include "board_presets.h"
#include "fry_board_hal.h"

typedef int esp_reset_reason_t;

inline esp_reset_reason_t esp_reset_reason() { return fry::boards::resetReasonCode(fry::board::resetReason()); }
