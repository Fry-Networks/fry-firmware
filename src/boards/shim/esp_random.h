#pragma once
// src/core/miner_key.cpp seeds the one-time salt from esp_random(); the board HAL's hardware RNG answers it here.
#include <stdint.h>

#include "fry_board_hal.h"

inline uint32_t esp_random() { return fry::board::random32(); }
