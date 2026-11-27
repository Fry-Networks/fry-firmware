#pragma once
// src/core/hardwareapi_client.cpp reads the physical flash size through esp_flash_get_physical_size(); the board HAL answers it.
#include <stddef.h>
#include <stdint.h>

#include "fry_board_hal.h"

#if !defined(esp_err_t)  // LibreTiny #defines it
typedef int esp_err_t;
#endif
#ifndef ESP_OK
#define ESP_OK 0
#endif

inline esp_err_t esp_flash_get_physical_size(void*, uint32_t* out) {
  if (!out) return -1;
  *out = fry::board::flashInfo().realSize;
  return ESP_OK;
}
