// Built only by the Pico / BK7231N envs (platformio.boards.ini defines FRY_BOARDS_PORT); the ESP envs compile all of src/.
#if defined(FRY_BOARDS_PORT)
// Translation unit of ../core/hardwareapi_client.cpp with the ESP-named platform calls answered by the board HAL (see esp_compat.h). The source is included
// unchanged.
#include "esp_compat.h"
#include "../core/hardwareapi_client.cpp"
#endif  // FRY_BOARDS_PORT
