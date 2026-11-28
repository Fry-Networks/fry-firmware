// Built only by the Pico / BK7231N envs (platformio.boards.ini defines FRY_BOARDS_PORT); the ESP envs compile all of src/.
#if defined(FRY_BOARDS_PORT)
// configTime() for the BK7231N over the lwIP SNTP client LibreTiny builds (lwipopts.h: SNTP_SET_SYSTEM_TIME_US -> settimeofday).
#include <Arduino.h>

#include "../boards/ntp_compat.h"

extern "C" {
#include <lwip/apps/sntp.h>
}

void configTime(long, int, const char* server1, const char* server2) {
  static bool started = false;
  if (!started) {
    sntp_setoperatingmode(SNTP_OPMODE_POLL);
    if (server1) sntp_setservername(0, server1);
    if (server2) sntp_setservername(1, server2);
    sntp_init();
    started = true;
  }
}
#endif  // FRY_BOARDS_PORT
