#pragma once
// configTime(gmtOffset, dstOffset, server1, server2): arduino-pico maps it onto its NTP class; LibreTiny has no such call, so on the
// BK7231N it starts the lwIP SNTP client (the SDK's lwipopts set the system clock from it, which is what time() then reads).
#include <Arduino.h>

#if defined(FRY_BOARD_BK7231N)
void configTime(long gmtOffsetSec, int daylightOffsetSec, const char* server1, const char* server2 = nullptr);
#endif
