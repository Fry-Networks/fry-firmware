#pragma once
// snprintf whose FORMAT stays in flash on the ESP8266.
//
// The ESP8266 keeps a plain string literal in DRAM, and the heap is whatever static RAM leaves: every byte of format text is a byte the
// image download's TLS session does not have. FRY_SNPRINTF(out, n, "fmt", args...) is snprintf_P(PSTR()) there and the snprintf it always
// was on the ESP32 family and on the host, so those images and the host tests do not change. (src/core/flash_print.h is the Serial twin.)
// The arguments are untouched: only the format is read from flash, a %s argument is still a RAM pointer.
#include <stdio.h>

#if defined(ARDUINO_ARCH_ESP8266)
#include <pgmspace.h>
#define FRY_SNPRINTF(out, n, fmt, ...) snprintf_P((out), (n), PSTR(fmt), ##__VA_ARGS__)
#else
#define FRY_SNPRINTF(out, n, fmt, ...) snprintf((out), (n), fmt, ##__VA_ARGS__)
#endif
