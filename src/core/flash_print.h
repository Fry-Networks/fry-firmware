#pragma once
// Serial prints whose text stays in flash on the ESP8266.
//
// The ESP8266 keeps a plain string literal in DRAM, and every byte of static RAM is a byte the heap does not have (the heap is
// [_heap_start, 0x3FFFC000)). The OTA download needs one 16 KB-record TLS session on an 80 KB part, so the log strings of a build
// that only ever prints them count against it. printf_P(PSTR()) / println(F()) read the same text from flash: the output is
// byte for byte what the plain call printed. The ESP32 family has no such split and keeps the call it always had.
#include <Arduino.h>

#if defined(ARDUINO_ARCH_ESP8266)
#define FRY_PRINTF(fmt, ...) Serial.printf_P(PSTR(fmt), ##__VA_ARGS__)
#define FRY_PRINTLN(text) Serial.println(F(text))
#define FRY_PRINT(text) Serial.print(F(text))
#else
#define FRY_PRINTF(fmt, ...) Serial.printf(fmt, ##__VA_ARGS__)
#define FRY_PRINTLN(text) Serial.println(text)
#define FRY_PRINT(text) Serial.print(text)
#endif
