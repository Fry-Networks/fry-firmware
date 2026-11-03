#pragma once
// No TLS session starts while the boot's asynchronous heap event can still land inside it (ESP8266 and host only).
//
// A persistent 504 B block is allocated between two loop passes 7770..7779 ms after the Wi-Fi connect (measured, see
// lib/fry_core/ota_first_check.h). A session that is live when it lands has its BearSSL blocks in the hole, so the 504 B
// request is placed above them and stays there once they are freed: the largest free block is cut for the rest of the boot
// and every later OTA manifest check is refused. Sessions last several seconds, so the boot registration and its retries,
// started right at the connect, straddle the event.
//
// The window is counted from the first TLS request of the boot. Every opener asks the gate before it allocates anything and is
// only reached once Wi-Fi is up, so that first request is never earlier than the connect. A closed gate is a deferral: the
// caller returns without recording a failure and asks again right after the gate opens.
#if !defined(ARDUINO) || defined(ARDUINO_ARCH_ESP8266)

#include <cstdint>

namespace fry {

// The measured 7.78 s plus about 1.2 s of margin. Not longer than kOtaFirstCheckAfterFirstTickMs (10 s).
constexpr uint32_t kBootAsyncEventDoneMs = 9000;

// Milliseconds still to wait before a TLS session may start; 0 means go. Wrap-safe on a 32-bit millisecond counter.
uint32_t tlsBootWaitMs(uint32_t nowMs, uint32_t firstCallMs);

}  // namespace fry

#endif  // !ARDUINO || ARDUINO_ARCH_ESP8266
