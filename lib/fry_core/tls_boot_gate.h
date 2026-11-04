#pragma once
// No TLS session starts while the boot's asynchronous heap event can still land inside it (ESP8266 and host only).
//
// A persistent 504 B block is allocated between two loop passes 7770..7779 ms after the Wi-Fi connect (measured, see
// lib/fry_core/ota_first_check.h). A session that is live when it lands has its BearSSL blocks in the hole, so the 504 B
// request is placed above them and stays there once they are freed: the largest free block is cut for the rest of the boot
// and every later OTA manifest check is refused. Sessions last several seconds, so the boot registration and its retries,
// started right at the connect, straddle the event.
//
// The window is counted from the Wi-Fi connect, never from boot time and never from the first request: the anchor is the later
// of the moment the address was obtained and the moment the station associated plus kAssocToDetectLeadMs. Until a connect has
// been seen the gate stays closed. Every link-up moves the anchor, so a reconnect re-arms the gate. A closed gate is a
// deferral: the caller returns without recording a failure and asks again right after the gate opens.
#if !defined(ARDUINO) || defined(ARDUINO_ARCH_ESP8266)

#include <cstdint>

namespace fry {

// The measured 7.78 s plus about 1.2 s of margin. Not longer than kOtaFirstCheckAfterFirstTickMs (10 s).
constexpr uint32_t kBootAsyncEventDoneMs = 9000;

// Where the association-to-address time is assumed to be at least this long when only the association was seen; keeps the
// anchor on the measured side when the address arrives faster than usual.
constexpr uint32_t kAssocToDetectLeadMs = 2500;

// Anchor of the window from the two link-up stamps: the later of detect and assoc + lead (wrap-safe). With only one stamp
// that one is used (assoc + lead, or detect). Returns false when neither was seen.
bool connectAnchorMs(uint32_t detectMs, bool haveDetect, uint32_t assocMs, bool haveAssoc, uint32_t* anchorOut);

// Window counted from the connect: the full window while no connect has been seen, else tlsBootWaitMs from the anchor (an anchor
// still ahead of now adds the distance to it).
uint32_t tlsConnectWaitMs(uint32_t nowMs, uint32_t connectMs, bool haveConnect);

// Milliseconds still to wait before a TLS session may start; 0 means go. Wrap-safe on a 32-bit millisecond counter.
uint32_t tlsBootWaitMs(uint32_t nowMs, uint32_t firstCallMs);

}  // namespace fry

#endif  // !ARDUINO || ARDUINO_ARCH_ESP8266
