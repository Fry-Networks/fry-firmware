#pragma once
// ESP8266: when does the next OTA manifest check run after one that was refused for lack of heap?
//
// tick() used to set the next check OTA_CHECK_MS (6 h) after every attempt, whatever happened: a board that is fragmented at its
// first check (blk 29.1 K at the 8 s boot sample, lo/c1-p3-125815.lines.txt) lost its update window for 6 h. A refusal by a heap
// gate opens no connection (the gate is one free-heap sample taken before the clients exist; beginHttpsUrl's Refuse is decided
// before http.begin), so asking again soon costs nothing on the wire. Everything else - an answer, a parse failure, HTTP -1 -
// keeps the 6 h cadence, because those cost a handshake and a TIME_WAIT pcb.
//
// Bounded: kOtaHeapRetryMax shorter waits in a row, then the normal cadence until a check gets past the heap gates.
// Pure and header-only so it is tested natively; tick() calls it on ESP8266 only (the ESP32 family is untouched).
#include <cstdint>

namespace fry {

constexpr uint32_t kOtaHeapRetryMs = 10UL * 60UL * 1000UL;  // 10 min
constexpr uint8_t kOtaHeapRetryMax = 6;                      // at most an hour of retries, then back to the normal cadence

// Delay until the next check. `retries` counts the shorter waits already used in the current run of refusals: it advances on
// every refusal that is answered with a retry and resets on any check that was not refused for heap.
inline uint32_t otaNextCheckDelayMs(bool refusedForHeap, uint8_t& retries, uint32_t normalMs) {
  if (!refusedForHeap) {
    retries = 0;
    return normalMs;
  }
  if (retries >= kOtaHeapRetryMax) return normalMs;
  retries++;
  return kOtaHeapRetryMs < normalMs ? kOtaHeapRetryMs : normalMs;
}

}  // namespace fry
