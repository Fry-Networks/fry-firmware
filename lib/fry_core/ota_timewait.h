#pragma once
// Hold an OTA check back while lwIP still has closed connections in TIME_WAIT.
//
// Measured on the bench ESP8266 (heaptrace image, steady state): the boot-time TLS calls to hardwareapi
// leave two pcbs in TIME_WAIT until about t=128 s; while they exist the largest free block is
// 28536 B, and when they expire it becomes 36320 B (+7784) while the TOTAL free heap moves only +408.
// The pcbs sit in the middle of the free heap and split the one block BearSSL's 16384 B receive buffer
// needs. The boot check (t~8 s) and any check that follows other TLS traffic by under two minutes
// therefore sees a heap that is smaller than the same heap will be moments later, and is skipped by
// the gate - which is why no ESP8266 ever completed a manifest check.
//
// lwIP keeps a closed connection's pcb for 2 x TCP_MSL (lwip2 tcp_priv.h: TCP_MSL 60000 ms), so the
// wait is bounded by the protocol, but other traffic can start a new 120 s window. The hold is
// therefore itself bounded (kOtaTimeWaitMaxHoldMs): a device whose pcbs never clear still checks, as
// it did before, instead of being starved. The hold never blocks: the OTA tick returns and the
// decision is taken again on the next loop pass.
//
// A pcb is also in the middle of the heap while this side is CLOSING its connection, before it reaches TIME_WAIT: FIN_WAIT_1 and FIN_WAIT_2
// (until the peer's FIN, up to TCP_FIN_WAIT_TIMEOUT = 20 s), CLOSING, LAST_ACK. The boot registration's connection is in one of them at 8.3 s
// (the sw9 capture: tw=0 there, tw=1 1.2 s later), so a hold that counts only TIME_WAIT let the first check start in that gap. The hold
// counts those states too (countClosingPcbs); the bound is unchanged, so a pcb stuck in one of them cannot starve a check either.
//
// ESP8266 and host only: ESP32's heap is not split by these pcbs (blk 110580 on the bench), so the
// translation unit is empty there and the ESP32/C3 images are untouched.
#if !defined(ARDUINO) || defined(ARDUINO_ARCH_ESP8266)

#include <cstdint>

namespace fry {

constexpr uint32_t kTcpMslMs = 60000;                // lwip2 TCP_MSL
constexpr uint32_t kTcpTimeWaitMs = 2 * kTcpMslMs;   // how long a closed connection's pcb lingers
constexpr uint32_t kTcpSlowTimerMs = 500;            // TCP_SLOW_INTERVAL: granularity of that expiry
// Longest a single check is held: the TIME_WAIT of the boot-time calls (120 s, measured 120 s from
// t~8 s to t~128 s) plus 10 s for the slow-timer granularity and the loop cadence. Short against the
// 6 h check interval (0.6 %), long enough that the pcbs of ONE burst of traffic always clear inside it.
constexpr uint32_t kOtaTimeWaitMaxHoldMs = kTcpTimeWaitMs + 10000;

enum class TwHold : uint8_t {
  Proceed,  // run the check now
  Hold,     // leave it due and look again on the next loop pass
};

// twPcbs: lwIP TIME_WAIT pcbs now. heldMs: how long this check has already been held (0 on the first
// look). Proceeds when none remain, or when the bound is reached whatever remains.
TwHold decideTimeWaitHold(uint32_t twPcbs, uint32_t heldMs, uint32_t maxHoldMs);

// lwIP tcp_state values (lwip/tcpbase.h; the ESP8266 translation unit static_asserts them against the enum): FIN_WAIT_1, FIN_WAIT_2, CLOSING and
// LAST_ACK are the states of an active pcb whose close this side started and the peer has not finished. CLOSE_WAIT (7) is the peer closing
// first: the application still owns that connection. TIME_WAIT (10) pcbs live in tcp_tw_pcbs and are counted from there.
constexpr uint8_t kTcpStateFinWait1 = 5;
constexpr uint8_t kTcpStateFinWait2 = 6;
constexpr uint8_t kTcpStateClosing = 8;
constexpr uint8_t kTcpStateLastAck = 9;

constexpr bool tcpStateIsClosing(uint8_t state) {
  return state == kTcpStateFinWait1 || state == kTcpStateFinWait2 || state == kTcpStateClosing || state == kTcpStateLastAck;
}

#if defined(ARDUINO_ARCH_ESP8266)
// Length of lwIP's tcp_tw_pcbs list.
uint32_t countTimeWaitPcbs();
// Pcbs of tcp_active_pcbs in a closing state (tcpStateIsClosing).
uint32_t countClosingPcbs();
#endif

}  // namespace fry

#endif  // !ARDUINO || ARDUINO_ARCH_ESP8266
