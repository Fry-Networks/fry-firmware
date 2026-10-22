#pragma once
// Let the manifest connection's teardown finish before the image download builds its clients (ESP8266).
//
// The manifest session ends with the connection's last allocations still alive: closing it leaves a 192 B tcp_pcb (sizeof(struct tcp_pcb) is
// 184), the 112 B pbuf of the last TLS record and its 24 B tcp_seg (16 B + header) in lwIP until the peer's FIN/ACK frees them, which takes
// from a few milliseconds to a second. The download's constructors run a millisecond after the session's clients are gone, so they run on a
// heap that still has those blocks in it. umm_malloc is best-fit and carves the low end of the block it picks: where the survivors sit
// decides where the download's 432 B work block and 6208 B BearSSL stack thunk go, and so what is left of the large free region.
//   bench X2 (lo/c1-x2-183903.lines.txt, c1/reports/settle-*.md): the download's blk after its constructors was 29072, 29072, 23000, 22648,
//   22648, 22648, 15008 over seven consecutive checks of one unchanged board: a 24 B survivor above the freed thunk slot made the 712 B of
//   clients take that slot and push the thunk into the big block (-6.1 KB); one 192 B and one 112 B survivor in the middle of the big block
//   split it in two (15008). The real umm_malloc replays of those heaps give the same numbers (c1/logs/settle-host-replay.log).
//
// So the check waits, bounded, until the largest free block is back to what it was when the check started, then goes on. It never waits for
// anything that is not coming back: a heap that does not recover (a TIME_WAIT pcb in the middle, a real leak) is let through after
// kOtaSettleMaxMs, exactly as before, and the download's own gate decides.
//
// ESP8266 and host only: the ESP32's heap is not split by these blocks, so the translation unit is empty there and the ESP32 images are
// untouched.
#if !defined(ARDUINO) || defined(ARDUINO_ARCH_ESP8266)

#include <cstdint>

namespace fry {

// Longest the check waits for the connection's blocks to come back. They were gone within 60 ms in the benign bench cases and always before
// the next check; 5 s is two orders above that and short against a download that blocks the loop for a minute and a check every 6 h.
constexpr uint32_t kOtaSettleMaxMs = 5000;
constexpr uint32_t kOtaSettlePollMs = 20;  // delay() between looks: lwIP's input and timers run in it
// The criterion is the LARGEST BLOCK, not the free total: the survivors are small (24, 112 and 192 B, 328 B together) but any one of them
// splits the region, so waiting for the total would let the 24 B one through. The slack is how far under the starting block still counts as
// back: the check may keep a small block it did not have at the start (none is intended), and one umm block is 8 B.
constexpr uint32_t kOtaSettleSlackBytes = 64;

enum class SettleHold : uint8_t {
  Proceed,  // build the download's clients now
  Hold,     // look again after kOtaSettlePollMs
};

// blkNow: the largest free block now. blkBefore: the largest free block when the check started (after its plan Strings were reserved).
// heldMs: how long this check has already waited (0 on the first look). Proceeds once the block is back within slackBytes of where it was
// (or above it), or when the bound is reached whatever the heap looks like.
SettleHold decideHeapSettle(uint32_t blkNow, uint32_t blkBefore, uint32_t slackBytes, uint32_t heldMs, uint32_t maxHoldMs);

}  // namespace fry

#endif  // !ARDUINO || ARDUINO_ARCH_ESP8266
