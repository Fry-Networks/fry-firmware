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

// ---- the wait BEFORE the check -------------------------------------------------------------------------------------------------
// The report tick (registration, telemetry, PoC) runs right before a check, and its connection leaves the same kind of blocks in the middle of the
// free region: a 24 B block, or a 192 B pcb with its 112 B pbuf, for a few milliseconds to a few seconds after the connection is closed.
//   x3-tip bench capture (lo/c1-x3t-204146.lines.txt), seven check cycles:
//   cycle C: a 24 B block at 11688 was alive at the check start (blk 32360 instead of the settled 39448). settleAfterManifest takes "blk at the
//            check start" as its reference, so it was satisfied at its first look (no "settled" line, the five clean cycles waited 20-80 ms) and
//            released the download onto a heap the manifest connection's own survivors split: download-begin blk 26280 instead of 32808.
//   cycle G: a 192 B + 112 B pair alive at the check start: blk 29776, and the manifest gate (blk >= 29808) skipped the whole check.
// A check that starts on a heap that has not settled cannot tell, because the reference it would use is the unsettled heap itself. So the
// baseline is what EARLIER checks started on: the largest block seen at a check start of this boot, kept in one word. The check waits (bounded,
// same bound, poll and slack as the wait after the manifest) until the block is back to it, and only then measures s_blkAtCheckStart and samples
// the manifest gate. It rises as the heap recovers and never falls by itself; when the bound is reached with the block still short, the heap
// did not recover (a persistent block landed mid-heap: dl-31's 40 B at 12544 cuts the settled blk from 38040 to 30072) and the block seen becomes
// the new level, so only the first check after it pays the wait. The first check of a boot has no baseline: it waits until the block has been the
// same for kOtaCheckStartStableMs.
constexpr uint32_t kOtaCheckStartStableMs = 1000;

// blkNow: the largest free block now. baseline: the largest block an earlier check started on this boot (0 = none yet). heldMs: how long this
// check has already waited. stableMs: how long blkNow has been unchanged. Proceeds once the block is back within slackBytes of the baseline (or
// above it); with no baseline, once it has been still for kOtaCheckStartStableMs; always at maxHoldMs.
SettleHold decideCheckStartSettle(uint32_t blkNow, uint32_t baseline, uint32_t slackBytes, uint32_t heldMs, uint32_t stableMs, uint32_t maxHoldMs);

// The baseline after the wait: the larger of it and the block the check starts on; except that when the wait ran into its bound with the block
// still below the baseline, the block seen is the new baseline.
uint32_t nextCheckStartBaseline(uint32_t baseline, uint32_t blkAtProceed, bool boundReached);

}  // namespace fry

#endif  // !ARDUINO || ARDUINO_ARCH_ESP8266
