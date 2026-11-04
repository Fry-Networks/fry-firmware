#pragma once
// Release the OTA check's hold on free heap, not only on the TIME_WAIT clock.
//
// ota_timewait.h holds a due check while closed connections linger (up to 130 s). Under registration 5xx the retries refresh those pcbs,
// so the check ran at the bound and could still find the heap short (observed bench case: "need blk>=30096 free>=35560, have blk=32680
// free=34872"). The hold exists only to wait for a heap the next TLS begin accepts, so it ends as soon as that heap is there: free and
// largest block both at the download gate (the stricter of the OTA steps; see UNITS below). The bound is unchanged and the decision only ever delays: the check is never skipped.
//
// ESP8266 and host only, like ota_timewait.h.
#if !defined(ARDUINO) || defined(ARDUINO_ARCH_ESP8266)

#include <cstdint>

#include "ota_heap_budget.h"
#include "ota_timewait.h"
#include "tls_sizing.h"

namespace fry {

// UNITS. The hold samples the heap BEFORE the TLS clients exist, so it compares against the download GATE itself (kDownloadGateFree /
// kDownloadGateBlock: 42280 / 36816, "pre-constructor" units), exactly as the OTA gate does. tlsFloorsAtBegin() (35560 / 30096) is the
// same bar seen AFTER the constructor has taken kBearsslStackThunkBytes + kOtaClientsBytes (http_tls.cpp: beginHttpsUrl); using those
// post-constructor numbers on a pre-constructor sample would release the hold too early by 6720 B.
constexpr uint32_t kOtaHoldReleaseFree = ota_heap::kDownloadGateFree;
constexpr uint32_t kOtaHoldReleaseBlock = ota_heap::kDownloadGateBlock;

// Proceed when decideTimeWaitHold would (no pcbs, or the bound reached), or when freeNow and blockNow both meet the floors.
inline TwHold decideHoldRelease(uint32_t pcbs, uint32_t heldMs, uint32_t maxHoldMs, uint32_t freeNow, uint32_t blockNow) {
  if (decideTimeWaitHold(pcbs, heldMs, maxHoldMs) == TwHold::Proceed) return TwHold::Proceed;
  return (freeNow >= kOtaHoldReleaseFree && blockNow >= kOtaHoldReleaseBlock) ? TwHold::Proceed : TwHold::Hold;
}

}  // namespace fry

#endif  // !ARDUINO || ARDUINO_ARCH_ESP8266
