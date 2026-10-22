#include "ota_settle.h"

#if !defined(ARDUINO) || defined(ARDUINO_ARCH_ESP8266)

namespace fry {

// Before: the download's clients were built the moment the manifest's were gone, whatever lwIP still held of the connection. Now: wait while
// the largest block is short of where the check started, never past the bound (see ota_settle.h).
SettleHold decideHeapSettle(uint32_t blkNow, uint32_t blkBefore, uint32_t slackBytes, uint32_t heldMs, uint32_t maxHoldMs) {
  const uint32_t want = blkBefore > slackBytes ? blkBefore - slackBytes : 0;
  if (blkNow >= want) return SettleHold::Proceed;
  return heldMs >= maxHoldMs ? SettleHold::Proceed : SettleHold::Hold;
}

}  // namespace fry

#endif  // !ARDUINO || ARDUINO_ARCH_ESP8266
