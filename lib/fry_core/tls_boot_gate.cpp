#include "tls_boot_gate.h"

#if !defined(ARDUINO) || defined(ARDUINO_ARCH_ESP8266)

namespace fry {

uint32_t tlsBootWaitMs(uint32_t nowMs, uint32_t firstCallMs) {
  const uint32_t elapsed = static_cast<uint32_t>(nowMs - firstCallMs);
  return elapsed >= kBootAsyncEventDoneMs ? 0 : kBootAsyncEventDoneMs - elapsed;
}

bool connectAnchorMs(uint32_t detectMs, bool haveDetect, uint32_t assocMs, bool haveAssoc, uint32_t* anchorOut) {
  const uint32_t assocAnchor = assocMs + kAssocToDetectLeadMs;
  uint32_t a;
  if (haveDetect && haveAssoc) {
    a = static_cast<int32_t>(detectMs - assocAnchor) >= 0 ? detectMs : assocAnchor;
  } else if (haveDetect) {
    a = detectMs;
  } else if (haveAssoc) {
    a = assocAnchor;
  } else {
    return false;
  }
  *anchorOut = a;
  return true;
}

uint32_t tlsConnectWaitMs(uint32_t nowMs, uint32_t connectMs, bool haveConnect) {
  if (!haveConnect) return kBootAsyncEventDoneMs;
  // The anchor can lie ahead of now only by association + lead: the whole window still has to pass after it.
  // A larger forward distance is an anchor so old that the counter has passed half its range, so it is long past.
  const int32_t ahead = static_cast<int32_t>(connectMs - nowMs);
  if (ahead > 0 && static_cast<uint32_t>(ahead) <= kAssocToDetectLeadMs) return static_cast<uint32_t>(ahead) + kBootAsyncEventDoneMs;
  return tlsBootWaitMs(nowMs, connectMs);
}

}  // namespace fry

#endif  // !ARDUINO || ARDUINO_ARCH_ESP8266
