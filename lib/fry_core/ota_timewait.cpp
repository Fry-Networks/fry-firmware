#include "ota_timewait.h"

#if !defined(ARDUINO) || defined(ARDUINO_ARCH_ESP8266)

#if defined(ARDUINO_ARCH_ESP8266)
extern "C" {
#include <lwip/priv/tcp_priv.h>
#include <lwip/tcp.h>
}
#endif

namespace fry {

// 217c2bb ran a due check whatever lwIP still held. Now: wait while TIME_WAIT pcbs remain, but never past
// the bound (see ota_timewait.h for why it is bounded).
TwHold decideTimeWaitHold(uint32_t twPcbs, uint32_t heldMs, uint32_t maxHoldMs) {
  if (twPcbs == 0) return TwHold::Proceed;
  return heldMs >= maxHoldMs ? TwHold::Proceed : TwHold::Hold;
}

#if defined(ARDUINO_ARCH_ESP8266)
uint32_t countTimeWaitPcbs() {
  uint32_t n = 0;
  for (const struct tcp_pcb* p = tcp_tw_pcbs; p; p = p->next) n++;
  return n;
}

static_assert(FIN_WAIT_1 == kTcpStateFinWait1 && FIN_WAIT_2 == kTcpStateFinWait2 && CLOSING == kTcpStateClosing &&
                  LAST_ACK == kTcpStateLastAck,
              "ota_timewait.h's tcp_state values must match lwIP's enum");

uint32_t countClosingPcbs() {
  uint32_t n = 0;
  for (const struct tcp_pcb* p = tcp_active_pcbs; p; p = p->next) {
    if (tcpStateIsClosing(static_cast<uint8_t>(p->state))) n++;
  }
  return n;
}
#endif

}  // namespace fry

#endif  // !ARDUINO || ARDUINO_ARCH_ESP8266
