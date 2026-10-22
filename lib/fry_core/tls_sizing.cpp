#include "tls_sizing.h"

#if !defined(ARDUINO) || defined(ARDUINO_ARCH_ESP8266)

#include "heap_gate.h"

namespace fry {

// Replaces src/esp8266/http_tls.cpp:62-78 of 217c2bb, where any unaffordable heap fell back to
// 512/512 whatever the peer was. Every other branch is unchanged.
TlsPlan planTls(const HeapSample& sample, uint32_t minFreeTotal, uint32_t minBlock,
                bool peerMightHonourMfln, bool smallReply) {
  const bool affordable = heapGatePass(sample.freeTotal, sample.maxBlock, minFreeTotal, minBlock);
  TlsSizing sizing;
  if (!affordable) {
    // 512/512 only carries a peer that negotiates a small fragment length. A peer that does not
    // (GitHub) answers with 16 KB records the buffer cannot hold; connecting anyway is what
    // soft-reset the 0.3.3 bench board, so the session is not opened.
    sizing = peerMightHonourMfln ? TlsSizing::Small : TlsSizing::Refuse;
  } else {
    sizing = peerMightHonourMfln ? TlsSizing::ProbeFirst : (smallReply ? TlsSizing::Medium : TlsSizing::Big);
  }
  return {sizing, affordable};
}

}  // namespace fry

#endif  // !ARDUINO || ARDUINO_ARCH_ESP8266
