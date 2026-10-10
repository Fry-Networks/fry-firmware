#include "reconnect_backoff.h"

namespace fry {

namespace {

// nominal * [0.8, 1.2): rand32 == 0x80000000 lands exactly on nominal.
uint32_t jitter(uint32_t nominal, uint32_t rand32) {
  const uint64_t span = static_cast<uint64_t>(nominal) * 2 / 5;  // 40 % of nominal
  return nominal - nominal / 5 + static_cast<uint32_t>((span * rand32) >> 32);
}

}  // namespace

uint32_t ReconnectBackoff::onFailure(Failure kind, uint32_t rand32) {
  if (_attempts < 32) _attempts++;
  if (kind == Failure::Http4xx) return jitter(kHttp4xxMs, rand32);
  uint32_t nominal = kBaseMs;
  for (uint32_t i = 1; i < _attempts && nominal < kCapMs; i++) nominal *= 2;
  if (nominal > kCapMs) nominal = kCapMs;
  return jitter(nominal, rand32);
}

void ReconnectBackoff::onLinkDown(uint32_t upMs) {
  if (upMs >= kStableMs) _attempts = 0;
}

}  // namespace fry
