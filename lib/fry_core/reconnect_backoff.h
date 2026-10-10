#pragma once
// Reconnect schedule for the ESP8266 relay link, pure so it is natively tested.
//   transport error / 5xx : 30 s, 60 s, 120 s ... capped at 600 s
//   any HTTP 4xx on the upgrade : 1 h flat - every hwapi refusal is a 403 and will not fix
//                                 itself in seconds (and the edge counts 404s toward a ban)
//   every delay gets +-20 % jitter from the caller's random word, so a fleet that lost the server
//   together does not reconnect together
//   a link that stayed up >= 10 min resets the schedule
// hwapi (relay_ws.py) refuses a key's 13th connect within an hour, so even at the shortest
// jitter a failing or flapping link stays at <= 12 connects/h (pinned by a native test).
#include <cstdint>

namespace fry {

class ReconnectBackoff {
 public:
  static constexpr uint32_t kBaseMs = 30000;
  static constexpr uint32_t kCapMs = 600000;
  static constexpr uint32_t kHttp4xxMs = 3600000;
  static constexpr uint32_t kStableMs = 600000;

  enum class Failure : uint8_t { Transport, Http4xx };

  // Delay before the next attempt. `rand32` is any random word (os_random() on the chip).
  uint32_t onFailure(Failure kind, uint32_t rand32);
  // Call when a link that was up goes down after `upMs`.
  void onLinkDown(uint32_t upMs);

  uint32_t attempts() const { return _attempts; }

 private:
  uint32_t _attempts = 0;
};

}  // namespace fry
