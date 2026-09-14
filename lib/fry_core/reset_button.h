// ResetButton — debounced long-hold detector for the physical BOOT button.
//
// Recovery of last resort. If the provisioning transport cannot help — the stored credentials are
// valid enough to join a network that is not the user's, the board was provisioned to the wrong
// wallet, or the owner simply wants to hand it on — the user needs a way to clear stored state
// without a USB cable and a toolchain. Every board this firmware targets exposes the same BOOT
// button on GPIO0, active-low.
//
// Deliberately long to hold: a short press on GPIO0 is a common accident, and a factory reset
// that fires by accident is worse than no factory reset at all.
//
// Pure logic on a caller-supplied clock, so the native Unity suite covers it.
#pragma once

#include <stdint.h>

namespace fry {

// How long the button must be held continuously before a reset fires.
constexpr uint32_t kFactoryResetHoldMs = 10000;

class ResetButton {
 public:
  explicit ResetButton(uint32_t holdMs = kFactoryResetHoldMs) : _holdMs(holdMs) {}

  // Feed the debounced button state once per loop, with a monotonic millisecond clock.
  // Returns true EXACTLY ONCE per hold, at the moment the threshold is crossed — releasing and
  // holding again is required to fire a second time.
  bool update(bool pressed, uint32_t nowMs);

  // Milliseconds the button has been held so far, for progress feedback on the serial log.
  uint32_t heldMs(uint32_t nowMs) const;

 private:
  uint32_t _holdMs;
  uint32_t _pressedAtMs = 0;
  bool _pressed = false;
  bool _fired = false;
};

}  // namespace fry
