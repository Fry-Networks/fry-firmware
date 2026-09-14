#include "reset_button.h"

namespace fry {

bool ResetButton::update(bool pressed, uint32_t nowMs) {
  if (!pressed) {
    // Released: the next hold starts from zero, and re-arms the trigger.
    _pressed = false;
    _fired = false;
    return false;
  }

  if (!_pressed) {
    _pressed = true;
    _pressedAtMs = nowMs;
    _fired = false;
    return false;
  }

  if (_fired) return false;

  // Unsigned subtraction, so this stays correct across the millis() rollover at ~49.7 days.
  if (nowMs - _pressedAtMs >= _holdMs) {
    _fired = true;
    return true;
  }
  return false;
}

uint32_t ResetButton::heldMs(uint32_t nowMs) const {
  if (!_pressed) return 0;
  return nowMs - _pressedAtMs;
}

}  // namespace fry
