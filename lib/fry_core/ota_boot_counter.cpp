#include "ota_boot_counter.h"

namespace fry {

OtaBootCounter::OtaBootCounter(uint8_t initial) : _count(initial) {}

uint8_t OtaBootCounter::increment() {
  if (_count < 255) _count++;
  return _count;
}

void OtaBootCounter::clear() { _count = 0; }

bool OtaBootCounter::shouldRollBack(uint8_t limit) const { return _count >= limit; }

}  // namespace fry
