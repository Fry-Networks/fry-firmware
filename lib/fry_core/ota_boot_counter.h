#pragma once
// Pure C++ OTA boot-fail counter. Persistence (NVS key fry_ota.bootfails, see PROTOCOL.md /
// T3 config store) is the caller's job — this class only implements the counting logic so it
// can be unit tested under `pio test -e native` without any Arduino/NVS dependency.
#include <cstdint>

namespace fry {

class OtaBootCounter {
 public:
  explicit OtaBootCounter(uint8_t initial = 0);

  uint8_t count() const { return _count; }

  // Called once per boot that has not yet confirmed itself good. Saturates at 255.
  uint8_t increment();

  // Called once the new image has confirmed itself good (e.g. hardwareapi reachable).
  void clear();

  // True once count() has reached limit — the caller should roll back to the previous image.
  bool shouldRollBack(uint8_t limit) const;

 private:
  uint8_t _count;
};

}  // namespace fry
