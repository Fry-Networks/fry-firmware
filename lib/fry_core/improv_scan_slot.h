#pragma once
// Heap home of the ESP8266 Improv scan list, held only while one scan reply is built.
//
// pollScan() (src/core/improv_serial_glue.cpp) used to keep a `static ScanList` (1060 B of .bss) for the whole uptime. The heap is
// [_heap_start, 0x3FFFC000), so every static byte is a byte the image download's TLS session does not have. The slot is a pointer
// of static storage; the list exists from acquire() to release(), inside one synchronous pollScan() call, and never at OTA time.
//
// ESP8266 and host only: the ESP32 family keeps its own scan branch and this header is not included there.
#if !defined(ARDUINO) || defined(ARDUINO_ARCH_ESP8266)

#include <cstddef>
#include <new>

#include "improv_scan.h"

namespace fry {
namespace improv {

class ScanListSlot {
 public:
  ScanListSlot() : list_(nullptr) {}
  ~ScanListSlot() { release(); }
  ScanListSlot(const ScanListSlot&) = delete;
  ScanListSlot& operator=(const ScanListSlot&) = delete;

  // A cleared list, or nullptr when the heap has no room (never throws: the core panics on a failed throwing new).
  ScanList* acquire() {
    if (!list_) list_ = new (std::nothrow) ScanList();
    if (list_) list_->clear();
    return list_;
  }
  void release() {
    delete list_;
    list_ = nullptr;
  }
  bool held() const { return list_ != nullptr; }

 private:
  ScanList* list_;
};

// The static footprint of a slot is one pointer, never the 1 KB list.
static_assert(sizeof(ScanListSlot) <= sizeof(void*), "ScanListSlot must stay pointer-sized");

}  // namespace improv
}  // namespace fry

#endif  // !ARDUINO || ARDUINO_ARCH_ESP8266
