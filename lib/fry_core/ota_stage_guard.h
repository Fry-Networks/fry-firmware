#pragma once
// ESP8266 OTA: an image that failed its sha256 must never be staged for the bootloader.
//
// The ESP8266 Updater (core 3.30102.0, cores/esp8266/Updater.cpp) has no abort(). Its end(false) drops the update only while the stream is
// unfinished or an error is set (:226-232: `hasError() || (!isFinished() && !evenIfRemaining)` -> _reset(), return false). Once every byte has
// been written and no error is set, end(false) falls through to the commit: _verifyEnd() passes on the 0xE9 magic byte (:339) and
// eboot_command_write() stores ACTION_COPY_RAW in RTC memory (:350), so at the next reboot eboot copies the image the sha256 check had just
// rejected over the running one. The digest is known only after the last byte, so the last byte is the one the Updater must not have yet.
//
// HeldTailWriter forwards the stream to the Updater except its final byte, which it keeps in the writer. The Updater has then been given at
// most total-1 bytes and progress() never exceeds the bytes it was given (_currentAddress advances by _bufferLen only, :431), so
// isFinished() (_currentAddress == _startAddress + _size, Updater.h:165) is false for every buffer size. discard() = end(false) on that
// unfinished update returns at :226-232 before _verifyEnd() and before eboot_command_write(): nothing is staged, and _reset() leaves the
// Updater idle (_size 0), so the next begin() is accepted (:69). A flash error sets _currentAddress to the end (:411-413, :423-426) and hasError(),
// which :226 tests first, so end(false) drops that update too. commit() is the success path: the held byte completes the stream (:460),
// then end(true). Header-only and Updater-agnostic so a native test can drive it with a model of the Updater.
#include <cstddef>
#include <cstdint>

namespace fry {

template <class UpdaterT>
class HeldTailWriter {
 public:
  // `total` is the size given to Updater.begin().
  HeldTailWriter(UpdaterT& up, size_t total) : up_(up), total_(total) {}

  // Forwards n bytes of the stream, except the stream's last byte. false: the Updater refused them, or the stream is longer than `total`
  // (the caller then discards).
  bool write(uint8_t* data, size_t n) {
    if (n == 0) return true;
    if (held_ || seen_ + n > total_) return false;
    if (seen_ + n < total_) {
      if (up_.write(data, n) != n) return false;
      seen_ += n;
      return true;
    }
    if (n > 1 && up_.write(data, n - 1) != n - 1) return false;
    tail_ = data[n - 1];
    held_ = true;
    seen_ += n;
    return true;
  }

  // The digest matched: the held byte completes the stream and the update is finished. false: nothing is staged (the Updater's own end(true)
  // failure, or an incomplete stream, or a write error, which end(false) clears because hasError() is checked first).
  bool commit() {
    if (!held_) {
      up_.end(false);
      return false;
    }
    if (up_.write(&tail_, 1) != 1) {
      up_.end(false);
      return false;
    }
    return up_.end(true);
  }

  // The digest did not match, or the stream failed: the update is dropped and nothing is staged.
  void discard() { up_.end(false); }

 private:
  UpdaterT& up_;
  size_t total_;
  size_t seen_ = 0;
  uint8_t tail_ = 0;
  bool held_ = false;
};

}  // namespace fry
