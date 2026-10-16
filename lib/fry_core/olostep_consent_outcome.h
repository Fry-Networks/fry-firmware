#pragma once
// Outcome of persisting the Olostep opt-in flag, zero Arduino includes.
//
// A consent write that did not reach storage must never leave the relay running on a stale "ON":
// when an OFF request could not be persisted the executor is told to go dormant for this boot.
// A failed ON request simply leaves the stored (default OFF) value in force.
//
// Unit tested standalone under `pio test -e native`.
#include <cstddef>

namespace fry_olostep {

struct ConsentWriteOutcome {
  bool persisted;          // the requested value is in storage
  bool mustForceDormant;   // an OFF request was not persisted: the relay must not run
};

// beginOk: the store opened read-write; putResult: bytes written (0 = nothing written).
ConsentWriteOutcome consentWriteOutcome(bool beginOk, size_t putResult, bool requested);

}  // namespace fry_olostep
