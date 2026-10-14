#pragma once
// Decision for a write to the Olostep opt-in GATT characteristic, zero Arduino includes.
//
// Turning the relay ON is a consent action, so it is accepted only from an encrypted (paired) link,
// the same rule the owner-key write follows. Turning it OFF can only reduce exposure, so it is
// accepted from any link. Anything that is not exactly one byte, 0x00 or 0x01, is ignored.
//
// Unit tested standalone under `pio test -e native`.
#include <cstddef>
#include <cstdint>

namespace fry_olostep {

enum class OptInWrite { Ignore, SetOn, SetOff };

OptInWrite olostepOptInWrite(const uint8_t* data, size_t len, bool linkEncrypted);

}  // namespace fry_olostep
