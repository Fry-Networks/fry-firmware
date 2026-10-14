#include "olostep_optin.h"

namespace fry_olostep {

OptInWrite olostepOptInWrite(const uint8_t* data, size_t len, bool linkEncrypted) {
  if (data == nullptr || len != 1) return OptInWrite::Ignore;
  if (data[0] == 0x00) return OptInWrite::SetOff;
  if (data[0] == 0x01) return linkEncrypted ? OptInWrite::SetOn : OptInWrite::Ignore;
  return OptInWrite::Ignore;
}

}  // namespace fry_olostep
