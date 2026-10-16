#include "olostep_consent_outcome.h"

namespace fry_olostep {

ConsentWriteOutcome consentWriteOutcome(bool beginOk, size_t putResult, bool requested) {
  const bool persisted = beginOk && putResult > 0;
  return ConsentWriteOutcome{persisted, !persisted && !requested};
}

}  // namespace fry_olostep
