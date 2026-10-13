#include "ota_mfln.h"

namespace fry {

// STUB (red): deliberately wrong so the tests fail before the real implementation lands.
bool otaUrlHost(const char*, char*, size_t) { return false; }
bool otaHostHonoursMfln(const char*) { return false; }
OtaTlsPlan otaTlsPlan(const char*, uint32_t configuredBlock) {
  return OtaTlsPlan{true, false, 16384, 512, configuredBlock};
}
bool otaMustClearStaged(uint32_t, uint32_t, bool, bool) { return false; }
OtaFailAction otaFailureAction(OtaFailKind) { return OtaFailAction::RetryNow; }

}  // namespace fry
