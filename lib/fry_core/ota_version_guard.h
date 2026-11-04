#pragma once
// ESP8266 OTA: an image that is not the version its manifest declared. The device applies the
// image named by the manifest (fry_ota.pending = X), reboots and finds a different version Y
// running with no rollback evidence at all (the ESP8266 has no bootloader rollback; only the boot
// counter and a planned restart leave a marker). Without a record the same manifest entry is
// downloaded again at every check. Pure C++ so the native suite pins the decision; the strike
// bookkeeping stays in src/core/ota_client.cpp (nextStrikeCount / skipBadVersion).
#include <cstring>

namespace fry {

// True when the boot after an applied OTA runs a version other than the pending one and neither
// a rollback nor a planned restart explains it. A legitimate update (pending == running) and a
// rollback (shouldRecordBadVersion's branch) are never a mismatch, so the two cannot both strike.
inline bool shouldRejectManifestVersion(const char* pending, const char* running, bool rolledBack,
                                        bool plannedRestart) {
  if (pending == nullptr || pending[0] == '\0') return false;
  if (running == nullptr || running[0] == '\0') return false;
  if (rolledBack || plannedRestart) return false;
  return std::strcmp(pending, running) != 0;
}

}  // namespace fry
