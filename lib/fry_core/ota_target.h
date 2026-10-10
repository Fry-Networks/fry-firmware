#pragma once
// B4: which OTA images this board may apply, pure so the rule is natively tested.
//
// ESP8266 has one app slot and no rollback - a wrong image is a bricked board until someone
// reflashes it over serial. So on that chip a manifest entry must name the board/layout it was
// built for and its flash size, and the board refuses anything else BEFORE writing a byte.
// Missing fields refuse too (fail closed).
#include <cstdint>

namespace fry {

struct OtaEntryTarget {
  const char* boardId = nullptr;  // e.g. "esp8266-4m1m"; nullptr/"" = absent
  uint32_t flashSize = 0;         // bytes the image's layout expects; 0 = absent
};

struct OtaDeviceFlash {
  const char* boardId = nullptr;  // compiled FRY_OTA_BOARD_ID
  uint32_t flashReal = 0;         // ESP.getFlashChipRealSize()
  uint32_t flashHeader = 0;       // ESP.getFlashChipSize() - the RUNNING image's layout
  bool isEsp8285 = false;
};

enum class OtaTargetVerdict : uint8_t {
  Ok = 0,
  MissingBoardId,
  BoardMismatch,
  MissingFlashSize,
  FlashTooSmall,
  LayoutMismatch,
  Esp8285,
  SizeMismatch,
};

OtaTargetVerdict checkOtaTarget(const OtaEntryTarget& entry, const OtaDeviceFlash& device);

// Content-Length must equal the entry's declared size (0 = absent, refused).
OtaTargetVerdict checkOtaSize(uint32_t declaredSize, int32_t contentLength);

// Stable lowercase token for the "ota: refused <reason>" log line.
const char* otaTargetReason(OtaTargetVerdict v);

// The version to compare against the running one: the build entry's own "version" when the
// manifest has one, else the manifest's top-level firmware_version. Without this a 0.3.4 board
// reading a manifest whose top level says 0.4.1 would re-apply its own image every 6 h.
const char* selectOtaVersion(const char* buildVersion, const char* topLevelVersion);

// The whole pre-download decision for one manifest check, in the order the client must apply it:
// version (per-build first) -> url/sha present -> newer than running -> B4 target. Only Update
// may lead to a download; Refuse means the entry was newer but not for this board.
struct OtaManifestEntry {
  const char* topVersion = nullptr;    // manifest "firmware_version"
  const char* buildVersion = nullptr;  // builds[env]["version"]
  const char* url = nullptr;
  const char* sha256 = nullptr;
  OtaEntryTarget target;
};

enum class OtaAction : uint8_t { None, Update, Refuse };

struct OtaDecision {
  OtaAction action = OtaAction::None;
  const char* version = "";  // the version that was compared (and is applied on Update)
  OtaTargetVerdict verdict = OtaTargetVerdict::Ok;
};

OtaDecision decideOtaApply(const OtaManifestEntry& entry, const OtaDeviceFlash& device,
                           const char* currentVersion);

}  // namespace fry
