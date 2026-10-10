#include "ota_target.h"

#include <cstring>

#include "semver.h"

namespace fry {

OtaTargetVerdict checkOtaTarget(const OtaEntryTarget& entry, const OtaDeviceFlash& device) {
  if (!entry.boardId || entry.boardId[0] == 0) return OtaTargetVerdict::MissingBoardId;
  if (!device.boardId || strcmp(entry.boardId, device.boardId) != 0) {
    return OtaTargetVerdict::BoardMismatch;
  }
  if (device.isEsp8285) return OtaTargetVerdict::Esp8285;
  if (entry.flashSize == 0) return OtaTargetVerdict::MissingFlashSize;
  if (entry.flashSize > device.flashReal) return OtaTargetVerdict::FlashTooSmall;
  if (entry.flashSize != device.flashHeader) return OtaTargetVerdict::LayoutMismatch;
  return OtaTargetVerdict::Ok;
}

OtaTargetVerdict checkOtaSize(uint32_t declaredSize, int32_t contentLength) {
  if (declaredSize == 0 || contentLength <= 0 ||
      static_cast<uint32_t>(contentLength) != declaredSize) {
    return OtaTargetVerdict::SizeMismatch;
  }
  return OtaTargetVerdict::Ok;
}

const char* otaTargetReason(OtaTargetVerdict v) {
  switch (v) {
    case OtaTargetVerdict::Ok: return "ok";
    case OtaTargetVerdict::MissingBoardId: return "board_id_missing";
    case OtaTargetVerdict::BoardMismatch: return "board_id";
    case OtaTargetVerdict::MissingFlashSize: return "flash_size_missing";
    case OtaTargetVerdict::FlashTooSmall: return "flash_too_small";
    case OtaTargetVerdict::LayoutMismatch: return "flash_layout";
    case OtaTargetVerdict::Esp8285: return "esp8285";
    case OtaTargetVerdict::SizeMismatch: return "size";
  }
  return "unknown";
}

const char* selectOtaVersion(const char* buildVersion, const char* topLevelVersion) {
  if (buildVersion && buildVersion[0]) return buildVersion;
  return topLevelVersion ? topLevelVersion : "";
}

OtaDecision decideOtaApply(const OtaManifestEntry& entry, const OtaDeviceFlash& device,
                           const char* currentVersion) {
  OtaDecision d;
  d.version = selectOtaVersion(entry.buildVersion, entry.topVersion);
  const bool hasImage = entry.url && entry.url[0] && entry.sha256 && entry.sha256[0];
  if (!d.version[0] || !hasImage || !isNewerVersion(d.version, currentVersion)) return d;
  d.verdict = checkOtaTarget(entry.target, device);
  d.action = (d.verdict == OtaTargetVerdict::Ok) ? OtaAction::Update : OtaAction::Refuse;
  return d;
}

}  // namespace fry
