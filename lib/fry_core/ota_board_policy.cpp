#include "ota_board_policy.h"

#include <cstring>

#include "semver.h"

namespace fry {
namespace boards {

namespace {
bool isHex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }
}  // namespace

OtaDecision decideOta(const OtaInput& in) {
  if (in.pendingVersion && in.pendingVersion[0]) return OtaDecision::RejectedPending;
  if (in.channel && in.channel[0] && strcmp(in.channel, "prod") != 0) return OtaDecision::WrongChannel;
  if (!in.buildPresent) return OtaDecision::NoBuild;
  if (!in.manifestVersion || !in.runningVersion || !isNewerVersionOta(in.manifestVersion, in.runningVersion)) {
    return OtaDecision::NotNewer;
  }
  if (!in.url || strncmp(in.url, "https://", 8) != 0 || in.url[8] == '\0') return OtaDecision::BadUrl;
  if (!in.sha256 || strlen(in.sha256) != 64) return OtaDecision::BadSha;
  for (size_t i = 0; i < 64; i++)
    if (!isHex(in.sha256[i])) return OtaDecision::BadSha;
  if (in.imageBytes != 0 && in.imageBytes > in.freeSlotBytes) return OtaDecision::TooBigForSlot;
  return OtaDecision::Apply;
}

const char* decisionText(OtaDecision d) {
  switch (d) {
    case OtaDecision::Apply: return "apply";
    case OtaDecision::NoBuild: return "no build for this board";
    case OtaDecision::NotNewer: return "not newer";
    case OtaDecision::WrongChannel: return "wrong channel";
    case OtaDecision::BadUrl: return "bad url";
    case OtaDecision::BadSha: return "bad sha256";
    case OtaDecision::TooBigForSlot: return "too big for slot";
    case OtaDecision::RejectedPending: return "unconfirmed image pending";
  }
  return "?";
}

ImageKind imageKindForOs(const char* os) {
  const Preset* p = presetForOs(os);
  return p ? p->image : ImageKind::None;
}

bool imageHeaderPlausible(ImageKind kind, const uint8_t* head, size_t n) {
  if (!head) return false;
  if (kind == ImageKind::BkUf2) {
    static const uint8_t kMagic[8] = {0x55, 0x46, 0x32, 0x0A, 0x57, 0x51, 0x5D, 0x9E};  // "UF2\n", 0x9E5D5157
    return n >= 8 && memcmp(head, kMagic, 8) == 0;
  }
  if (kind == ImageKind::PicoBin) {
    if (n < 256) return false;
    bool allFF = true, allZero = true, text = true;
    for (size_t i = 0; i < 256; i++) {
      if (head[i] != 0xFF) allFF = false;
      if (head[i] != 0x00) allZero = false;
      if (!((head[i] >= 0x20 && head[i] < 0x7F) || head[i] == '\n' || head[i] == '\r' || head[i] == '\t')) text = false;
    }
    return !allFF && !allZero && !text;
  }
  return false;
}

}  // namespace boards
}  // namespace fry
