#pragma once
// OTA decision of the non-ESP boards (PROTOCOL.md sections 6 and 11.5) as pure C++: which manifest build applies to this board
// and whether the image fits, decided before anything is downloaded. The download itself is src/boards/ota_boards.cpp.
#include <cstddef>
#include <cstdint>

#include "board_presets.h"

namespace fry {
namespace boards {

enum class OtaDecision : uint8_t {
  Apply,
  NoBuild,          // builds[os] absent: this board does not update, and never takes another chip's image
  NotNewer,         // SemVer precedence, never downward
  WrongChannel,     // channel other than "prod" (a missing channel reads as prod)
  BadUrl,           // not an absolute https URL
  BadSha,           // not 64 hex characters
  TooBigForSlot,    // the announced size exceeds the room for the next image
  RejectedPending,  // an installed image is still unconfirmed: no new check until it proves itself
};

struct OtaInput {
  const char* os;
  const char* runningVersion;
  const char* manifestVersion;
  const char* channel;  // nullptr or "" = prod
  bool buildPresent;
  const char* url;
  const char* sha256;
  uint32_t imageBytes;     // 0 = not announced yet (the download checks Content-Length again)
  uint32_t freeSlotBytes;  // room for the next image
  const char* pendingVersion;  // fry_ota/pending, nullptr or "" when none
};

OtaDecision decideOta(const OtaInput& in);
const char* decisionText(OtaDecision d);

ImageKind imageKindForOs(const char* os);
// First bytes of the stream. UF2: the two magic words that start every block. Pico .bin: at least 256 bytes that are not blank flash, not all zero and not
// text (an HTML error page served with 200 must never be staged).
bool imageHeaderPlausible(ImageKind kind, const uint8_t* head, size_t n);

// Single-slot boards cannot roll back: after `limit` boots of an unconfirmed image the counter only reports it.
inline bool bootLimitReached(uint8_t fails, uint8_t limit) { return fails >= limit; }

}  // namespace boards
}  // namespace fry
