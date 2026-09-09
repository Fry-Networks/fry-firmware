#pragma once
// Minimal numeric version comparison for the OTA manifest, zero Arduino includes.
//
// The manifest check used to be `strcmp(latest, current) != 0`, which updates in EITHER
// direction: a device running a newer build than the published manifest silently downgraded
// itself. Deliberate rollback is slot-based (see ota_client.cpp "Manual rollback"), so the
// manifest must only ever move a device forward.
//
// A lexical comparison would also be wrong regardless of direction, because "0.9.0" sorts
// above "0.10.0" as text while 10 is the later minor. Components are compared as numbers.
//
// Unit tested standalone under `pio test -e native`.
#include <cstdint>

namespace fry {

// Compares up to three dot-separated numeric components ("MAJOR.MINOR.PATCH"). Any suffix
// beginning '-' or '+' (pre-release / build metadata) is ignored, so "0.1.1-rc1" compares
// equal to "0.1.1". Missing components read as 0, so "0.1" equals "0.1.0".
// Returns -1 when a < b, 0 when equal, 1 when a > b. A null or empty string reads as 0.0.0.
int compareSemver(const char* a, const char* b);

// Convenience wrapper: true when `latest` is strictly newer than `current`.
bool isNewerVersion(const char* latest, const char* current);

}  // namespace fry
