#pragma once
// Confirming a new image early, bounded install attempts and a short probation after the confirm.
// Pure C++ (no Arduino); src/core/ota_client.cpp does the I/O, the NVS writes and the ESP-IDF calls.
// Sits next to ota_health.h and leaves its functions untouched: decideMarkValid (any HTTP answer +
// the settle window) stays the fallback and decideRollbackGuard the no-answer deadline.
//
// Life of a new image on the ESP32 family:
//   PENDING    the bootloader boots it PENDING_VERIFY. A reset in this state boots the previous image.
//              Every pending boot is counted in an NVS record the previous image does not touch.
//   PROBATION  confirmed (marked valid). Only crash-class boots without health count; N of them roll
//              back to the previous slot, unless this was the last permitted install attempt.
//   NORMAL     after a long healthy run the record is dropped.
// ESP8266 has one slot and no bootloader rollback: none of this is used there.
#include <cstddef>
#include <cstdint>

namespace fry {

// ---- reset reasons ------------------------------------------------------------------------------

// esp_reset_reason_t: 4 panic, 5 interrupt wdt, 6 task wdt, 7 other wdt, 9 brownout are CRASH.
// 1 power-on, 2 EN pin, 3 software restart, 8 deep sleep, 10 SDIO (and any other known value) are
// BENIGN: somebody or something deliberately restarted the board. 0 and out-of-range are UNKNOWN.
enum class ResetClass : uint8_t { Benign, Crash, Unknown };
ResetClass classifyResetReason(uint32_t espResetReason);

// ---- confirm early ------------------------------------------------------------------------------

// Core health, all of it from THIS boot. The tunnel being up is deliberately not an input: only
// that its bring-up attempt is over (`startupDone`, set when the VPN start call returned).
struct CoreHealth {
  bool staUp = false;        // Wi-Fi associated and holding an IP right now
  bool apiOk2xx = false;     // a registration or heartbeat was answered with a 2xx
  bool startupDone = false;  // the tunnel bring-up attempt (made or skipped) is over
  uint8_t loopPasses = 0;    // main-loop passes since startupDone
  uint32_t freeHeap = 0;
  uint32_t uptimeMs = 0;
};

const uint32_t kEarlyConfirmMinUptimeMs = 30000UL;
const uint8_t kEarlyConfirmMinLoopPasses = 3;

// Everything but the uptime floor.
bool coreHealthy(const CoreHealth& h, uint32_t minFreeHeap);

// Mark a pending image valid once core health holds and it has survived its own start-up.
bool decideEarlyConfirm(bool pending, const CoreHealth& h, uint32_t minFreeHeap);

// ---- install attempts ---------------------------------------------------------------------------

// The record is "<version>#<n>": n pending boots of that version since it was last healthy for a
// long time. The previous image does not know the NVS key, so it survives a rollback.
uint8_t attemptsOf(const char* record, const char* version);  // 0 for another version or a bad record
size_t formatAttempts(char* out, size_t cap, const char* version, uint8_t attempts);  // 0 if it does not fit

// The install attempt at which the image must settle one way or the other. Without evidence that
// THIS build crashed in the earlier attempts (a core dump of this build), the resets were external
// (power, cable, EN): the attempt is confirmed at init and sticks. With such evidence it is NOT
// force-confirmed: the board is sent back to the previous image, and that image is kept from
// installing it again (its own strike memory, or the quarantine manifest address below).
const uint8_t kStickyInstallAttempt = 3;

// A previous image that counts strikes has recorded at least one for this version in badver/badn.
bool oldKeepsStrikes(const char* badver, uint8_t badn, const char* version);

// The manifest address a quarantined board is pointed at, derived from the compiled manifest URL by
// swapping "/releases/latest/download/" for "/releases/download/quarantine/". False if the compiled
// URL does not have that shape or `out` is too small. Nothing exists at that address until someone
// publishes it, which a previous image reads as "no update".
bool quarantineUrlFrom(const char* manifestUrl, char* out, size_t cap);

// Whether the quarantine address / version note may be cleared: a different build than the
// quarantined one is running (e.g. a fixed image was flashed or installed). `url` is the current
// override, empty if none.
bool shouldClearQuarantine(const char* url, const char* quarantineUrl, const char* quarantinedVersion,
                           const char* running);

// ---- decision at init ---------------------------------------------------------------------------

// RollbackNow: go back to the previous slot (the previous image decides about re-installing).
// AbandonNow: the same, after the quarantine address was stored when `quarantine` is set.
enum class BootAction : uint8_t { Continue, ConfirmNow, RollbackNow, AbandonNow };

struct BootInputs {
  bool pendingBoot = false;      // PENDING_VERIFY in otadata or fry_ota.pending names the running version
  uint8_t attemptsBefore = 0;    // from the record, 0 when it names another version
  uint8_t failCount = 0;         // fry_ota.bootfails
  ResetClass reset = ResetClass::Unknown;
  bool otherSlotIntact = false;  // the previous OTA slot can be booted
  uint8_t failLimit = 3;         // OTA_BOOT_FAIL_LIMIT
  bool crashEvidence = false;    // a core dump written by THIS build exists
  bool oldKeepsStrikes = false;  // the previous image counts strikes (see oldKeepsStrikes())
  bool quarantineAvailable = false;  // the address can be stored (derivable and no other override)
};

struct BootDecision {
  BootAction action = BootAction::Continue;
  uint8_t attempts = 0;          // record value after this boot
  bool writeAttempts = false;
  uint8_t failCount = 0;         // boot-fail counter after this boot
  bool writeFailCount = false;
  bool inProbation = false;      // confirmed image whose record is still open
  bool quarantine = false;       // with AbandonNow: store the quarantine address first
};

BootDecision decideBoot(const BootInputs& in);

// ---- probation progress -------------------------------------------------------------------------

const uint32_t kProbationHealthyMs = 120UL * 1000UL;
const uint32_t kProbationEndMs = 30UL * 60UL * 1000UL;

enum class ProbationStep : uint8_t { None, ClearFails, End };
// `healthy`: core health holds now. Cleared counter after kProbationHealthyMs of uptime, record
// dropped after kProbationEndMs.
ProbationStep decideProbationProgress(bool inProbation, bool healthy, uint32_t uptimeMs, uint8_t failCount);

}  // namespace fry
