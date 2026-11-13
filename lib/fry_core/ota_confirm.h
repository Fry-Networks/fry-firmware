#pragma once
// Confirming a new image early, bounded install attempts and a short probation after the confirm.
// Pure C++ (no Arduino); src/core/ota_client.cpp does the I/O, the NVS writes and the ESP-IDF calls
// (through lib/fry_core/ota_boot_flow.h). Sits next to ota_health.h and leaves its functions
// untouched: decideMarkValid (any HTTP answer + the settle window) stays the fallback and
// decideRollbackGuard the no-answer deadline.
//
// Life of a new image on the ESP32 family:
//   PENDING    the bootloader boots it PENDING_VERIFY. A reset in this state boots the previous image.
//              Every pending boot is counted in an NVS record the previous image does not touch.
//   PROBATION  confirmed (marked valid). Only crash-class boots without health count; N of them roll
//              back to the previous slot, unless this was the last permitted attempt.
//   NORMAL     after a long healthy run, or a number of boots, the record is dropped.
// ESP8266 has one slot and no bootloader rollback: none of this is used there.
#include <cstddef>
#include <cstdint>

namespace fry {

// ---- reset reasons ------------------------------------------------------------------------------

// esp_reset_reason_t: 4 panic, 5 interrupt wdt, 6 task wdt, 7 other wdt are CRASH. 9 brownout is
// BROWNOUT: a supply problem, counted as a crash only when a core dump of this build exists.
// 1 power-on, 2 EN pin, 3 software restart, 8 deep sleep, 10 SDIO (and any other known value) are
// BENIGN: somebody or something deliberately restarted the board. 0 and out-of-range are UNKNOWN.
enum class ResetClass : uint8_t { Benign, Crash, Unknown, Brownout };
ResetClass classifyResetReason(uint32_t espResetReason);

// ---- confirm early ------------------------------------------------------------------------------

// Core health, all of it from THIS boot. The tunnel being up is deliberately not an input: only
// that its bring-up has been attempted (or cannot be, see tunnelSettled()).
struct CoreHealth {
  bool staUp = false;          // Wi-Fi associated and holding an IP right now
  bool apiOk2xx = false;       // a registration or heartbeat was answered with a 2xx
  bool startupDone = false;    // the VPN start call returned
  bool tunnelSettled = false;  // see tunnelSettled()
  uint8_t loopPasses = 0;      // main-loop passes since startupDone
  uint32_t freeHeap = 0;
  uint32_t uptimeMs = 0;
};

const uint32_t kEarlyConfirmMinUptimeMs = 30000UL;
const uint8_t kEarlyConfirmMinLoopPasses = 3;
const uint32_t kTunnelWaitCapMs = 120000UL;

// The tunnel bring-up has been tried (made, or failed) before an image confirms, so an image that
// crashes in the tunnel code is still caught by the bootloader. Settled when the bring-up was
// attempted; or no config is stored and the provisioning fetch completed one attempt (any outcome);
// or the wait hit its cap, so a tunnel service outage cannot block validation.
// `waitedMs` is the time since the start-up note (the VPN start call returned), so a Wi-Fi join that
// succeeds late still waits for the bring-up attempt.
bool tunnelSettled(bool configStored, bool bringUpAttempted, bool fetchAttempted, uint32_t waitedMs);

// Everything but the uptime floor.
bool coreHealthy(const CoreHealth& h, uint32_t minFreeHeap);

// Mark a pending image valid once core health holds and it has survived its own start-up.
bool decideEarlyConfirm(bool pending, const CoreHealth& h, uint32_t minFreeHeap);

// ---- install attempts ---------------------------------------------------------------------------

// The record is "<version>#<n>[#<h>#<b>]": n pending boots of that version, h whether any of them
// got as far as Wi-Fi with a 2xx answer, b boots of the confirmed image since. The previous image
// does not know the NVS key, so it survives a rollback.
struct AttemptRecord {
  uint8_t n = 0;
  bool healthy = false;
  uint8_t boots = 0;
};
AttemptRecord parseAttemptRecord(const char* record, const char* version);  // n == 0: no record
size_t formatAttemptRecord(char* out, size_t cap, const char* version, const AttemptRecord& r);  // 0 if it does not fit
uint8_t attemptsOf(const char* record, const char* version);  // parseAttemptRecord(...).n
size_t formatAttempts(char* out, size_t cap, const char* version, uint8_t attempts);

// The install attempt at which the image must settle one way or the other (see decideBoot).
const uint8_t kStickyInstallAttempt = 3;
// Boots of the confirmed image after which an open record is dropped even if it never had a long
// healthy run (a board that is power-cycled every day).
const uint8_t kProbationMaxBoots = 8;

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
  AttemptRecord record;          // from the record, n == 0 when it names another version
  uint8_t failCount = 0;         // fry_ota.bootfails
  ResetClass reset = ResetClass::Unknown;
  bool otherSlotIntact = false;  // the previous OTA slot can be booted
  uint8_t failLimit = 3;         // OTA_BOOT_FAIL_LIMIT
  bool crashEvidence = false;    // a core dump written by THIS build exists
  bool evidenceUnavailable = false;  // the core dump cannot be read: absence of a dump proves nothing
  bool oldKeepsStrikes = false;  // the previous image counts strikes (see oldKeepsStrikes())
  bool quarantineAvailable = false;  // the address can be stored (derivable and no other override)
};

struct BootDecision {
  BootAction action = BootAction::Continue;
  AttemptRecord record;          // record value after this boot
  bool writeRecord = false;
  uint8_t failCount = 0;         // boot-fail counter after this boot
  bool writeFailCount = false;
  bool inProbation = false;      // confirmed image whose record is still open
  bool probationExpired = false; // kProbationMaxBoots reached: drop the record
  bool quarantine = false;       // with AbandonNow: store the quarantine address first
};

// Pending boot (attempt n = record.n + 1):
//   n < kStickyInstallAttempt  -> keep going (the bootloader and the previous image's strikes apply).
//   n >= kStickyInstallAttempt:
//     previous image keeps strikes -> never force-confirm; with a core dump of this build leave at once
//       (it counts the strike), otherwise the strikes bound the loop;
//     strike-less previous image: no dump (readable) AND an earlier attempt reached health -> the resets
//       were external, confirm at once; a dump, or no earlier attempt ever reached health (a silent failure)
//       -> give up through the quarantine address, or do nothing special when it cannot be stored.
// Confirmed boot with an open record: crash-class boots count (a brownout only with a dump); at the
//   limit roll back while n < kStickyInstallAttempt, later only with a dump and a way out.
BootDecision decideBoot(const BootInputs& in);

// ---- probation progress -------------------------------------------------------------------------

// The crash count is forgiven only after the old settle horizon (POC_INTERVAL_MS + 60 s, see
// ota_client.cpp kMarkValidSettleMs) in the same boot AND a completed PoC/lease 2xx in it: a defect
// that panics between 120 s and the first PoC cycle must still be counted.
const uint32_t kProbationHealthyMs = 660UL * 1000UL;
const uint32_t kProbationEndMs = 30UL * 60UL * 1000UL;

enum class ProbationStep : uint8_t { None, ClearFails, End };
// `healthy`: core health holds now; `pocOk`: a PoC or lease request was answered 2xx in this boot.
ProbationStep decideProbationProgress(bool inProbation, bool healthy, uint32_t uptimeMs, uint8_t failCount,
                                      bool pocOk);

}  // namespace fry
