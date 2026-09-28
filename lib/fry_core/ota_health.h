#pragma once
// Post-OTA health: heartbeat bookkeeping, the rollback guard, the bad-version memory and the
// manifest update decision (PROTOCOL.md section 11.5). Pure C++ with no Arduino dependency;
// src/core/ota_client.cpp does the I/O, the NVS writes and the ESP-IDF calls.
//
// Life of an OTA image on the ESP32 family (the bootloader is built with app rollback):
//   1. the old image writes the new one and reboots into it; the bootloader boots it PENDING_VERIFY
//   2. the new image keeps it pending (verifyRollbackLater() returns true, src/esp32/ota_rollback.cpp)
//   3. the first hardwareapi HTTP response of ANY status marks it valid (HeartbeatTracker::note)
//   4. a crash or reboot before that, or no response by the deadline, rolls back to the old image,
//      which then records the version it rolled away from and never installs it again
// ESP8266 has one slot and no bootloader rollback; there only the NVS boot counter logs.
#include <cstdint>

namespace fry {

// ---- heartbeat ----------------------------------------------------------------------------------

class HeartbeatTracker {
 public:
  // Records one hardwareapi response (`http` <= 0 is a transport error and is ignored). Returns
  // true exactly once: on the first real HTTP status of this boot, whatever it is.
  bool note(int http, uint32_t nowMs);

  bool anyResponse() const { return _any; }
  // Seconds since the last 2xx, -1 if none this boot. Wrap-safe on millis().
  int32_t ageS(uint32_t nowMs) const;
  // The last HTTP status seen (any class), 0 if none.
  int lastHttp() const { return _lastHttp; }

 private:
  bool _any = false;
  bool _okSeen = false;
  uint32_t _lastOkMs = 0;
  int _lastHttp = 0;
};

// ---- rollback guard -----------------------------------------------------------------------------

const uint32_t kOtaVerifyDeadlineProdMs = 20UL * 60UL * 1000UL;
const uint32_t kOtaVerifyDeadlineTestMs = 2UL * 60UL * 1000UL;

enum class GuardAction : uint8_t { None, Rollback };

// `pendingVerify`: the running image is still PENDING_VERIFY. `heartbeatSeen`: any HTTP response
// this boot. Roll back once uptime reaches the deadline without one.
GuardAction decideRollbackGuard(bool pendingVerify, bool heartbeatSeen, uint32_t uptimeMs,
                                uint32_t deadlineMs);

// Boot-time evidence that the image named by fry_ota.pending did not survive: the running version
// is a different one AND the bootloader reports an invalid (rolled-back) OTA partition.
bool shouldRecordBadVersion(const char* pending, const char* running, bool lastInvalidPartition);

enum class OtaImageState : uint8_t { Valid, Pending, RolledBack };
OtaImageState otaImageState(bool pendingVerify, bool rolledBackBefore);
const char* otaImageStateName(OtaImageState s);  // "valid" | "pending" | "rolled_back"

// ---- manifest selection -------------------------------------------------------------------------

// A missing or empty manifest "channel" is "prod". Exact match otherwise.
bool otaChannelAccepted(const char* manifestChannel, const char* ownChannel);

// True when `candidate` is exactly the version recorded as rolled back on this board.
bool isSkippedBadVersion(const char* candidate, const char* badver);

enum class OtaDecision : uint8_t { Update, NotNewer, WrongChannel, BadVersion, NoBuild };

// Channel first, then forward-only SemVer precedence, then the bad version, then a build entry for
// this environment with both url and sha256 (a chip left out of the manifest never updates).
OtaDecision decideOtaUpdate(const char* manifestChannel, const char* ownChannel, const char* latest,
                            const char* current, const char* badver, const char* url,
                            const char* sha256);
const char* otaDecisionName(OtaDecision d);

}  // namespace fry
