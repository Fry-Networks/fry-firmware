#pragma once
// The I/O side of the boot decision (lib/fry_core/ota_confirm.h) behind a small port interface, so
// the order of the reads, the NVS writes and the rollback can be tested on the host with a fake.
// src/core/ota_client.cpp implements the ports with NVS, esp_ota_* and the core dump API.
// ESP32 family only; nothing here is referenced by the ESP8266 build.
#include <cstddef>
#include <cstdint>

#include "ota_confirm.h"

namespace fry {

enum class CrashEvidence : uint8_t { No, Yes, Unavailable };

class OtaBootPorts {
 public:
  virtual ~OtaBootPorts() {}
  // fry_ota namespace
  virtual void getAttempts(char* out, size_t cap) = 0;
  virtual bool setAttempts(const char* record) = 0;  // false: the write failed
  virtual void clearAttempts() = 0;
  virtual uint8_t getBootFails() = 0;
  virtual bool setBootFails(uint8_t v) = 0;  // false: the write failed
  virtual void getBadVer(char* out, size_t cap) = 0;
  virtual uint8_t getBadN() = 0;
  virtual void getUrl(char* out, size_t cap) = 0;
  virtual void setUrl(const char* url) = 0;  // "" clears
  virtual void getQuarantined(char* out, size_t cap) = 0;
  virtual void setQuarantined(const char* version) = 0;  // "" clears
  virtual void setPending(const char* version) = 0;
  // platform
  virtual bool pendingBoot() = 0;  // PENDING_VERIFY in otadata or fry_ota.pending names the running version
  virtual uint32_t resetReason() = 0;
  virtual bool otherSlotIntact() = 0;
  virtual CrashEvidence crashEvidence() = 0;  // only asked when a record is open
  virtual bool selectOtherSlot() = 0;         // true when the previous slot is selected for the next boot
  virtual void finishRollback() = 0;          // clear the boot-fail counter and restart (does not return on a board)
  virtual void log(const char* line) = 0;
};

struct BootFlowConfig {
  const char* version = "";
  const char* manifestUrl = "";
  uint8_t failLimit = 3;
};

enum class FlowOutcome : uint8_t {
  Continue,        // go on booting
  ConfirmNow,      // the caller marks the image valid now
  RolledBack,      // the previous slot is selected and finishRollback() was called
  RollbackFailed,  // it could not be selected; finishRollback() was called, the quarantine note was undone
};

struct BootFlowResult {
  FlowOutcome outcome = FlowOutcome::Continue;
  bool inProbation = false;
  AttemptRecord record;     // the record as stored after this boot
  uint8_t failCount = 0;
  bool recordWriteFailed = false;
};

// Reads the state through the ports, decides, applies the writes and the rollback. Order of the
// quarantine note: the version first, then the address (a partial write leaves a harmless note).
// Fail-safe direction of a failed NVS write: a lost attempt record or boot-fail counter leaves the
// state it had, so decisions fall back toward the behaviour without this logic (no early
// give-up, no force-confirm); a lost health bit is retried once and logged.
BootFlowResult runBootFlow(OtaBootPorts& p, const BootFlowConfig& c);

// A pending or confirmed boot of a build whose record is open got Wi-Fi with a 2xx: remember it in the
// record (once). Returns false if the write failed twice.
bool recordHealthReached(OtaBootPorts& p, const BootFlowConfig& c, AttemptRecord* rec);

}  // namespace fry
