#include "ota_confirm.h"

#include <cstring>

namespace fry {

ResetClass classifyResetReason(uint32_t r) {
  switch (r) {
    case 4:  // panic
    case 5:  // interrupt watchdog
    case 6:  // task watchdog
    case 7:  // other watchdog
    case 9:  // brownout
      return ResetClass::Crash;
    case 1:   // power-on
    case 2:   // EN pin
    case 3:   // software restart
    case 8:   // deep sleep
    case 10:  // SDIO
      return ResetClass::Benign;
    default:
      return ResetClass::Unknown;
  }
}

bool coreHealthy(const CoreHealth& h, uint32_t minFreeHeap) {
  return h.staUp && h.apiOk2xx && h.startupDone && h.loopPasses >= kEarlyConfirmMinLoopPasses &&
         h.freeHeap >= minFreeHeap;
}

bool decideEarlyConfirm(bool pending, const CoreHealth& h, uint32_t minFreeHeap) {
  return pending && coreHealthy(h, minFreeHeap) && h.uptimeMs >= kEarlyConfirmMinUptimeMs;
}

uint8_t attemptsOf(const char* record, const char* version) {
  if (record == nullptr || version == nullptr || version[0] == 0) return 0;
  const size_t vl = strlen(version);
  if (strncmp(record, version, vl) != 0 || record[vl] != '#') return 0;
  const char* p = record + vl + 1;
  if (*p < '0' || *p > '9') return 0;
  uint32_t n = 0;
  for (; *p >= '0' && *p <= '9'; p++) {
    n = n * 10 + static_cast<uint32_t>(*p - '0');
    if (n > 255) n = 255;
  }
  return *p == 0 ? static_cast<uint8_t>(n) : 0;
}

size_t formatAttempts(char* out, size_t cap, const char* version, uint8_t attempts) {
  if (out == nullptr || cap == 0 || version == nullptr) return 0;
  char digits[4];
  size_t d = 0;
  uint8_t v = attempts;
  do {
    digits[d++] = static_cast<char>('0' + v % 10);
    v = static_cast<uint8_t>(v / 10);
  } while (v != 0);
  const size_t vl = strlen(version);
  const size_t need = vl + 1 + d + 1;
  if (need > cap) {
    out[0] = 0;
    return 0;
  }
  memcpy(out, version, vl);
  out[vl] = '#';
  for (size_t i = 0; i < d; i++) out[vl + 1 + i] = digits[d - 1 - i];
  out[vl + 1 + d] = 0;
  return need - 1;
}

BootDecision decideBoot(const BootInputs& in) {
  BootDecision d;
  d.attempts = in.attemptsBefore;
  d.failCount = in.failCount;
  if (in.pendingBoot) {
    d.attempts = in.attemptsBefore < 255 ? static_cast<uint8_t>(in.attemptsBefore + 1) : in.attemptsBefore;
    d.writeAttempts = true;
    if (d.attempts >= kStickyInstallAttempt) d.action = BootAction::ConfirmNow;
    return d;
  }
  if (in.attemptsBefore == 0) return d;  // no record: not in probation
  d.inProbation = true;
  if (in.reset != ResetClass::Crash) return d;  // power cycles and restarts neither count nor forgive
  if (in.failCount < 255) d.failCount = static_cast<uint8_t>(in.failCount + 1);
  d.writeFailCount = d.failCount != in.failCount;
  if (d.failCount >= in.failLimit && in.attemptsBefore < kStickyInstallAttempt && in.otherSlotIntact) {
    d.action = BootAction::RollbackNow;
  }
  return d;
}

ProbationStep decideProbationProgress(bool inProbation, bool healthy, uint32_t uptimeMs, uint8_t failCount) {
  if (!inProbation || !healthy) return ProbationStep::None;
  if (uptimeMs >= kProbationEndMs) return ProbationStep::End;
  if (failCount > 0 && uptimeMs >= kProbationHealthyMs) return ProbationStep::ClearFails;
  return ProbationStep::None;
}

}  // namespace fry
