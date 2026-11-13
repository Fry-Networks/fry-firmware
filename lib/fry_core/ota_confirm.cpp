#include "ota_confirm.h"

#include <cstring>

namespace fry {

ResetClass classifyResetReason(uint32_t r) {
  switch (r) {
    case 4:  // panic
    case 5:  // interrupt watchdog
    case 6:  // task watchdog
    case 7:  // other watchdog
      return ResetClass::Crash;
    case 9:  // brownout
      return ResetClass::Brownout;
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

bool tunnelSettled(bool configStored, bool bringUpAttempted, bool fetchAttempted, uint32_t waitedMs) {
  if (bringUpAttempted) return true;
  if (!configStored && fetchAttempted) return true;
  return waitedMs >= kTunnelWaitCapMs;
}

bool coreHealthy(const CoreHealth& h, uint32_t minFreeHeap) {
  return h.staUp && h.apiOk2xx && h.startupDone && h.tunnelSettled && h.loopPasses >= kEarlyConfirmMinLoopPasses &&
         h.freeHeap >= minFreeHeap;
}

bool decideEarlyConfirm(bool pending, const CoreHealth& h, uint32_t minFreeHeap) {
  return pending && coreHealthy(h, minFreeHeap) && h.uptimeMs >= kEarlyConfirmMinUptimeMs;
}

namespace {

// Reads digits at *p (saturating at 255); false if there is none.
bool readNumber(const char** p, uint8_t* out) {
  if (**p < '0' || **p > '9') return false;
  uint32_t n = 0;
  for (; **p >= '0' && **p <= '9'; (*p)++) {
    n = n * 10 + static_cast<uint32_t>(**p - '0');
    if (n > 255) n = 255;
  }
  *out = static_cast<uint8_t>(n);
  return true;
}

size_t appendNumber(char* out, size_t pos, size_t cap, uint8_t v) {
  char digits[4];
  size_t d = 0;
  do {
    digits[d++] = static_cast<char>('0' + v % 10);
    v = static_cast<uint8_t>(v / 10);
  } while (v != 0);
  if (pos + d >= cap) return 0;
  for (size_t i = 0; i < d; i++) out[pos + i] = digits[d - 1 - i];
  return pos + d;
}

}  // namespace

AttemptRecord parseAttemptRecord(const char* record, const char* version) {
  AttemptRecord r;
  if (record == nullptr || version == nullptr || version[0] == 0) return r;
  const size_t vl = strlen(version);
  if (strncmp(record, version, vl) != 0 || record[vl] != '#') return r;
  const char* p = record + vl + 1;
  uint8_t n = 0;
  if (!readNumber(&p, &n)) return r;
  bool healthy = false;
  uint8_t boots = 0;
  if (*p == '#') {
    p++;
    if (*p != '0' && *p != '1') return r;
    healthy = *p == '1';
    p++;
    if (*p == '#') {
      p++;
      if (!readNumber(&p, &boots)) return r;
    }
  }
  if (*p != 0) return r;
  r.n = n;
  r.healthy = healthy;
  r.boots = boots;
  return r;
}

size_t formatAttemptRecord(char* out, size_t cap, const char* version, const AttemptRecord& r) {
  if (out == nullptr || cap == 0 || version == nullptr) return 0;
  out[0] = 0;
  const size_t vl = strlen(version);
  if (vl + 2 >= cap) return 0;
  memcpy(out, version, vl);
  out[vl] = '#';
  size_t pos = appendNumber(out, vl + 1, cap, r.n);
  if (pos == 0) return 0;
  if (r.healthy || r.boots != 0) {
    if (pos + 3 >= cap) return 0;
    out[pos++] = '#';
    out[pos++] = r.healthy ? '1' : '0';
    out[pos++] = '#';
    pos = appendNumber(out, pos, cap, r.boots);
    if (pos == 0) return 0;
  }
  out[pos] = 0;
  return pos;
}

uint8_t attemptsOf(const char* record, const char* version) { return parseAttemptRecord(record, version).n; }

size_t formatAttempts(char* out, size_t cap, const char* version, uint8_t attempts) {
  AttemptRecord r;
  r.n = attempts;
  return formatAttemptRecord(out, cap, version, r);
}

bool oldKeepsStrikes(const char* badver, uint8_t badn, const char* version) {
  return badver != nullptr && version != nullptr && badn > 0 && strcmp(badver, version) == 0;
}

bool quarantineUrlFrom(const char* manifestUrl, char* out, size_t cap) {
  static const char kFrom[] = "/releases/latest/download/";
  static const char kTo[] = "/releases/download/quarantine/";
  if (manifestUrl == nullptr || out == nullptr || cap == 0) return false;
  const char* at = strstr(manifestUrl, kFrom);
  if (at == nullptr) return false;
  const size_t head = static_cast<size_t>(at - manifestUrl);
  const size_t tail = strlen(at + sizeof(kFrom) - 1);
  const size_t total = head + sizeof(kTo) - 1 + tail;
  if (total + 1 > cap) return false;
  memcpy(out, manifestUrl, head);
  memcpy(out + head, kTo, sizeof(kTo) - 1);
  memcpy(out + head + sizeof(kTo) - 1, at + sizeof(kFrom) - 1, tail + 1);
  return true;
}

bool shouldClearQuarantine(const char* url, const char* quarantineUrl, const char* quarantinedVersion,
                           const char* running) {
  if (url == nullptr || quarantineUrl == nullptr || quarantinedVersion == nullptr || running == nullptr) return false;
  if (url[0] == 0 || quarantinedVersion[0] == 0) return false;
  return strcmp(url, quarantineUrl) == 0 && strcmp(quarantinedVersion, running) != 0;
}

namespace {
// Leave through the previous image: its own strike memory when it has one, else the quarantine
// address, else nothing (the behaviour stays as it was).
void giveUp(const BootInputs& in, BootDecision* d) {
  if (in.oldKeepsStrikes) {
    d->action = BootAction::AbandonNow;
  } else if (in.quarantineAvailable) {
    d->action = BootAction::AbandonNow;
    d->quarantine = true;
  }
}
}  // namespace

BootDecision decideBoot(const BootInputs& in) {
  BootDecision d;
  d.record = in.record;
  d.failCount = in.failCount;
  if (in.pendingBoot) {
    d.record.n = in.record.n < 255 ? static_cast<uint8_t>(in.record.n + 1) : in.record.n;
    d.record.boots = 0;  // a fresh install opens a fresh probation window
    d.writeRecord = true;
    if (d.record.n < kStickyInstallAttempt) return d;
    if (in.oldKeepsStrikes) {
      // Never force-confirm: its strikes bound the loop. A dump says this build crashed: leave now.
      if (in.crashEvidence && in.otherSlotIntact) giveUp(in, &d);
    } else {
      const bool silentFailure = !in.record.healthy;  // no earlier attempt ever got Wi-Fi + a 2xx
      if (!in.crashEvidence && !silentFailure) {
        // External resets: this attempt sticks. If the dump cannot be read, a missing dump proves nothing:
        // neither confirm nor give up, the behaviour stays as it was.
        if (!in.evidenceUnavailable) d.action = BootAction::ConfirmNow;
      } else if (in.otherSlotIntact) {
        giveUp(in, &d);
      }
    }
    return d;
  }
  if (in.record.n == 0) return d;  // no record: not in probation
  if (in.record.boots >= kProbationMaxBoots) {
    d.probationExpired = true;
    return d;
  }
  d.inProbation = true;
  d.record.boots = static_cast<uint8_t>(in.record.boots + 1);
  d.writeRecord = true;
  const bool crash = in.reset == ResetClass::Crash || (in.reset == ResetClass::Brownout && in.crashEvidence);
  if (!crash) return d;  // power cycles and restarts neither count nor forgive
  if (in.failCount < 255) d.failCount = static_cast<uint8_t>(in.failCount + 1);
  d.writeFailCount = d.failCount != in.failCount;
  if (d.failCount >= in.failLimit && in.otherSlotIntact) {
    if (in.record.n < kStickyInstallAttempt) {
      d.action = BootAction::RollbackNow;  // bounded: the install count reaches the sticky attempt
    } else if (in.crashEvidence) {
      if (in.oldKeepsStrikes) {
        d.action = BootAction::RollbackNow;  // bounded by the previous image's strikes
      } else {
        giveUp(in, &d);
      }
    }
  }
  return d;
}

ProbationStep decideProbationProgress(bool inProbation, bool healthy, uint32_t uptimeMs, uint8_t failCount,
                                      bool pocOk) {
  if (!inProbation || !healthy) return ProbationStep::None;
  if (uptimeMs >= kProbationEndMs) return ProbationStep::End;
  if (failCount > 0 && uptimeMs >= kProbationHealthyMs && pocOk) return ProbationStep::ClearFails;
  return ProbationStep::None;
}

}  // namespace fry
