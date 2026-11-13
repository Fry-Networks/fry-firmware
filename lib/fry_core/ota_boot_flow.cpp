#include "ota_boot_flow.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace fry {

namespace {

void say(OtaBootPorts& p, const char* fmt, ...) {
  char line[220];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(line, sizeof(line), fmt, ap);
  va_end(ap);
  p.log(line);
}

bool writeRecord(OtaBootPorts& p, const char* version, const AttemptRecord& r) {
  char buf[64];
  if (formatAttemptRecord(buf, sizeof(buf), version, r) == 0) return false;
  return p.setAttempts(buf);
}

}  // namespace

BootFlowResult runBootFlow(OtaBootPorts& p, const BootFlowConfig& c) {
  BootFlowResult res;
  char quarantine[160] = {0};
  const bool qDerivable = quarantineUrlFrom(c.manifestUrl, quarantine, sizeof(quarantine));
  char url[200] = {0};
  char qver[32] = {0};
  p.getUrl(url, sizeof(url));
  p.getQuarantined(qver, sizeof(qver));
  // A different build than the quarantined one is running: the override has done its job.
  if (qDerivable && shouldClearQuarantine(url, quarantine, qver, c.version)) {
    p.setQuarantined("");
    p.setUrl("");
    url[0] = 0;
    p.log("ota: quarantine address cleared - a different build is running");
  }

  BootInputs bi;
  bi.pendingBoot = p.pendingBoot();
  char rec[64] = {0};
  p.getAttempts(rec, sizeof(rec));
  bi.record = parseAttemptRecord(rec, c.version);
  bi.failCount = p.getBootFails();
  bi.reset = classifyResetReason(p.resetReason());
  bi.failLimit = c.failLimit;
  if (bi.record.n > 0) {
    // These read flash: only a build whose record is already open can act on them.
    bi.otherSlotIntact = p.otherSlotIntact();
    const CrashEvidence ev = p.crashEvidence();
    bi.crashEvidence = ev == CrashEvidence::Yes;
    char badver[32] = {0};
    p.getBadVer(badver, sizeof(badver));
    bi.oldKeepsStrikes = oldKeepsStrikes(badver, p.getBadN(), c.version);
    bi.quarantineAvailable = qDerivable && (url[0] == 0 || strcmp(url, quarantine) == 0);
    say(p, "ota: crash evidence for %s: %s", c.version,
        ev == CrashEvidence::Yes ? "yes" : (ev == CrashEvidence::No ? "no" : "unavailable"));
    if (ev == CrashEvidence::Unavailable) {
      p.log("ota: core dump inspection is unavailable (compiled out, or no core dump partition) - no crash evidence can be read");
    }
    say(p, "ota: previous image keeps strikes for %s: %s, earlier attempt reached the API: %s", c.version,
        bi.oldKeepsStrikes ? "yes" : "no", bi.record.healthy ? "yes" : "no");
  }

  const BootDecision bd = decideBoot(bi);
  res.record = bd.record;
  res.failCount = bi.pendingBoot ? 0 : bd.failCount;  // a pending boot's counter belongs to the pending check
  res.inProbation = bd.inProbation || bi.pendingBoot;

  if (bd.probationExpired) {
    p.clearAttempts();
    if (bi.failCount != 0) p.setBootFails(0);
    res.record = AttemptRecord();
    res.failCount = 0;
    res.inProbation = false;
    say(p, "ota: probation over for %s - %u boots", c.version, static_cast<unsigned>(bi.record.boots));
  }
  if (bd.writeRecord) {
    if (!writeRecord(p, c.version, bd.record)) {
      res.recordWriteFailed = true;
      say(p, "ota: NVS write failed for the install attempt record of %s - the count stays as it was", c.version);
    }
    if (bi.pendingBoot) {
      say(p, "ota: install attempt %u/%u of %s", static_cast<unsigned>(bd.record.n),
          static_cast<unsigned>(kStickyInstallAttempt), c.version);
    } else {
      say(p, "ota: probation for %s - %u/%u crash boots without health, reset_reason=%u", c.version,
          static_cast<unsigned>(bd.failCount), static_cast<unsigned>(c.failLimit),
          static_cast<unsigned>(p.resetReason()));
    }
  }
  if (bd.writeFailCount && !p.setBootFails(bd.failCount)) {
    say(p, "ota: NVS write failed for the crash boot counter of %s - the count stays as it was", c.version);
  }

  switch (bd.action) {
    case BootAction::ConfirmNow:
      say(p, "ota: install attempt %u/%u of %s - no crash evidence and an earlier attempt reached the API, confirmed at once",
          static_cast<unsigned>(bd.record.n), static_cast<unsigned>(kStickyInstallAttempt), c.version);
      res.outcome = FlowOutcome::ConfirmNow;
      return res;
    case BootAction::RollbackNow:
    case BootAction::AbandonNow: {
      bool stored = false;
      if (bd.quarantine) {
        p.setQuarantined(c.version);  // the version first: a partial write leaves a note that can be cleared
        p.setUrl(quarantine);
        stored = true;
        say(p, "ota: %s is given up - the previous image is pointed at the quarantine manifest", c.version);
      } else if (bd.action == BootAction::AbandonNow) {
        say(p, "ota: %s is given up - the previous image keeps its strike", c.version);
      }
      if (!bi.pendingBoot) {
        say(p, "ota: %u crash boots without health during probation of %s - rolling back to the previous image",
            static_cast<unsigned>(bd.failCount), c.version);
      }
      p.setPending(c.version);  // names the abandoned version for a previous image that counts strikes
      if (!p.selectOtherSlot()) {
        if (stored) {
          p.setQuarantined("");
          p.setUrl("");
        }
        p.log("ota: the other OTA slot cannot be booted - staying");
        res.outcome = FlowOutcome::RollbackFailed;
      } else {
        res.outcome = FlowOutcome::RolledBack;
      }
      p.finishRollback();
      return res;
    }
    case BootAction::Continue:
      break;
  }
  if (bi.pendingBoot && bd.record.n >= kStickyInstallAttempt) {
    say(p, "ota: install attempt %u/%u of %s - not confirmed at once (crash evidence, a failing earlier attempt or strikes)",
        static_cast<unsigned>(bd.record.n), static_cast<unsigned>(kStickyInstallAttempt), c.version);
  }
  return res;
}

bool recordHealthReached(OtaBootPorts& p, const BootFlowConfig& c, AttemptRecord* rec) {
  if (rec == nullptr || rec->n == 0 || rec->healthy) return true;
  AttemptRecord next = *rec;
  next.healthy = true;
  if (!writeRecord(p, c.version, next) && !writeRecord(p, c.version, next)) {
    say(p, "ota: NVS write failed for the health note of %s - a later attempt may count as not having reached the API",
        c.version);
    return false;
  }
  *rec = next;
  return true;
}

}  // namespace fry
