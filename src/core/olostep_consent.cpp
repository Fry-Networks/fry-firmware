#include "olostep_consent.h"

#if FRY_HAS_OLOSTEP

#include <Arduino.h>

#include "kv_store.h"
#include "olostep_consent_outcome.h"
#include "olostep_exec.h"

bool getOlostepOptIn() {
  KvStore p;
  p.begin("fry_olostep", true);
  bool v = p.getBool("optIn", false);
  p.end();
  return v;
}
bool setOlostepOptIn(bool v) {
  KvStore p;
  const bool beginOk = p.begin("fry_olostep", false);
  const size_t put = beginOk ? p.putBool("optIn", v) : 0;
  p.end();
  const fry_olostep::ConsentWriteOutcome out = fry_olostep::consentWriteOutcome(beginOk, put, v);
  if (!out.persisted) {
    Serial.printf("[olostep] consent write FAILED (requested %s)%s\n", v ? "ON" : "OFF",
                  out.mustForceDormant ? " - relay forced dormant" : "");
  }
  if (out.mustForceDormant) fry_olostep_consent_write_failed(v);
  return out.persisted;
}

#endif  // FRY_HAS_OLOSTEP
