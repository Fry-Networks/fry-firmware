#include "olostep_consent.h"

#if FRY_HAS_OLOSTEP

#include "kv_store.h"

bool getOlostepOptIn() {
  KvStore p;
  p.begin("fry_olostep", true);
  bool v = p.getBool("optIn", false);
  p.end();
  return v;
}
void setOlostepOptIn(bool v) {
  KvStore p;
  p.begin("fry_olostep", false);
  p.putBool("optIn", v);
  p.end();
}

#endif  // FRY_HAS_OLOSTEP
