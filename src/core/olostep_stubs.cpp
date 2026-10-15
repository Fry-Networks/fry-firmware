// Weak no-op defaults for the Olostep executor interface (see olostep_exec.h). Empty unless
// FRY_HAS_OLOSTEP, so default builds contain nothing from this file.
#include "olostep_exec.h"

#if FRY_HAS_OLOSTEP

extern "C" __attribute__((weak)) void fry_olostep_start() {}
extern "C" __attribute__((weak)) void fry_olostep_stop() {}
extern "C" __attribute__((weak)) void fry_olostep_tick() {}
extern "C" __attribute__((weak)) void fry_olostep_optin_changed() {}
extern "C" __attribute__((weak)) bool fry_olostep_running() { return false; }
extern "C" __attribute__((weak)) void fry_olostep_consent_write_failed(bool) {}

#endif  // FRY_HAS_OLOSTEP
