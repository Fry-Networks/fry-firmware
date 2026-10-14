#pragma once
// Opt-in consent for the "olostep" web-relay. Compiled OUT by default (-DFRY_HAS_OLOSTEP=1 is
// added only by a dedicated opt-in build env, never by a production env). Even when compiled in,
// the relay stays inert until the owner opts in: the stored flag defaults to FALSE.
#include "olostep_flag.h"

// Shown verbatim by the provisioning UI / consent gate.
constexpr const char OLOSTEP_OWNER_DISCLOSURE[] =
    "When enabled, this device relays third-party unauthenticated web requests through your IP. "
    "It is opt-in and reversible. It never uses your own accounts, sessions, or stored credentials.";

#if FRY_HAS_OLOSTEP

// NVS namespace "fry_olostep", key "optIn" (bool, default false).
bool getOlostepOptIn();
void setOlostepOptIn(bool v);

#endif  // FRY_HAS_OLOSTEP
