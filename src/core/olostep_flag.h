#pragma once
// Feature gate for the opt-in "olostep" web-relay: compiled OUT unless a dedicated opt-in build env
// passes -DFRY_HAS_OLOSTEP=1. Kept in its own tiny header, with no declarations, so that including
// it from production translation units leaves their object code and debug info untouched.
#ifndef FRY_HAS_OLOSTEP
#define FRY_HAS_OLOSTEP 0
#endif
