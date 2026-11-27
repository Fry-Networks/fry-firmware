#pragma once
// src/core/kv_store.h wraps `Preferences` on every non-ESP8266 chip. LibreTiny declares only IPreferences (no implementation), so on
// the BK7231N that name is the FlashDB-backed store.
#ifdef __cplusplus  // force-included (-include) into the C files too
#include "../kv_flashdb.h"
#include "../../boards/prefs_impl.h"

using Preferences = fry_boards::PreferencesT<fry_boards::FlashDbBackend>;
#endif
