#pragma once
// src/core/kv_store.h wraps `Preferences` on every non-ESP8266 chip. On the Pico boards that name is the LittleFS-backed store.
#include "../kv_littlefs.h"
#include "../../boards/prefs_impl.h"

using Preferences = fry_boards::PreferencesT<fry_boards::LittleFsBackend>;
