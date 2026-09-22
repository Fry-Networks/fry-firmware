#pragma once
// Improv Serial bridge: moves bytes between Serial and the pure parser/encoder in
// lib/fry_core/improv_serial.*, and answers the four RPC commands using the provisioning
// transport that is already running. Enabled by -DFRY_HAS_IMPROV=1 (platformio.ini [embedded]).
//
// It is forced OFF in the lab builds. FRY_SERIAL_PROVISION gives src/core/serial_commands.cpp a
// line-based JSON console on the same UART, and tools/provision.py drives boards with it; a
// binary packet stream and a line protocol cannot share one port, and the lab build is the one
// where losing the console would cost the most.
#include <Arduino.h>

#if defined(FRY_SERIAL_PROVISION)
#undef FRY_HAS_IMPROV
#define FRY_HAS_IMPROV 0
#endif
#ifndef FRY_HAS_IMPROV
#define FRY_HAS_IMPROV 0
#endif

namespace fry_improv {

#if FRY_HAS_IMPROV

// Device name and miner key as src/main.cpp already computed them (the key may have just been
// migrated from an IOT- prefix, so it must not be recomputed here).
void init(const char* deviceName, const char* minerKey);

// Call every loop(). `transportRunning` is fry::BootPolicy::transportStarted(): Improv answers
// only on a board that is provisionable, never on one that booted straight into its network.
void poll(bool transportRunning);

#else

inline void init(const char*, const char*) {}
inline void poll(bool) {}

#endif

}  // namespace fry_improv
