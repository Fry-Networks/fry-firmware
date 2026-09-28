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

// Device name as src/main.cpp computed it. The miner key is no longer cached here: an 0xF0 write
// can change it at any time, so it is read through fry_identity::ensureMinerKey() when needed.
void init(const char* deviceName, const char* minerKey);

// Call every loop(). The read-only commands (current state, device info, 0xF1 status) and the
// 0xF0 key write are answered in every phase, so a web flasher sees a board it can UPDATE instead
// of one it must erase (PROTOCOL.md section 11.4). `transportRunning` is
// fry::BootPolicy::transportStarted(): Wi-Fi settings and the scan are still answered only on a
// board that is provisionable, never on one that booted straight into its network.
void poll(bool transportRunning);

// True once after a 0xF0 write stored a key DIFFERENT from the previous one. src/main.cpp restarts
// a board that is already Ready so it registers with the new key.
bool consumeKeyChanged();

#else

inline void init(const char*, const char*) {}
inline void poll(bool) {}
inline bool consumeKeyChanged() { return false; }

#endif

}  // namespace fry_improv
