#pragma once
// Lab-only serial provisioning commands (PROTOCOL.md section 7). Compiled only when
// -DFRY_SERIAL_PROVISION=1 (the *_lab envs) — never in a fleet-release build.
#ifdef FRY_SERIAL_PROVISION

// Called once from setup().
void fry_serial_init();

// Called every loop(); reads at most one complete '\n'-terminated line per call and dispatches
// it. Never blocks — a partial line is buffered across calls.
void fry_serial_poll();

#endif  // FRY_SERIAL_PROVISION
