#pragma once
// Bench-only fault images of the PRODUCTION envs. FRY_BENCH_FAULT is passed by the manual
// fault-images workflow only (never by a release or a normal build); it selects the same fault
// numbers as FRY_TEST_FAULT (src/core/ota_client.h) without the test OTA channel. With the macro
// undefined this header defines nothing, so no normal image changes.
#if defined(FRY_BENCH_FAULT) && !defined(FRY_TEST_FAULT)
#define FRY_TEST_FAULT FRY_BENCH_FAULT
#define FRY_BENCH_IMAGE 1
#endif
