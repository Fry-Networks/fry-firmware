#pragma once
// OTA client per PROTOCOL.md sections 6 and 11.5.
//
// Rollback. The ESP32-family bootloader shipped with espressif32@6.12.0 IS built with app rollback
// (CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y in every chip's sdkconfig). What defeated it was
// arduino-esp32's initArduino(), which marks the running image valid before setup() unless the
// sketch overrides the weak verifyRollbackLater(). src/esp32/ota_rollback.cpp now overrides it, so
// a new image stays PENDING_VERIFY until hardwareapi has answered AND it has run through the first
// PoC/lease cycle (POC_INTERVAL_MS + 60 s); a crash or reboot before that makes the bootloader
// boot the previous image, and loopGuard() rolls back an image that gets no answer in 20 minutes
// of Wi-Fi (PROTOCOL.md 11.8). The previous image counts a strike per rollback. The NVS boot
// counter (lib/fry_core/ota_boot_counter.h) is kept as a second line, and is the only one on
// ESP8266, which has a single slot.
#include <Arduino.h>

// Test-only fault injection (tools/fry_prebuild.py sets it from FRY_TEST_FAULT for ESP32-family
// *_test envs and refuses everything else): 1 abort in setup() after the banner, 2 never
// heartbeat, 3 crash 60 s after the first heartbeat (inside the settle window, so it rolls back).
#if defined(FRY_TEST_FAULT) && !defined(FRY_OTA_TEST_CHANNEL)
#error "FRY_TEST_FAULT is for *_test (test OTA channel) builds only"
#endif

namespace fry_ota {

// Call once early in setup(), before the boot banner if possible. If fry_ota.pending equals the
// running firmware version, this is a post-OTA boot: the boot-fail counter is incremented and,
// if it has reached OTA_BOOT_FAIL_LIMIT, this boots back into the other OTA slot immediately
// (ESP32/S3/C3) or just logs the failure (ESP8266 has one slot — rollback is impossible there).
void init();

// Clears the pending flag and the boot-fail counter. Called when the image is marked valid.
void confirmGood();

// Every hardwareapi response (registration, PoC, lease) comes through here. Once any HTTP status
// has been seen AND the image has run for the settle window, it is marked valid (confirmGood() +
// esp_ota_mark_app_valid_cancel_rollback() when PENDING_VERIFY); every later answer retries a mark
// that failed. A 2xx refreshes the heartbeat age. `http` <= 0 (transport error) is ignored.
void noteHeartbeat(int http, const char* what);

// Call right before a restart that is not a failure (restartToApply, a USB re-key). While the image
// is still pending, the bootloader will roll it back; this tells the previous image not to count
// that as a strike.
void notePlannedRestart();

// Call every loop(), in every phase: marks the image valid when the settle window ends after an
// answer, and rolls back a PENDING_VERIFY image that got no answer in 20 min of Wi-Fi (2 min in
// *_test builds). The rollback part is ESP32 family only.
void loopGuard();

// Seconds since the last 2xx heartbeat, -1 if none this boot.
int32_t heartbeatAgeS();

// "valid" | "pending" | "rolled_back" (PROTOCOL.md section 11).
const char* imageStateName();

// Fetches the manifest, compares versions, and downloads+verifies+applies an update if newer.
// Returns true if an update was applied (in which case the device has already restarted and
// this call never returns to the caller).
bool checkNow();

// Drives the OTA_CHECK_MS cadence. Call every loop() once WiFi is connected.
void tick();

}  // namespace fry_ota
