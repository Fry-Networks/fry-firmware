#pragma once
// OTA client per PROTOCOL.md section 6. Rollback uses the NVS boot counter from T2
// (lib/fry_core/ota_boot_counter.h), NOT Update.rollBack()/esp_ota_mark_app_valid_cancel_
// rollback() — that ESP-IDF call is a no-op on the arduino-esp32 2.0.x bootloader shipped with
// espressif32@6.12.0 (it is built without app-rollback support), so relying on it would silently
// never roll back a bad image.
#include <Arduino.h>

namespace fry_ota {

// Call once early in setup(), before the boot banner if possible. If fry_ota.pending equals the
// running firmware version, this is a post-OTA boot: the boot-fail counter is incremented and,
// if it has reached OTA_BOOT_FAIL_LIMIT, this boots back into the other OTA slot immediately
// (ESP32/S3/C3) or just logs the failure (ESP8266 has one slot — rollback is impossible there).
void init();

// Call once the device has proven itself good (this firmware wires it to the first successful
// hardwareapi registration). Clears the pending flag and the boot-fail counter.
void confirmGood();

// Fetches the manifest, compares versions, and downloads+verifies+applies an update if newer.
// Returns true if an update was applied (in which case the device has already restarted and
// this call never returns to the caller).
bool checkNow();

// Drives the OTA_CHECK_MS cadence. Call every loop() once WiFi is connected.
void tick();

}  // namespace fry_ota
