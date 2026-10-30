#pragma once
// Body of the installation heartbeat, POST {apiBase}/installations/{key}/installations/{id}
// (src/core/hardwareapi_client.cpp registerInstallation). Header-only (ArduinoJson only) so the
// field set is host-testable without the chip.
//
// The four flash_* / ota_* / sketch_* integers say how much room a board has for an OTA image; the
// server keeps unknown fields. They are measured once per boot by the platform shim in
// hardwareapi_client.cpp and passed in, so this builder has no platform calls.
#include <ArduinoJson.h>

#include <cstdint>

namespace fry {

struct FlashInfo {
  uint32_t flashRealSize;  // physical flash chip size, bytes
  uint32_t flashIdeSize;   // ESP.getFlashChipSize(): the size the image header / core believes
  uint32_t otaFreeBytes;   // ESP.getFreeSketchSpace(): room for the next OTA image
  uint32_t sketchSize;     // ESP.getSketchSize(): the running image
};

struct InstallationFields {
  const char* minerKey;
  const char* installId;
  const char* minerCode;
  const char* softwareVersion;
  const char* pocVersion;
  const char* hostname;
  const char* os;
  const char* deviceName;
  FlashInfo flash;
};

// The existing keys come first and unchanged (same order, same types); the four new ones follow.
// Worst-case body is bounded: 13 members, each value a short string or a uint32 (<= 10 digits); the ESP8266's four heap keys (addHeapFields) make it 17.
inline void buildInstallationDoc(JsonDocument& doc, const InstallationFields& f) {
  doc["miner_key"] = f.minerKey;
  doc["install_id"] = f.installId;
  doc["minerCode"] = f.minerCode;  // camelCase - every sibling key is snake_case (protocol)
  doc["software_version_installed"] = f.softwareVersion;
  doc["poc_version_installed"] = f.pocVersion;
  doc["hostname"] = f.hostname;
  doc["os"] = f.os;
  doc["is_installed"] = true;
  doc["device_name"] = f.deviceName;
  doc["flash_real_size"] = f.flash.flashRealSize;
  doc["flash_ide_size"] = f.flash.flashIdeSize;
  doc["ota_free_bytes"] = f.flash.otaFreeBytes;
  doc["sketch_size"] = f.flash.sketchSize;
}

// Heap and loop-stack headroom, sampled by the platform shim in one pass (ESP8266: ESP.getHeapStats + ESP.getFreeContStack).
struct HeapInfo {
  uint32_t freeHeap;        // total free heap, bytes
  uint32_t maxFreeBlock;    // largest contiguous free block, bytes: what a TLS session's input buffer needs
  uint32_t heapFrag;        // fragmentation, percent (0 = one free block)
  uint32_t stackHighWater;  // loop-stack bytes still unused at its deepest point since boot
};

// Appended AFTER buildInstallationDoc(), so the 13-member body (pinned by test_heartbeat_fields) and the 0.4.7 prefix are untouched.
// Only the ESP8266 platform shim calls it (-DFRY_HEARTBEAT_HEAP=1 in [env:esp8266]); unused elsewhere, so it emits no code there.
inline void addHeapFields(JsonDocument& doc, const HeapInfo& h) {
  doc["free_heap"] = h.freeHeap;
  doc["max_free_block"] = h.maxFreeBlock;
  doc["heap_frag"] = h.heapFrag;
  doc["stack_high_water"] = h.stackHighWater;
}

// Relay connect latency, from lib/fry_core/relay_latency.h's bounded ring in the ESP32 relay task.
// Appended the same way as addHeapFields: after buildInstallationDoc(), so the 13-member body and
// the 0.4.7 prefix are untouched. Only builds with the WireGuard relay (-DFRY_HAS_WIREGUARD=1, i.e.
// the ESP32 family) call it; there it is always present, with 0/0 and relay_samples 0 before the
// first successful connect, because every other appended field is unconditional too.
struct RelayLatencyInfo {
  uint32_t p50Ms;   // median of the recent successful upstream connects
  uint32_t p95Ms;   // nearest-rank 95th percentile of the same samples
  uint32_t samples; // how many samples the two values were computed from (0..kLatencySamples)
};

inline void addRelayLatencyFields(JsonDocument& doc, const RelayLatencyInfo& r) {
  doc["relay_p50_ms"] = r.p50Ms;
  doc["relay_p95_ms"] = r.p95Ms;
  doc["relay_samples"] = r.samples;
}

// Why the chip last reset, one small unsigned integer (PROTOCOL.md 11.10). The platform shim in hardwareapi_client.cpp reads it once
// per boot (ESP32 family: esp_reset_reason_t; ESP8266: rst_info.reason), so the value is chip-specific and `os` says which table
// applies. Appended last, after the heap and relay fields, so the 13-member body and every earlier append are untouched. Always
// present on every build, 0 included. Clamped to a byte: the server mirror keeps only 0..255.
inline void addResetReasonField(JsonDocument& doc, uint32_t raw) {
  doc["reset_reason"] = raw > 255 ? 255u : raw;
}

}  // namespace fry
