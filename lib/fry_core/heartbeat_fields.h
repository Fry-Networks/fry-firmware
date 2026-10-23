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

}  // namespace fry
