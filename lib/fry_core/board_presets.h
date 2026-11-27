#pragma once
// Preset table of the non-ESP boards (Raspberry Pi Pico W / Pico 2 W and the Beken BK7231N). Pure C++, no Arduino include, so
// `pio test -e native_boards` pins it. The os value is FRY_BUILD_ENV: it is what the installation heartbeat sends as `os` and
// what the OTA manifest is looked up by (builds[os]).
#include <cstddef>
#include <cstdint>

namespace fry {
namespace boards {

enum class KvBackend : uint8_t { LittleFs, FlashDb };
// What the OTA download writes: an arduino-pico Updater .bin (staged in LittleFS, applied by the boot ROM helper) or a
// LibreTiny UF2 stream (the Update class feeds it through uf2ota into the download partition, the Beken bootloader applies it).
enum class ImageKind : uint8_t { None, PicoBin, BkUf2 };

struct Preset {
  const char* env;      // PlatformIO environment name
  const char* os;       // FRY_BUILD_ENV, the heartbeat `os`
  const char* chipTag;  // FRY_CHIP, the device-name tag: FRY-<chipTag>-<MAC6>
  KvBackend kv;
  ImageKind image;
  int16_t resetButtonPin;  // active low, INPUT_PULLUP; the factory-reset hold (lib/fry_core/reset_button.h)
};

size_t presetCount();
const Preset& presetAt(size_t i);
const Preset* presetForEnv(const char* env);
const Preset* presetForOs(const char* os);

// ^FRY-(RP2040|RP2350|BK7231N)-[0-9A-F]{6}$ . The ESP grammar (fry::isValidDeviceName) is a closed list shared with the phone
// app and is left alone; this is the grammar of the tags added here.
bool isValidBoardDeviceName(const char* name);

// The heartbeat `reset_reason` (PROTOCOL.md 11.10) from the HAL's short token, in the ESP32 esp_reset_reason_t numbering:
// poweron 1, external 2, software 3, panic 4, wdt 7, brownout 9; anything else 0 (unknown).
uint8_t resetReasonCode(const char* token);

}  // namespace boards
}  // namespace fry
