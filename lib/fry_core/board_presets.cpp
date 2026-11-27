#include "board_presets.h"

#include <cstring>

namespace fry {
namespace boards {

namespace {

// Reset button pins: GP15 on both Picos (a button to GND; the pin floats high through INPUT_PULLUP when none is fitted),
// P6 on the generic Tuya BK7231N-QFN32 module (an unused GPIO there; override with -DFRY_RESET_BUTTON_PIN).
const Preset kPresets[] = {
    {"rpipicow", "rp2040", "RP2040", KvBackend::LittleFs, ImageKind::PicoBin, 15},
    {"rpipico2w", "rp2350", "RP2350", KvBackend::LittleFs, ImageKind::PicoBin, 15},
    {"bk7231n", "bk7231n", "BK7231N", KvBackend::FlashDb, ImageKind::BkUf2, 6},
};
const size_t kCount = sizeof(kPresets) / sizeof(kPresets[0]);

bool isHexUpper(char c) { return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'); }

}  // namespace

size_t presetCount() { return kCount; }
const Preset& presetAt(size_t i) { return kPresets[i < kCount ? i : 0]; }

const Preset* presetForEnv(const char* env) {
  if (!env) return nullptr;
  for (size_t i = 0; i < kCount; i++)
    if (strcmp(kPresets[i].env, env) == 0) return &kPresets[i];
  return nullptr;
}

const Preset* presetForOs(const char* os) {
  if (!os) return nullptr;
  for (size_t i = 0; i < kCount; i++)
    if (strcmp(kPresets[i].os, os) == 0) return &kPresets[i];
  return nullptr;
}

bool isValidBoardDeviceName(const char* name) {
  if (!name || strncmp(name, "FRY-", 4) != 0) return false;
  const char* tag = name + 4;
  const char* dash = strchr(tag, '-');
  if (!dash) return false;
  const size_t tagLen = static_cast<size_t>(dash - tag);
  bool known = false;
  for (size_t i = 0; i < kCount; i++)
    if (strlen(kPresets[i].chipTag) == tagLen && strncmp(kPresets[i].chipTag, tag, tagLen) == 0) known = true;
  if (!known) return false;
  const char* mac = dash + 1;
  if (strlen(mac) != 6) return false;
  for (int i = 0; i < 6; i++)
    if (!isHexUpper(mac[i])) return false;
  return true;
}

uint8_t resetReasonCode(const char* token) {
  if (!token) return 0;
  static const struct {
    const char* token;
    uint8_t code;
  } kMap[] = {{"poweron", 1}, {"external", 2}, {"software", 3}, {"panic", 4}, {"wdt", 7}, {"brownout", 9}};
  for (size_t i = 0; i < sizeof(kMap) / sizeof(kMap[0]); i++)
    if (strcmp(kMap[i].token, token) == 0) return kMap[i].code;
  return 0;
}

}  // namespace boards
}  // namespace fry
