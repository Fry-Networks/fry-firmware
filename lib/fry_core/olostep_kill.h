#pragma once
// Fleet kill switch for the opt-in "olostep" web-relay, read from the OTA manifest.
//
// The manifest carries a top-level "olostep_kill". Only a JSON boolean true switches the relay
// off; an absent key, false, or any other type (string "true", number 1, null) means "no kill",
// which is exactly what every manifest published before the key existed says. Header-only so that
// builds without the relay carry no object code from it.
#include <ArduinoJson.h>

namespace fry {

inline bool manifestOlostepKill(JsonVariantConst manifest) {
  JsonVariantConst v = manifest["olostep_kill"];
  return v.is<bool>() && v.as<bool>();
}

}  // namespace fry
