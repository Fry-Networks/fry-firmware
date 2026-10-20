#pragma once
// Reads the optional top-level "rollout" object of the OTA manifest (see ota_rollout.h) and says
// whether THIS device may take the update. Header-only, like olostep_kill.h.
//
// Strictness: a rollout object that is not exactly well-formed is IGNORED ENTIRELY (verdict
// Malformed, which rolloutAllows() maps to "no gate"). Well-formed means: an object whose
// bucket_lo and bucket_hi are JSON integers 0..99 with lo <= hi; "allow", when present, an array
// of strings that are each exactly 16 hex digits; no nested object/array anywhere else inside it.
// Unknown keys with scalar values are tolerated.
#include <ArduinoJson.h>

#include <cstdint>
#include <cstring>

#include "ota_rollout.h"

namespace fry {

enum class RolloutVerdict : uint8_t { Absent, Malformed, Eligible, NotEligible };

// Only a well-formed rollout this device is outside of closes the gate.
inline bool rolloutAllows(RolloutVerdict v) { return v != RolloutVerdict::NotEligible; }

inline RolloutVerdict evaluateRollout(JsonVariantConst manifest, const uint8_t digest[32]) {
  // Key presence is found by walking the pairs (containsKey is deprecated in ArduinoJson 7), so an
  // explicit "rollout": null is PRESENT and, not being an object, Malformed.
  JsonObjectConst top = manifest.as<JsonObjectConst>();
  bool present = false;
  JsonVariantConst r;
  for (JsonPairConst kv : top) {
    if (strcmp(kv.key().c_str(), "rollout") == 0) {
      present = true;
      r = kv.value();
      break;
    }
  }
  if (!present) return RolloutVerdict::Absent;
  if (!r.is<JsonObjectConst>()) return RolloutVerdict::Malformed;

  JsonObjectConst o = r.as<JsonObjectConst>();
  JsonVariantConst vlo = o["bucket_lo"];
  JsonVariantConst vhi = o["bucket_hi"];
  if (!vlo.is<int>() || !vhi.is<int>()) return RolloutVerdict::Malformed;
  const int lo = vlo.as<int>();
  const int hi = vhi.as<int>();
  if (lo < 0 || hi > 99 || lo > hi) return RolloutVerdict::Malformed;

  // No nested containers except the allow array itself; scalars under unknown keys are fine.
  bool hasAllow = false;
  JsonVariantConst va;
  for (JsonPairConst kv : o) {
    if (strcmp(kv.key().c_str(), "allow") == 0) {
      hasAllow = true;
      va = kv.value();
      continue;
    }
    if (kv.value().is<JsonObjectConst>() || kv.value().is<JsonArrayConst>()) return RolloutVerdict::Malformed;
  }
  if (hasAllow) {
    if (!va.is<JsonArrayConst>()) return RolloutVerdict::Malformed;
    for (JsonVariantConst e : va.as<JsonArrayConst>()) {
      if (!e.is<const char*>() || !isRolloutHexPrefix(e.as<const char*>())) return RolloutVerdict::Malformed;
    }
  }

  // Well-formed from here on.
  char prefix[kRolloutPrefixHexLen + 1];
  rolloutPrefixHex(digest, prefix);
  bool inAllow = false;
  if (hasAllow) {
    for (JsonVariantConst e : va.as<JsonArrayConst>()) {
      if (rolloutPrefixMatches(e.as<const char*>(), prefix)) {
        inAllow = true;
        break;
      }
    }
  }
  return rolloutEligible(static_cast<uint32_t>(lo), static_cast<uint32_t>(hi), rolloutBucket(digest), inAllow)
             ? RolloutVerdict::Eligible
             : RolloutVerdict::NotEligible;
}

}  // namespace fry
