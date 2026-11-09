#pragma once
// Reads the optional builds.<env>.rollback object of the OTA manifest (PROTOCOL.md 11.11). Header-only,
// like ota_rollout_json.h. The decision itself is decideOtaRollback (ota_health.h).
//
//   "rollback": {"version": "0.4.24", "url": "...", "sha256": "<64 hex>", "from": ["0.4.25", ...]}
//
// Strict: anything that is not exactly this shape reads as ABSENT (no rollback), never a crash and never
// a partial rollback. version, url and sha256 must be non-empty strings; "from" must be an array of at
// most kRollbackFromMax strings, every element a string. Unknown scalar keys are tolerated.
#include <ArduinoJson.h>

#include <cstring>

namespace fry {

const size_t kRollbackFromMax = 16;

struct RollbackEntry {
  const char* version = "";
  const char* url = "";
  const char* sha256 = "";
};

// True iff `rollback` is a well-formed rollback object whose "from" names `running`. The strings point
// into the manifest document and live as long as it does.
inline bool readRollbackEntry(JsonVariantConst rollback, const char* running, RollbackEntry* out) {
  if (!out || !running || !running[0] || !rollback.is<JsonObjectConst>()) return false;
  JsonObjectConst o = rollback.as<JsonObjectConst>();
  JsonVariantConst vv = o["version"], vu = o["url"], vs = o["sha256"], vf = o["from"];
  if (!vv.is<const char*>() || !vu.is<const char*>() || !vs.is<const char*>()) return false;
  if (!vf.is<JsonArrayConst>()) return false;
  const char* version = vv.as<const char*>();
  const char* url = vu.as<const char*>();
  const char* sha = vs.as<const char*>();
  if (!version[0] || !url[0] || !sha[0]) return false;
  JsonArrayConst from = vf.as<JsonArrayConst>();
  if (from.size() == 0 || from.size() > kRollbackFromMax) return false;
  bool listed = false;
  for (JsonVariantConst e : from) {
    if (!e.is<const char*>()) return false;
    if (strcmp(e.as<const char*>(), running) == 0) listed = true;
  }
  if (!listed) return false;
  out->version = version;
  out->url = url;
  out->sha256 = sha;
  return true;
}

}  // namespace fry
