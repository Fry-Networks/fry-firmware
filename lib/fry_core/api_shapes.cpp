#include "api_shapes.h"

#include <cstring>

namespace fry {

void fillPocSoftware(JsonObject software, const char* os, const char* firmwareVersion) {
  software["os"] = os;
  software["poc_version_installed"] = "1.0.0";
  software["software_version_installed"] = firmwareVersion;
}

LeaseResult parseLeaseResponse(const char* json, const char* ownInstallId) {
  LeaseResult r;
  if (json == nullptr || json[0] == 0) return r;
  JsonDocument doc;
  if (deserializeJson(doc, json)) return r;
  JsonVariant g = doc["granted"];
  if (!(g.is<bool>() && !g.as<bool>())) return r;  // granted:true, or no boolean: Granted
  const char* rc = doc["reason_code"] | "";
  const char* holder = doc["holder_install_id"] | "";  // null / missing -> ""
  const char* own = ownInstallId ? ownInstallId : "";
  const bool heldElsewhere = std::strcmp(rc, "lease_held_elsewhere") == 0;
  const bool otherHolder = holder[0] != 0 && own[0] != 0 && std::strcmp(holder, own) != 0;
  if (heldElsewhere || otherHolder) {
    r.verdict = LeaseVerdict::Denied;
    std::strncpy(r.reasonCode, rc, sizeof(r.reasonCode) - 1);
  } else {
    r.verdict = LeaseVerdict::NotHeld;
  }
  return r;
}

}  // namespace fry
