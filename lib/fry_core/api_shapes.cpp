#include "api_shapes.h"

#include <cstring>

namespace fry {

void fillPocSoftware(JsonObject software, const char* os, const char* firmwareVersion) {
  software["os"] = os;
  software["poc_version_installed"] = "1.0.0";
  software["software_version_installed"] = firmwareVersion;
}

LeaseResult parseLeaseResponse(const char* json) {
  LeaseResult r;
  if (json == nullptr || json[0] == 0) return r;
  JsonDocument doc;
  if (deserializeJson(doc, json)) return r;
  JsonVariant g = doc["granted"];
  if (g.is<bool>() && !g.as<bool>()) {
    r.verdict = LeaseVerdict::Denied;
    const char* rc = doc["reason_code"] | "";
    std::strncpy(r.reasonCode, rc, sizeof(r.reasonCode) - 1);
  }
  return r;
}

}  // namespace fry
