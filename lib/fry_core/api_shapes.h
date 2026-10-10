#pragma once
// Pure helpers for the hardwareapi request/response shapes the firmware depends on.
#include <ArduinoJson.h>

namespace fry {

// T9: the `software` block of the PoC PUT document, in the shape hwapi's version gate reads
// (software.os selects the platform row, software.poc_version_installed is compared, and
// software_version_installed is the firmware version). `os` is FRY_BUILD_ENV, the same value the
// installation POST sends.
void fillPocSoftware(JsonObject software, const char* os, const char* firmwareVersion);

// Lease (U2/U3). The firmware only RENEWS (PATCH); it never acquires. A renew by an install that
// holds no lease answers 200 {"granted":false,"holder_install_id":null,"ttl_seconds":0,
// "error_code":null}: that is "no lease held" (NotHeld), NOT a denial, and every board is in that
// state today. Denied means another install holds it:
//   reason_code == "lease_held_elsewhere", OR granted == false with a non-empty holder_install_id
//   that differs from our own install id.
enum class LeaseVerdict { Granted, Denied, NotHeld };
struct LeaseResult {
  LeaseVerdict verdict = LeaseVerdict::Granted;
  char reasonCode[40] = {};
};
// A body without a boolean `granted` (an older server, empty body) counts as Granted. ownInstallId
// may be null/empty (then only the reason_code can denote a denial).
LeaseResult parseLeaseResponse(const char* json, const char* ownInstallId = "");

}  // namespace fry
