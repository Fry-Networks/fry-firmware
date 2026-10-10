#pragma once
// Pure helpers for the hardwareapi request/response shapes the firmware depends on.
#include <ArduinoJson.h>

namespace fry {

// T9: the `software` block of the PoC PUT document, in the shape hwapi's version gate reads
// (software.os selects the platform row, software.poc_version_installed is compared, and
// software_version_installed is the firmware version). `os` is FRY_BUILD_ENV, the same value the
// installation POST sends.
void fillPocSoftware(JsonObject software, const char* os, const char* firmwareVersion);

// Lease (U2/U3): the server answers a denied renewal with 200 + {"granted":false,...}.
enum class LeaseVerdict { Granted, Denied, Unknown };
struct LeaseResult {
  LeaseVerdict verdict = LeaseVerdict::Granted;
  char reasonCode[40] = {};
};
// A body without a boolean `granted` (an older server, empty body) counts as Granted: only an
// explicit false is a denial.
LeaseResult parseLeaseResponse(const char* json);

}  // namespace fry
