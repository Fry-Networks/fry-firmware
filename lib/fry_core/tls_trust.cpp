#include "tls_trust.h"

#include <cstring>

namespace fry {

namespace {

// Kept in the header's declared order, and each TlsRoot appears at least once: an anchor that no
// host needs is heap spent for nothing on this chip (test_tls_trust pins that).
const TlsHostRoot kHostRoots[] = {
    {"hardwareapi.frynetworks.com", TlsRoot::IsrgX2},
    {"fry.farm", TlsRoot::IsrgX2},
    {"dashboard.frynetworks.com", TlsRoot::IsrgX2},
    {"github.com", TlsRoot::SectigoE46},
    {"release-assets.githubusercontent.com", TlsRoot::IsrgX1},
    {"objects.githubusercontent.com", TlsRoot::IsrgX1},
};

}  // namespace

bool tlsClockUsable(uint32_t epochSeconds) { return epochSeconds >= kTlsMinPlausibleEpoch; }

const TlsHostRoot* tlsHostRootTable(size_t* count) {
  if (count) *count = sizeof(kHostRoots) / sizeof(kHostRoots[0]);
  return kHostRoots;
}

bool tlsRootForHost(const char* host, TlsRoot* root) {
  if (!host || !host[0]) return false;
  for (size_t i = 0; i < sizeof(kHostRoots) / sizeof(kHostRoots[0]); i++) {
    if (strcmp(kHostRoots[i].host, host) == 0) {
      if (root) *root = kHostRoots[i].root;
      return true;
    }
  }
  return false;
}

}  // namespace fry
