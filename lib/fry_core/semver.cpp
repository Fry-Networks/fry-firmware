#include "semver.h"

namespace fry {
namespace {

// Reads the next numeric component, then advances p past a single separating dot. Anything
// else (end of string, or a pre-release/build suffix such as -rc1) ends the version, so the
// remaining components read as 0.
uint32_t nextComponent(const char*& p) {
  if (p == nullptr || *p == 0) return 0;
  uint32_t v = 0;
  while (*p >= '0' && *p <= '9') {
    v = v * 10u + static_cast<uint32_t>(*p - '0');
    ++p;
  }
  if (*p == '.') {
    ++p;
  } else {
    p = "";
  }
  return v;
}

}  // namespace

int compareSemver(const char* a, const char* b) {
  const char* pa = (a == nullptr) ? "" : a;
  const char* pb = (b == nullptr) ? "" : b;
  for (int i = 0; i < 3; ++i) {
    const uint32_t ca = nextComponent(pa);
    const uint32_t cb = nextComponent(pb);
    if (ca < cb) return -1;
    if (ca > cb) return 1;
  }
  return 0;
}

bool isNewerVersion(const char* latest, const char* current) {
  return compareSemver(latest, current) > 0;
}

}  // namespace fry
