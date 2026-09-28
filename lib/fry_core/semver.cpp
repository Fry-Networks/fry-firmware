#include "semver.h"

#include <cstddef>

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

namespace {

// Pre-release text of a version: what follows the first '-' that ends the numeric core, up to any
// '+'. Empty when there is none.
const char* preRelease(const char* v) {
  if (v == nullptr) return "";
  while ((*v >= '0' && *v <= '9') || *v == '.') ++v;
  return *v == '-' ? v + 1 : "";
}

bool endOfPre(char c) { return c == 0 || c == '+'; }
bool endOfIdent(char c) { return endOfPre(c) || c == '.'; }

// Length of the identifier at p and whether it is all digits.
size_t identLen(const char* p, bool* numeric) {
  size_t n = 0;
  *numeric = true;
  while (!endOfIdent(p[n])) {
    if (p[n] < '0' || p[n] > '9') *numeric = false;
    ++n;
  }
  if (n == 0) *numeric = false;
  return n;
}

int compareIdent(const char* a, size_t la, bool na, const char* b, size_t lb, bool nb) {
  if (na && nb) {
    // Equal-length digit strings compare as numbers lexically; skip leading zeros first.
    while (la > 1 && *a == '0') { ++a; --la; }
    while (lb > 1 && *b == '0') { ++b; --lb; }
    if (la != lb) return la < lb ? -1 : 1;
  } else if (na != nb) {
    return na ? -1 : 1;  // numeric identifiers have lower precedence
  }
  const size_t n = la < lb ? la : lb;
  for (size_t i = 0; i < n; ++i) {
    if (a[i] != b[i]) return static_cast<unsigned char>(a[i]) < static_cast<unsigned char>(b[i]) ? -1 : 1;
  }
  if (la != lb) return la < lb ? -1 : 1;
  return 0;
}

}  // namespace

int compareSemverPrecedence(const char* a, const char* b) {
  const int core = compareSemver(a, b);
  if (core != 0) return core;
  const char* pa = preRelease(a);
  const char* pb = preRelease(b);
  const bool ha = !endOfPre(*pa);
  const bool hb = !endOfPre(*pb);
  if (!ha || !hb) return ha == hb ? 0 : (ha ? -1 : 1);  // a release outranks its pre-releases
  for (;;) {
    bool na = false, nb = false;
    const size_t la = identLen(pa, &na);
    const size_t lb = identLen(pb, &nb);
    const int c = compareIdent(pa, la, na, pb, lb, nb);
    if (c != 0) return c;
    pa += la;
    pb += lb;
    const bool moreA = *pa == '.';
    const bool moreB = *pb == '.';
    if (!moreA || !moreB) return moreA == moreB ? 0 : (moreA ? 1 : -1);
    ++pa;
    ++pb;
  }
}

bool isNewerVersionOta(const char* latest, const char* current) {
  return compareSemverPrecedence(latest, current) > 0;
}

}  // namespace fry
