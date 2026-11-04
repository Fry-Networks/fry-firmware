#include "tls_trust.h"

#include <cstring>

namespace fry {

namespace {

char lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c; }

bool equalsLower(const char* host, size_t len, const char* lit) {
  const size_t n = std::strlen(lit);
  if (len != n) return false;
  for (size_t i = 0; i < n; i++) {
    if (lower(host[i]) != lit[i]) return false;
  }
  return true;
}

// True when host (len chars) ends with the literal suffix, which starts with a dot, and has a non-empty label before it.
bool endsWithLower(const char* host, size_t len, const char* suffix) {
  const size_t n = std::strlen(suffix);
  if (len <= n) return false;
  return equalsLower(host + (len - n), n, suffix);
}

// A DNS name: lowercase letters, digits, '-' and '.', no empty label (no leading, trailing or doubled dot).
bool plainDnsName(const char* host, size_t len) {
  if (len == 0 || host[0] == '.' || host[len - 1] == '.') return false;
  for (size_t i = 0; i < len; i++) {
    const char c = lower(host[i]);
    const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.';
    if (!ok || (c == '.' && i > 0 && host[i - 1] == '.')) return false;
  }
  return true;
}

}  // namespace

TrustSet trustSetForHost(const char* host) {
  if (!host || !*host) return TrustSet::None;
  size_t len = std::strlen(host);
  const char* colon = std::strchr(host, ':');
  if (colon) {
    if (colon[1] == 0) return TrustSet::None;
    for (const char* p = colon + 1; *p; p++) {
      if (*p < '0' || *p > '9') return TrustSet::None;
    }
    len = static_cast<size_t>(colon - host);
  }
  if (!plainDnsName(host, len)) return TrustSet::None;
  // The second API host serves the same chain as the first (exact match only, no subdomains).
  if (equalsLower(host, len, "hardwareapi.frynetworks.com") || equalsLower(host, len, "fry.farm")) return TrustSet::Hwapi;
  if (equalsLower(host, len, "github.com")) return TrustSet::GithubCom;
  if (endsWithLower(host, len, ".githubusercontent.com")) return TrustSet::GithubAssets;
  return TrustSet::None;
}

bool tlsClockSane(int64_t now) { return now >= kMinSaneEpoch; }

const char* trustSetName(TrustSet set) {
  switch (set) {
    case TrustSet::Hwapi: return "HWAPI";
    case TrustSet::GithubCom: return "GITHUB_COM";
    case TrustSet::GithubAssets: return "GITHUB_ASSETS";
    default: return "NONE";
  }
}

uint8_t trustSetCount(TrustSet set) {
  switch (set) {
    case TrustSet::Hwapi: return 1;
    case TrustSet::GithubCom: return 1;
    case TrustSet::GithubAssets: return 1;
    default: return 0;
  }
}

}  // namespace fry
