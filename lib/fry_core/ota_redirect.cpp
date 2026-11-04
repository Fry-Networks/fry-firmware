#include "ota_redirect.h"

#include <cstring>

#include "tls_trust.h"

namespace fry {

namespace {

char lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c; }

bool startsWithLower(const char* s, const char* prefix) {
  for (; *prefix; s++, prefix++) {
    if (!*s || lower(*s) != *prefix) return false;
  }
  return true;
}

}  // namespace

bool isRedirectStatus(int code) { return code == 301 || code == 302 || code == 303 || code == 307 || code == 308; }

RedirectDecision decideRedirect(int code, uint8_t hopsTaken, const char* location) {
  if (!isRedirectStatus(code)) return RedirectDecision::NotRedirect;
  if (hopsTaken >= kMaxRedirectHops) return RedirectDecision::TooMany;
  if (!location || !*location) return RedirectDecision::NoLocation;
  if (!startsWithLower(location, "https://")) return RedirectDecision::NotHttps;
  const char* host = location + 8;
  const char* end = host;
  while (*end && *end != '/') end++;
  // the host part ("name" or "name:port") is copied out for the lookup; a longer one cannot be a name with a set
  char name[80];
  const size_t n = static_cast<size_t>(end - host);
  if (n == 0 || n >= sizeof(name)) return RedirectDecision::UnknownHost;
  std::memcpy(name, host, n);
  name[n] = 0;
  return trustSetForHost(name) == TrustSet::None ? RedirectDecision::UnknownHost : RedirectDecision::Follow;
}

}  // namespace fry
