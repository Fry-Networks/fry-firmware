#include "ota_mfln.h"

#include <cstring>

namespace fry {

namespace {

char lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

bool ieq(const char* a, const char* b) {
  for (; *a && *b; ++a, ++b)
    if (lower(*a) != lower(*b)) return false;
  return *a == *b;
}

bool startsWithHttps(const char* url) {
  return url && strncmp(url, "https://", 8) == 0;
}

}  // namespace

bool otaUrlHost(const char* url, char* out, size_t cap) {
  if (!url || !out || cap == 0) return false;
  const char* sep = strstr(url, "://");
  if (!sep) return false;
  const char* p = sep + 3;
  size_t n = 0;
  while (p[n] && p[n] != '/' && p[n] != ':' && p[n] != '?' && p[n] != '#') {
    if (p[n] == '@') return false;  // userinfo: the real host is ambiguous, refuse
    ++n;
  }
  // A ':' may be a port or the start of userinfo ("user:pw@host"); only a port may follow it.
  if (p[n] == ':') {
    const char* q = p + n + 1;
    while (*q && *q != '/' && *q != '?' && *q != '#') {
      if (*q < '0' || *q > '9') return false;
      ++q;
    }
  }
  if (n == 0 || n >= cap) return false;
  for (size_t i = 0; i < n; ++i) out[i] = lower(p[i]);
  out[n] = '\0';
  return true;
}

bool otaHostHonoursMfln(const char* host) {
  if (!host || !*host) return false;
  for (const char* h : kOtaMflnHosts)
    if (ieq(host, h)) return true;
  return false;
}

OtaTlsPlan otaTlsPlan(const char* url, uint32_t configuredBlock) {
  OtaTlsPlan p{};
  if (!startsWithHttps(url)) return p;  // plain http: no TLS buffers, no block requirement
  p.https = true;
  char host[96];
  if (otaUrlHost(url, host, sizeof(host)) && otaHostHonoursMfln(host)) {
    p.mfln = true;
    p.rx = 512;
    p.tx = 512;
    p.minBlock = 0;
  } else {
    p.rx = 16384;
    p.tx = 512;
    p.minBlock = configuredBlock;
  }
  return p;
}

bool otaFollowRedirects(const OtaTlsPlan& plan) { return !plan.mfln; }
bool otaIsRedirectCode(int httpCode) { return httpCode >= 300 && httpCode < 400; }

bool otaMustClearStaged(uint32_t received, uint32_t len, bool shaOk, bool endOk) {
  return !(received == len && shaOk && endOk);
}

OtaFailAction otaFailureAction(OtaFailKind) { return OtaFailAction::SkipToNextCheck; }

}  // namespace fry
