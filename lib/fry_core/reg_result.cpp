#include "reg_result.h"

#include <cstring>

namespace fry {

namespace {

const uint32_t kFirstBackoffMs = 60000UL;
const uint32_t kMaxBackoffMs = 3600000UL;
const size_t kMaxDetail = 120;

bool isAlnum(char c) {
  return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

size_t alnumRun(const char* p) {
  size_t n = 0;
  while (isAlnum(p[n])) n++;
  return n;
}

}  // namespace

RegClass classifyRegistration(int http) {
  if (http >= 200 && http < 300) return RegClass::Ok;
  if (http == 401) return RegClass::Unauthorized;
  if (http == 403) return RegClass::Forbidden;
  if (http == 409) return RegClass::Conflict;
  if (http == 429) return RegClass::Unreachable;
  if (http >= 400 && http < 500) return RegClass::OtherClientError;
  return RegClass::Unreachable;
}

ProvErr regClassProvErr(RegClass c) {
  switch (c) {
    case RegClass::Ok:
      return ProvErr::None;
    case RegClass::Unauthorized:
      return ProvErr::Reg401;
    case RegClass::Forbidden:
      return ProvErr::Reg403;
    case RegClass::Conflict:
      return ProvErr::Reg409;
    case RegClass::OtherClientError:
      return ProvErr::RegOther4xx;
    case RegClass::Unreachable:
      return ProvErr::Unreachable;
  }
  return ProvErr::Unreachable;
}

bool regClassRetryQuickly(RegClass c) { return c == RegClass::Unreachable; }

uint32_t nextRegisterDelayMs(RegClass c, uint32_t consecutiveFailures) {
  if (c != RegClass::Unreachable) return kMaxBackoffMs;
  const uint32_t n = consecutiveFailures == 0 ? 1 : consecutiveFailures;
  if (n > 7) return kMaxBackoffMs;  // 60 s << 6 already passes the cap; never shift further
  const uint32_t d = kFirstBackoffMs << (n - 1);
  return d > kMaxBackoffMs ? kMaxBackoffMs : d;
}

const char* regClassText(RegClass c) {
  switch (c) {
    case RegClass::Ok:
      return "registered";
    case RegClass::Unauthorized:
      return "key not accepted (unknown key, or a legacy IOT- key)";
    case RegClass::Forbidden:
      return "registration forbidden for this key";
    case RegClass::Conflict:
      return "key is active on another install";
    case RegClass::OtherClientError:
      return "registration refused by the server";
    case RegClass::Unreachable:
      return "hardwareapi unreachable (network, 5xx or rate limit) - will retry";
  }
  return "unknown";
}

size_t sanitizeServerDetail(const char* in, const char* minerKey, char* out, size_t outCap) {
  if (!out || outCap == 0) return 0;
  out[0] = 0;
  if (!in) return 0;
  const size_t cap = (outCap - 1) < kMaxDetail ? (outCap - 1) : kMaxDetail;
  const size_t keyLen = minerKey ? strlen(minerKey) : 0;
  size_t n = 0;

  for (size_t i = 0; in[i] && n < cap;) {
    const bool prefixed = strncmp(in + i, "FEM-", 4) == 0 || strncmp(in + i, "IOT-", 4) == 0;
    size_t tokenLen = 0;
    if (keyLen >= 8 && strncmp(in + i, minerKey, keyLen) == 0) {
      tokenLen = keyLen;
    } else if (prefixed && alnumRun(in + i + 4) >= 8) {
      tokenLen = 4 + alnumRun(in + i + 4);
    }
    if (tokenLen) {
      // prefix + 2 characters + "...", or as much of it as still fits
      const char* src = in + i;
      const size_t keep = tokenLen >= 6 ? 6 : tokenLen;
      for (size_t k = 0; k < keep && n < cap; k++) out[n++] = src[k];
      for (int k = 0; k < 3 && n < cap; k++) out[n++] = '.';
      i += tokenLen;
      continue;
    }
    const unsigned char c = static_cast<unsigned char>(in[i]);
    char o;
    if (c == '"') {
      o = '\'';
    } else if (c == '\\') {
      o = '/';
    } else if (c < 0x20 || c > 0x7E) {
      o = '?';
    } else {
      o = static_cast<char>(c);
    }
    out[n++] = o;
    i++;
  }
  out[n] = 0;
  return n;
}

}  // namespace fry
