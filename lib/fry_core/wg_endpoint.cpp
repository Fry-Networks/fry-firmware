#include "wg_endpoint.h"

#include <cstring>

namespace fry {

WgEndpoint parseWgEndpoint(const char* in) {
  WgEndpoint r;
  if (in == nullptr) return r;
  const size_t n = std::strlen(in);
  if (n == 0) return r;

  const char* hostBegin = in;
  size_t hostLen = n;
  const char* portBegin = nullptr;

  if (in[0] == '[') {
    // Bracketed IPv6: the brackets exist precisely so the port is unambiguous.
    const char* close = std::strchr(in, ']');
    if (close == nullptr) return r;
    hostBegin = in + 1;
    hostLen = static_cast<size_t>(close - hostBegin);
    if (hostLen == 0) return r;
    const char after = *(close + 1);
    if (after == ':') {
      portBegin = close + 2;
    } else if (after != 0) {
      return r;  // trailing junk after the closing bracket
    }
  } else {
    const char* firstColon = std::strchr(in, ':');
    const char* lastColon = std::strrchr(in, ':');
    if (firstColon != nullptr && firstColon == lastColon) {
      hostLen = static_cast<size_t>(lastColon - in);
      if (hostLen == 0) return r;  // ":51820" carries no host
      portBegin = lastColon + 1;
    }
    // Two or more colons with no brackets is a bare IPv6 literal. A port cannot be
    // separated from the address, so the literal is kept whole rather than guessed at.
  }

  if (hostLen >= kWgHostCap) return r;

  if (portBegin != nullptr) {
    uint32_t port = 0;
    if (*portBegin == 0) return r;
    for (const char* c = portBegin; *c != 0; ++c) {
      if (*c < '0' || *c > '9') return r;
      port = port * 10u + static_cast<uint32_t>(*c - '0');
      if (port > 65535u) return r;
    }
    if (port == 0) return r;
    r.port = static_cast<uint16_t>(port);
    r.hasPort = true;
  }

  std::memcpy(r.host, hostBegin, hostLen);
  r.ok = true;
  return r;
}

}  // namespace fry
