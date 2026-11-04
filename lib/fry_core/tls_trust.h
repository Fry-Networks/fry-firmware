#pragma once
// Which X.509 root the ESP8266 loads for a host, and when its clock may validate a certificate.
// Pure C++ so `pio test -e native` pins the rules; the BearSSL calls live in src/esp8266/http_tls.cpp.
//
// Anchors are the roots the live chains end at, never a leaf or an intermediate. The Sectigo E46 anchor is the self-signed root.
// The ISRG YE and YR certificates shipped in data/cert are the cross-signed forms of those roots: a trust anchor is only a
// subject name and a public key, and the cross-signed form carries the same name and key as the self-signed root, so it
// anchors exactly the same chains. Validation ends at the intermediate whose issuer name and key match the anchor, so the
// cross-signed roots some servers append are not needed. One root per set, because every root kept resident costs heap this chip does not have:
//   Hwapi         the two API hosts (exact names)            -> ISRG Root YE
//   GithubCom     github.com                                  -> Sectigo Public Server Authentication Root E46
//   GithubAssets  *.githubusercontent.com (release assets,    -> ISRG Root YR
//                 objects and raw hosts)
// A release download crosses from the first to the second host, so the set is chosen per hop and the client's anchors are
// replaced between hops (src/core/ota_client.cpp). Any other host has no set: the call is refused (fail closed), and there
// is no insecure fallback.
#include <cstdint>

namespace fry {

enum class TrustSet : uint8_t { None = 0, Hwapi = 1, GithubCom = 2, GithubAssets = 3 };

// 2026-01-01T00:00:00Z. A clock below this has not been set by SNTP (the chip boots at 1970).
constexpr int64_t kMinSaneEpoch = 1767225600;

// `host` is "name" or "name:port" as http_tls.cpp extracts it; case-insensitive. Suffixes match on a dot boundary.
TrustSet trustSetForHost(const char* host);
bool tlsClockSane(int64_t now);
const char* trustSetName(TrustSet set);
uint8_t trustSetCount(TrustSet set);  // roots in the set

}  // namespace fry
