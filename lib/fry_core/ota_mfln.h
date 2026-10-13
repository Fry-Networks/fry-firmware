#pragma once
// ESP8266 OTA over a small-buffer TLS session.
//
// GitHub's asset hosts (objects./release-assets.githubusercontent.com) do not honour TLS MFLN, so
// an OTA from them forces BearSSL's 16384-byte rx buffer and the 36864-byte contiguous heap gate
// (HEAP_GATE_OTA_BLOCK) that a relay board (20-30 KB free) never meets. hardwareapi.frynetworks.com
// does echo max_fragment_length (checked with `openssl s_client -maxfraglen 512`), so an OTA served
// from there runs on 512/512 buffers and needs no contiguous block. Everything here is pure so the
// choice is natively tested; src/esp8266/ota_client_esp8266.cpp only applies it.
#include <cstddef>
#include <cstdint>

namespace fry {

// Hosts known to honour MFLN. Exact, case-insensitive match - a suffix or substring match would let
// "hardwareapi.frynetworks.com.evil.example" pick the small-buffer path.
constexpr const char* kOtaMflnHosts[] = {"hardwareapi.frynetworks.com"};

// Copies the host of "scheme://[user@]host[:port]/..." into out (NUL terminated, lowercased).
// False when there is no host, it does not fit, or the URL carries userinfo.
bool otaUrlHost(const char* url, char* out, size_t cap);

bool otaHostHonoursMfln(const char* host);

struct OtaTlsPlan {
  bool https;         // false: plain http, no TLS buffers at all
  bool mfln;          // host is on kOtaMflnHosts: small-buffer path
  uint16_t rx;        // BearSSL rx buffer (0 when !https)
  uint16_t tx;        // BearSSL tx buffer (0 when !https)
  uint32_t minBlock;  // contiguous block the gate must find (0 on the small path / plain http)
};

// configuredBlock is HEAP_GATE_OTA_BLOCK; it is applied to the non-MFLN https path only.
OtaTlsPlan otaTlsPlan(const char* url, uint32_t configuredBlock);

// Framework Updater::end(false) on a COMPLETE download still falls through to eboot_command_write
// (ACTION_COPY_RAW), i.e. it STAGES the image though our SHA-256 check failed, and the restart that
// follows would copy it. True whenever bytes may be staged and the image must not stay staged:
// anything but a complete download whose SHA-256 matched and whose Update.end(true) succeeded.
bool otaMustClearStaged(uint32_t received, uint32_t len, bool shaOk, bool endOk);

enum class OtaFailKind : uint8_t { ConnectOrHandshake, HttpError, ManifestParse, GateFailed };
enum class OtaFailAction : uint8_t { SkipToNextCheck, RetryNow, Restart };

// Every failure waits for the next scheduled check: no restart, no tight retry loop.
OtaFailAction otaFailureAction(OtaFailKind kind);

}  // namespace fry
