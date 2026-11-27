// Built only by the Pico / BK7231N envs (platformio.boards.ini defines FRY_BOARDS_PORT); the ESP envs compile all of src/.
#if defined(FRY_BOARDS_PORT)
#include "tls_client.h"

#include <time.h>

#include "../core/flash_print.h"
#include "ntp_compat.h"
#include "ntp_kick.h"
#include "tls_trust.h"

namespace fry_boards {

namespace {
bool s_ntpKicked = false;
uint32_t s_ntpKickedMs = 0;
const uint32_t kClockWaitMs = 12000;
}  // namespace

bool hostOfUrl(const char* url, char* out, size_t cap) {
  if (!url || !out || cap == 0) return false;
  const char* start = strstr(url, "://");
  start = start ? start + 3 : url;
  const char* end = strchr(start, '/');
  const size_t n = end ? static_cast<size_t>(end - start) : strlen(start);
  if (n == 0 || n + 1 > cap) {
    out[0] = '\0';
    return false;
  }
  memcpy(out, start, n);
  out[n] = '\0';
  return true;
}

bool ensureClock() {
  if (fry::tlsClockSane(static_cast<int64_t>(time(nullptr)))) return true;
  if (fry::ntpRestartDue(s_ntpKicked, millis(), s_ntpKickedMs)) {
    configTime(0, 0, "pool.ntp.org", "time.nist.gov");
    s_ntpKicked = true;
    s_ntpKickedMs = millis();
  }
  const uint32_t start = millis();
  while (millis() - start < kClockWaitMs) {
    if (fry::tlsClockSane(static_cast<int64_t>(time(nullptr)))) return true;
    delay(100);
  }
  FRY_PRINTLN("tls: clock not set yet - session deferred");
  return false;
}

bool prepareSecure(WiFiClientSecure& sec, const char* url) {
  char host[64];
  if (!hostOfUrl(url, host, sizeof(host))) return false;
  const fry::TrustSet set = fry::trustSetForHost(host);
  if (set == fry::TrustSet::None) {
    FRY_PRINTF("tls: refused, no trust anchors for host %s\n", host);
    return false;
  }
  if (!ensureClock()) return false;
  return applyTrust(sec, set);
}

}  // namespace fry_boards
#endif  // FRY_BOARDS_PORT
