// Built only by the Pico / BK7231N envs (platformio.boards.ini defines FRY_BOARDS_PORT); the ESP envs compile all of src/.
#if defined(FRY_BOARDS_PORT)
// Trust roots for the mbedtls client of LibreTiny: setCACert with the PEM of the host's trust set. The PEM text lives in flash
// (const), mbedtls parses it per connection.
#include <WiFiClientSecure.h>

#include "../boards/tls_client.h"
#include "../boards/tls_roots.h"

namespace fry_boards {

bool applyTrust(WiFiClientSecure& sec, fry::TrustSet set) {
  switch (set) {
    case fry::TrustSet::Hwapi: sec.setCACert(kRootPemHwapi); return true;
    case fry::TrustSet::GithubCom: sec.setCACert(kRootPemGithubCom); return true;
    case fry::TrustSet::GithubAssets: sec.setCACert(kRootPemGithubAssets); return true;
    default: return false;
  }
}

}  // namespace fry_boards
#endif  // FRY_BOARDS_PORT
