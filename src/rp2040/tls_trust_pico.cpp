// Built only by the Pico / BK7231N envs (platformio.boards.ini defines FRY_BOARDS_PORT); the ESP envs compile all of src/.
#if defined(FRY_BOARDS_PORT)
// Trust roots for the BearSSL client of arduino-pico: one X509List per trust set, parsed from the generated PEM on first use and
// kept (a WiFiClientSecure holds a raw pointer to the list it was given).
#include <WiFiClientSecure.h>
#include <time.h>

#include "../boards/tls_client.h"
#include "../boards/tls_roots.h"

namespace fry_boards {

bool applyTrust(WiFiClientSecure& sec, fry::TrustSet set) {
  static BearSSL::X509List* lists[4] = {nullptr, nullptr, nullptr, nullptr};
  const char* pem = nullptr;
  switch (set) {
    case fry::TrustSet::Hwapi: pem = kRootPemHwapi; break;
    case fry::TrustSet::GithubCom: pem = kRootPemGithubCom; break;
    case fry::TrustSet::GithubAssets: pem = kRootPemGithubAssets; break;
    default: return false;
  }
  const unsigned idx = static_cast<unsigned>(set);
  if (!lists[idx]) lists[idx] = new BearSSL::X509List(pem);
  if (!lists[idx] || lists[idx]->getCount() == 0) return false;
  sec.setTrustAnchors(lists[idx]);
  sec.setX509Time(time(nullptr));
  return true;
}

}  // namespace fry_boards
#endif  // FRY_BOARDS_PORT
