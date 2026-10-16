#include "wifi_reason.h"

namespace fry {

ProvErr classifyWifiDisconnect(uint8_t reason) {
  return reason == 201 ? ProvErr::BadSsid : ProvErr::WifiAuth;
}

}  // namespace fry
