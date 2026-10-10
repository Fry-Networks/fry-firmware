#include "status_snapshot.h"

#include <cstring>

#include "fry_config.h"
#include "hardwareapi_client.h"
#include "key_policy.h"
#include "miner_key.h"
#include "ota_client.h"
#include "provisioning_transport.h"

#ifndef FRY_FIRMWARE_VERSION
#define FRY_FIRMWARE_VERSION "0.0.0-dev"
#endif

namespace fry_status {

void snapshot(fry::DeviceStatus& out) {
  out.state = fry_provisioning::state();
  out.err = fry_provisioning::lastError();
  char key[40] = {0};
  fry_identity::ensureMinerKey(key, sizeof(key));  // the key this boot actually runs on
  out.keySet = key[0] != 0;
  out.keyConfirmed = out.keySet && fry_config::getKeyOk();
  fry::maskMinerKey(key, out.keyMasked, sizeof(out.keyMasked));
  memset(key, 0, sizeof(key));
  out.regHttp = fry_hwapi::lastRegisterHttp();
  out.hbAgeS = fry_ota::heartbeatAgeS();
  out.fw = FRY_FIRMWARE_VERSION;
  out.ota = fry_ota::imageStateName();
  out.apCode = "";
#if defined(ARDUINO_ARCH_ESP8266)
  // Only a keyless board runs the WPA2 setup AP; once a key exists the AP is open again and the
  // code means nothing.
  static char s_code[12];
  if (!out.keySet) {
    String code = fry_config::getApCode();
    strncpy(s_code, code.c_str(), sizeof(s_code) - 1);
    s_code[sizeof(s_code) - 1] = 0;
    out.apCode = s_code;
  }
#endif
}

}  // namespace fry_status
