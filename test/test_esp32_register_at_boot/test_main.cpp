// ESP32-family boot registration is recorded on success so tick() does not register a second time
// on the first Ready loop pass, while failures still leave s_lastRegisterAttemptMs == 0 for an
// immediate retry on tick().
//
// Tests both the production pure C++ scheduling helpers (lib/fry_core/reg_result.h) and the
// src/core/hardwareapi_client.cpp wiring that feeds them. Synthetic test values only.
#include <unity.h>

#include <ArduinoJson.h>

#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "heartbeat_fields.h"
#include "reg_result.h"
#include "stale_token_heal.h"

namespace {

const unsigned long kHeartbeatMs = 3600000UL;  // INSTALL_HEARTBEAT_MS

bool readFile(const std::string& path, std::string& out) {
  std::ifstream f(path.c_str(), std::ios::in | std::ios::binary);
  if (!f) return false;
  std::ostringstream ss;
  ss << f.rdbuf();
  out = ss.str();
  return !out.empty();
}

bool loadSource(const std::string& rel, std::string& out) {
  const std::string self = __FILE__;
  const std::string tail = "test/test_esp32_register_at_boot/test_main.cpp";
  std::vector<std::string> prefixes;
  if (self.size() >= tail.size() && self.compare(self.size() - tail.size(), tail.size(), tail) == 0) {
    prefixes.push_back(self.substr(0, self.size() - tail.size()));
  }
  const char* ups[] = {"", "../", "../../", "../../../", "../../../../"};
  for (size_t i = 0; i < sizeof(ups) / sizeof(ups[0]); i++) prefixes.push_back(ups[i]);
  for (size_t i = 0; i < prefixes.size(); i++) {
    if (readFile(prefixes[i] + rel, out)) return true;
  }
  return false;
}

int countOf(const std::string& hay, const std::string& needle) {
  int n = 0;
  for (size_t pos = hay.find(needle); pos != std::string::npos; pos = hay.find(needle, pos + needle.size())) n++;
  return n;
}

bool between(const std::string& src, const std::string& from, const std::string& to, std::string& out) {
  const size_t a = src.find(from);
  if (a == std::string::npos) return false;
  const size_t b = src.find(to, a + from.size());
  if (b == std::string::npos) return false;
  out = src.substr(a, b - a);
  return true;
}

// ---- Source wiring pins -------------------------------------------------------------------------

void test_esp32_registerInstallation_records_boot_success_on_both_ok_and_heal_paths() {
  std::string src, fn;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/core/hardwareapi_client.cpp", src),
                           "cannot read src/core/hardwareapi_client.cpp");
  TEST_ASSERT_TRUE_MESSAGE(between(src, "bool registerInstallation() {", "int lastRegisterHttp()", fn),
                           "cannot find registerInstallation()");

  // 1. Capture `started = millis()` at entry on the non-ESP8266 (#else) side before `char minerKey[40];`.
  const size_t startedAt = fn.find("const unsigned long started = millis();");
  TEST_ASSERT_TRUE_MESSAGE(startedAt != std::string::npos,
                           "registerInstallation() captures started = millis() on the ESP32 side");
  const size_t minerKeyAt = fn.find("char minerKey[40];");
  TEST_ASSERT_TRUE(minerKeyAt != std::string::npos && startedAt < minerKeyAt);

  // 2. Normal 2xx path records attempt timestamp and s_registered inside #if !defined(ARDUINO_ARCH_ESP8266),
  //    after persisting device_token and setting s_nextRegisterDelayMs.
  std::string okBranch;
  TEST_ASSERT_TRUE(between(fn, "if (cls == fry::RegClass::Ok) {", "if (!fry::regClassRetryQuickly(cls)) {", okBranch));
  const size_t okTok = okBranch.find("fry_config::setDeviceToken(token);");
  const size_t okDelay = okBranch.find("s_nextRegisterDelayMs = INSTALL_HEARTBEAT_MS;");
  const size_t okStamp = okBranch.find("s_lastRegisterAttemptMs = fry::nonZeroAttemptStamp(started);");
  const size_t okReg = okBranch.find("s_registered = true;");
  TEST_ASSERT_TRUE_MESSAGE(okStamp != std::string::npos && okReg != std::string::npos,
                           "RegClass::Ok branch records s_lastRegisterAttemptMs and s_registered on ESP32");
  TEST_ASSERT_TRUE(okTok != std::string::npos && okDelay != std::string::npos);
  TEST_ASSERT_TRUE(okTok < okDelay && okDelay < okStamp && okStamp < okReg);
  const size_t okGuard = okBranch.rfind("#if !defined(ARDUINO_ARCH_ESP8266)", okStamp);
  const size_t okEnd = okBranch.find("#endif", okReg);
  TEST_ASSERT_TRUE_MESSAGE(okGuard != std::string::npos && okEnd != std::string::npos && okGuard < okStamp,
                           "Ok boot-attempt recording is guarded with #if !defined(ARDUINO_ARCH_ESP8266)");

  // 3. Stale-token heal success path also records attempt timestamp and s_registered on ESP32.
  std::string healBranch;
  TEST_ASSERT_TRUE(between(fn, "if (healStaleTokenIfDue(", "break;", healBranch));
  const size_t healDelay = healBranch.find("s_nextRegisterDelayMs = INSTALL_HEARTBEAT_MS;");
  const size_t healStamp = healBranch.find("s_lastRegisterAttemptMs = fry::nonZeroAttemptStamp(started);");
  const size_t healReg = healBranch.find("s_registered = true;");
  TEST_ASSERT_TRUE_MESSAGE(healStamp != std::string::npos && healReg != std::string::npos,
                           "healStaleTokenIfDue success branch records s_lastRegisterAttemptMs and s_registered on ESP32");
  TEST_ASSERT_TRUE(healDelay != std::string::npos && healDelay < healStamp && healStamp < healReg);
  const size_t healGuard = healBranch.rfind("#if !defined(ARDUINO_ARCH_ESP8266)", healStamp);
  const size_t healEnd = healBranch.find("#endif", healReg);
  TEST_ASSERT_TRUE_MESSAGE(healGuard != std::string::npos && healEnd != std::string::npos && healGuard < healStamp,
                           "heal boot-attempt recording is guarded with #if !defined(ARDUINO_ARCH_ESP8266)");

  // 4. Failure path at end of registerInstallation() must NOT touch s_lastRegisterAttemptMs or s_registered.
  std::string failTail;
  TEST_ASSERT_TRUE(between(fn, "if (s_regFailures < 0xFFFFFFFFu) s_regFailures++;", "return false;\n}", failTail));
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(failTail, "s_lastRegisterAttemptMs"),
                                "failed registration must leave s_lastRegisterAttemptMs untouched");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, countOf(failTail, "s_registered"),
                                "failed registration must leave s_registered untouched");
}

void test_version_0_4_30_and_tunnel_prerequisite_wiring() {
  std::string ini, wg, hw;
  TEST_ASSERT_TRUE(loadSource("platformio.ini", ini));
  const std::string verKey = "-DFRY_FIRMWARE_VERSION='\"";
  const size_t verAt = ini.find(verKey);
  const size_t verEnd = (verAt == std::string::npos) ? std::string::npos : ini.find('"', verAt + verKey.size());
  const std::string iniVer = (verEnd == std::string::npos)
                                 ? std::string()
                                 : ini.substr(verAt + verKey.size(), verEnd - (verAt + verKey.size()));
  TEST_ASSERT_TRUE_MESSAGE(!iniVer.empty() && iniVer.find('.') != std::string::npos &&
                               ini.find(verKey + iniVer + "\"'") != std::string::npos,
                           "platformio.ini must declare a valid FRY_FIRMWARE_VERSION");
  TEST_ASSERT_TRUE(loadSource("src/esp32/wg_provision_client.cpp", wg));
  TEST_ASSERT_TRUE_MESSAGE(wg.find("fry_config::getDeviceToken()") != std::string::npos,
                           "WG provisioning depends on fry_config::getDeviceToken()");
  TEST_ASSERT_TRUE(loadSource("src/core/hardwareapi_client.cpp", hw));
  TEST_ASSERT_TRUE_MESSAGE(hw.find("fry_config::setDeviceToken(token)") != std::string::npos,
                           "registerInstallation persists device_token on 2xx");
  TEST_ASSERT_TRUE_MESSAGE(hw.find("if (token.length() > 0) fry_config::setDeviceToken(token.c_str());") !=
                               std::string::npos,
                           "healStaleTokenIfDue persists fresh device_token on 2xx");
}

// ---- Behavioral state-machine tests -------------------------------------------------------------

#if defined(FRY_REG_BOOT_HELPERS)

struct Esp32RegSim {
  // RAM state reset on every boot / OTA reboot
  unsigned long lastRegisterAttemptMs = 0;
  unsigned long nextRegisterDelayMs = kHeartbeatMs;
  uint32_t regFailures = 0;
  bool registered = false;

  // Simulated NVS / clock / server
  unsigned long nowMs = 4000;
  std::string softwareVersion = "0.4.30";
  std::string minerKey = "FEM-TEST-0001";
  std::string installId = "0123456789abcdef0123456789abcdef";
  std::string deviceToken;
  bool customApiBase = false;
  int nextHttp = 200;
  std::string nextToken = "tok-boot-1";
  int healHttp = 200;
  std::string healToken = "tok-heal-1";

  // Recorded outbound registrations
  std::vector<std::string> sentBodies;
  int healAttempts = 0;

  bool registerInstallation() {
    const unsigned long started = nowMs;
    if (minerKey.empty()) return false;

    fry::InstallationFields fields{};
    fields.minerKey = minerKey.c_str();
    fields.installId = installId.c_str();
    fields.minerCode = "IOTVPN";
    fields.softwareVersion = softwareVersion.c_str();
    fields.pocVersion = "1.0.0";
    fields.hostname = "fry-test";
    fields.os = "esp32s3";
    fields.deviceName = "fry-test";
    fields.flash = {4194304, 4194304, 1500000, 900000};
    JsonDocument doc;
    fry::buildInstallationDoc(doc, fields);
    std::string body;
    serializeJson(doc, body);
    sentBodies.push_back(body);

    const bool deviceTokenSent = !deviceToken.empty();
    const int code = nextHttp;
    const fry::RegClass cls = fry::classifyRegistration(code);
    if (cls == fry::RegClass::Ok) {
      if (!nextToken.empty()) deviceToken = nextToken;
      regFailures = 0;
      nextRegisterDelayMs = kHeartbeatMs;
      lastRegisterAttemptMs = fry::nonZeroAttemptStamp(started);
      registered = true;
      return true;
    }
    if (!fry::regClassRetryQuickly(cls)) {
      if (customApiBase && fry::isStaleTokenSignature(code, deviceTokenSent)) {
        healAttempts++;
        if (healHttp >= 200 && healHttp < 300 && !healToken.empty()) {
          deviceToken = healToken;
          regFailures = 0;
          nextRegisterDelayMs = kHeartbeatMs;
          lastRegisterAttemptMs = fry::nonZeroAttemptStamp(started);
          registered = true;
          return true;
        }
      }
    }
    if (regFailures < 0xFFFFFFFFu) regFailures++;
    nextRegisterDelayMs = fry::nextRegisterDelayMs(cls, regFailures);
    return false;
  }

  void fry_trigger_register_now() { registerInstallation(); }

  void tick() {
    if (fry::registerAttemptDue(nowMs, lastRegisterAttemptMs, nextRegisterDelayMs)) {
      lastRegisterAttemptMs = nowMs;
      if (registerInstallation()) {
        registered = true;
      }
    }
  }

  bool tunnelEnrolHasToken() const { return !deviceToken.empty() && !minerKey.empty(); }
};

void test_case1_boot_success_suppresses_duplicate_on_tick_within_heartbeat() {
  Esp32RegSim sim;
  sim.nowMs = 4200;
  sim.fry_trigger_register_now();
  TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)sim.sentBodies.size());
  TEST_ASSERT_EQUAL_UINT32(4200, (uint32_t)sim.lastRegisterAttemptMs);
  TEST_ASSERT_TRUE(sim.registered);
  TEST_ASSERT_TRUE(sim.tunnelEnrolHasToken());

  // First Ready loop tick() and repeated ticks up to 1 ms before INSTALL_HEARTBEAT_MS: NO duplicate.
  sim.nowMs = 4205;
  sim.tick();
  sim.nowMs = 15000;
  sim.tick();
  sim.nowMs = 4200UL + kHeartbeatMs - 1UL;
  sim.tick();
  TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)sim.sentBodies.size());

  // At INSTALL_HEARTBEAT_MS, the scheduled hourly heartbeat fires (token refresh still works).
  sim.nowMs = 4200UL + kHeartbeatMs;
  sim.nextToken = "tok-refreshed-1h";
  sim.tick();
  TEST_ASSERT_EQUAL_UINT32(2, (uint32_t)sim.sentBodies.size());
  TEST_ASSERT_EQUAL_STRING("tok-refreshed-1h", sim.deviceToken.c_str());

  // Zero-timestamp edge case and 32-bit wrap safety.
  TEST_ASSERT_EQUAL_UINT32(1UL, (uint32_t)fry::nonZeroAttemptStamp(0));
  TEST_ASSERT_FALSE(fry::registerAttemptDue(0x00000100UL, 0xFFFFFF00UL, kHeartbeatMs));
}

void test_case2_boot_failure_retries_immediately_on_next_tick() {
  // 503 outage at boot -> next tick() retries immediately without waiting 1 hour.
  {
    Esp32RegSim sim;
    sim.nowMs = 4000;
    sim.nextHttp = 503;
    sim.nextToken.clear();
    sim.fry_trigger_register_now();
    TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)sim.sentBodies.size());
    TEST_ASSERT_EQUAL_UINT32(0, (uint32_t)sim.lastRegisterAttemptMs);
    TEST_ASSERT_FALSE(sim.registered);
    TEST_ASSERT_FALSE(sim.tunnelEnrolHasToken());

    // Server recovers by first tick(): immediate retry succeeds and satisfies tunnel prerequisite.
    sim.nowMs = 4050;
    sim.nextHttp = 200;
    sim.nextToken = "tok-recovered";
    sim.tick();
    TEST_ASSERT_EQUAL_UINT32(2, (uint32_t)sim.sentBodies.size());
    TEST_ASSERT_TRUE(sim.registered);
    TEST_ASSERT_TRUE(sim.tunnelEnrolHasToken());

    // Subsequent tick within heartbeat window does not duplicate.
    sim.nowMs = 5000;
    sim.tick();
    TEST_ASSERT_EQUAL_UINT32(2, (uint32_t)sim.sentBodies.size());
  }

  // Persistent 401 failure at boot -> tick() retries once immediately, then backs off cleanly.
  {
    Esp32RegSim sim;
    sim.nowMs = 4000;
    sim.nextHttp = 401;
    sim.nextToken.clear();
    sim.fry_trigger_register_now();
    TEST_ASSERT_EQUAL_UINT32(0, (uint32_t)sim.lastRegisterAttemptMs);

    sim.nowMs = 4050;
    sim.tick();
    TEST_ASSERT_EQUAL_UINT32(2, (uint32_t)sim.sentBodies.size());
    TEST_ASSERT_EQUAL_UINT32(4050, (uint32_t)sim.lastRegisterAttemptMs);
    TEST_ASSERT_FALSE(sim.registered);

    sim.nowMs = 10000;
    sim.tick();
    TEST_ASSERT_EQUAL_UINT32(2, (uint32_t)sim.sentBodies.size());
  }
}

void test_case3_ota_reboot_on_0_4_30_sends_exactly_one_registration_with_new_version() {
  // Pre-OTA boot on 0.4.29 already registered an hour ago.
  Esp32RegSim preOta;
  preOta.softwareVersion = "0.4.29";
  preOta.nowMs = 3500;
  preOta.fry_trigger_register_now();
  TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)preOta.sentBodies.size());

  // OTA reboot resets RAM state (lastRegisterAttemptMs=0, registered=false) while preserving NVS identity.
  Esp32RegSim postOta;
  postOta.softwareVersion = "0.4.30";
  postOta.deviceToken = preOta.deviceToken;
  postOta.nowMs = 3800;

  postOta.fry_trigger_register_now();
  postOta.nowMs = 3900;
  postOta.tick();
  postOta.nowMs = 60000;
  postOta.tick();

  TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)postOta.sentBodies.size());
  JsonDocument parsed;
  TEST_ASSERT_FALSE(deserializeJson(parsed, postOta.sentBodies[0]));
  TEST_ASSERT_EQUAL_STRING("0.4.30", parsed["software_version_installed"] | "");
}

void test_stale_token_heal_is_not_suppressed_and_records_boot_attempt_once() {
  Esp32RegSim sim;
  sim.customApiBase = true;
  sim.deviceToken = "tok-stale";
  sim.nextHttp = 404;
  sim.healHttp = 200;
  sim.healToken = "tok-fresh";
  sim.nowMs = 4500;

  sim.fry_trigger_register_now();
  TEST_ASSERT_EQUAL_INT(1, sim.healAttempts);
  TEST_ASSERT_EQUAL_STRING("tok-fresh", sim.deviceToken.c_str());
  TEST_ASSERT_EQUAL_UINT32(4500, (uint32_t)sim.lastRegisterAttemptMs);
  TEST_ASSERT_TRUE(sim.registered);

  // Subsequent tick() inside heartbeat window does not duplicate.
  sim.nowMs = 4600;
  sim.tick();
  TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)sim.sentBodies.size());

  // If the heal itself fails, lastRegisterAttemptMs stays 0 so tick() retries immediately.
  Esp32RegSim failHeal;
  failHeal.customApiBase = true;
  failHeal.deviceToken = "tok-stale";
  failHeal.nextHttp = 404;
  failHeal.healHttp = 500;
  failHeal.nowMs = 4500;
  failHeal.fry_trigger_register_now();
  TEST_ASSERT_EQUAL_INT(1, failHeal.healAttempts);
  TEST_ASSERT_EQUAL_UINT32(0, (uint32_t)failHeal.lastRegisterAttemptMs);
  failHeal.nowMs = 4550;
  failHeal.nextHttp = 200;
  failHeal.nextToken = "tok-recovered";
  failHeal.tick();
  TEST_ASSERT_EQUAL_UINT32(2, (uint32_t)failHeal.sentBodies.size());
  TEST_ASSERT_TRUE(failHeal.registered);
}

#else

#define FRY_RED_ON_MAIN(name) \
  void name() { TEST_FAIL_MESSAGE("lib/fry_core/reg_result.h lacks FRY_REG_BOOT_HELPERS"); }
FRY_RED_ON_MAIN(test_case1_boot_success_suppresses_duplicate_on_tick_within_heartbeat)
FRY_RED_ON_MAIN(test_case2_boot_failure_retries_immediately_on_next_tick)
FRY_RED_ON_MAIN(test_case3_ota_reboot_on_0_4_30_sends_exactly_one_registration_with_new_version)
FRY_RED_ON_MAIN(test_stale_token_heal_is_not_suppressed_and_records_boot_attempt_once)
#undef FRY_RED_ON_MAIN

#endif

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_esp32_registerInstallation_records_boot_success_on_both_ok_and_heal_paths);
  RUN_TEST(test_version_0_4_30_and_tunnel_prerequisite_wiring);
  RUN_TEST(test_case1_boot_success_suppresses_duplicate_on_tick_within_heartbeat);
  RUN_TEST(test_case2_boot_failure_retries_immediately_on_next_tick);
  RUN_TEST(test_case3_ota_reboot_on_0_4_30_sends_exactly_one_registration_with_new_version);
  RUN_TEST(test_stale_token_heal_is_not_suppressed_and_records_boot_attempt_once);
  return UNITY_END();
}
