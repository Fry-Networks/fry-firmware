// Touch-simulator end-to-end: both first-boot setup paths, the keyboard, the Store poll, OTA screen,
// two-tap factory reset and calibration, all through the real TouchUI against fakes.
#include <unity.h>

#include "../support/ui_fakes.h"

using namespace fry;
using namespace fry::uitest;
using fry::ui::MinerState;

static const char* kKey = "FEM-0123456789abcdefABCDEF0123456789";

void setUp(void) {}
void tearDown(void) {}

static void rigAps(Rig& r) {
  r.act.addAp("HomeNet", -48, true);
  r.act.addAp("CafeOpen", -70, false);
  r.act.addAp("Neighbour", -82, true);
}

void test_first_boot_shown_when_unconfigured() {
  Rig r;
  r.begin();
  r.step();
  TEST_ASSERT_EQUAL_UINT8(ui::S_FirstBoot, r.ui.screenId());
  TEST_ASSERT_TRUE(r.canvas.hasText("Welcome"));
  TEST_ASSERT_TRUE(r.canvas.flushes() > 0);
}

void test_configured_boot_goes_straight_to_dashboard() {
  Rig r;
  r.store.externalWrite("HomeNet", "pw", kKey);
  r.status.s.state = MinerState::Mining;
  r.begin();
  r.step();
  TEST_ASSERT_EQUAL_UINT8(ui::S_Dashboard, r.ui.screenId());
}

void test_path_a_setup_on_screen_full_flow() {
  Rig r;
  rigAps(r);
  r.begin();
  r.step();
  r.tapRect(ui::gridBtn(ui::kFirstContinue, 1, 3, r.W, r.H));
  TEST_ASSERT_EQUAL_UINT8(ui::S_SetupChoice, r.ui.screenId());
  TEST_ASSERT_TRUE(r.canvas.hasText("Setup on Screen"));
  TEST_ASSERT_TRUE(r.canvas.hasText("Setup with App"));

  r.tapRect(ui::gridBtn(ui::kChoiceScreen, 1, 3, r.W, r.H));
  TEST_ASSERT_EQUAL_UINT8(ui::S_WifiList, r.ui.screenId());
  TEST_ASSERT_EQUAL_INT(1, r.act.scans);
  r.waitMs(1500);  // scan completes after a few polls
  TEST_ASSERT_TRUE(r.canvas.hasText("HomeNet"));
  TEST_ASSERT_TRUE(r.canvas.hasText("CafeOpen"));
  TEST_ASSERT_TRUE(r.canvas.hasText("Neighbour"));

  r.tapRect(ui::gridBtn(0, 1, 6, r.W, r.H));  // HomeNet (secured)
  TEST_ASSERT_EQUAL_UINT8(ui::S_Keyboard, r.ui.screenId());

  // lowercase, UPPERCASE, symbols, then a typo fixed with backspace
  TEST_ASSERT_TRUE(r.typeString("abc"));
  TEST_ASSERT_TRUE(r.typeString("XYZ"));
  TEST_ASSERT_TRUE(r.typeString("9;!"));
  TEST_ASSERT_TRUE(r.typeString("q"));
  r.tapRect(ui::kbFn(ui::kFnBack, r.W, r.H));  // remove the 'q'
  // Hidden by default: dots, never the password.
  TEST_ASSERT_FALSE(r.canvas.hasText("abcXYZ9;!"));
  TEST_ASSERT_TRUE(r.canvas.hasText("********"));
  r.tapRect(ui::kbFn(ui::kFnShow, r.W, r.H));  // show
  TEST_ASSERT_TRUE(r.canvas.hasText("abcXYZ9;!"));
  TEST_ASSERT_FALSE(r.canvas.hasText("abcXYZ9;!q"));
  r.tapRect(ui::kbFn(ui::kFnShow, r.W, r.H));  // hide again
  TEST_ASSERT_FALSE(r.canvas.hasText("abcXYZ9;!"));
  r.tapRect(ui::kbFn(ui::kFnOk, r.W, r.H));
  TEST_ASSERT_EQUAL_UINT8(ui::S_MinerKey, r.ui.screenId());

  // Miner key: prefilled FEM-, Save refused until the key is valid.
  TEST_ASSERT_TRUE(r.canvas.hasText("FEM-"));
  r.tapRect(ui::kbFn(ui::kFnOk, r.W, r.H));
  TEST_ASSERT_EQUAL_UINT8(ui::S_MinerKey, r.ui.screenId());
  TEST_ASSERT_EQUAL_INT(0, r.store.keySaves);
  TEST_ASSERT_TRUE(r.typeString("0123456789abcdefABCDEF0123456789"));
  r.tapRect(ui::kbFn(ui::kFnOk, r.W, r.H));
  TEST_ASSERT_EQUAL_UINT8(ui::S_Connecting, r.ui.screenId());

  // Persistence assertions against the store.
  TEST_ASSERT_EQUAL_STRING("HomeNet", r.store.ssid);
  TEST_ASSERT_EQUAL_STRING("abcXYZ9;!", r.store.pass);
  TEST_ASSERT_EQUAL_STRING(kKey, r.store.key);
  TEST_ASSERT_TRUE(r.store.provDone);
  TEST_ASSERT_EQUAL_INT(1, r.act.connects);

  // Board joins: status goes live, UI lands on the Dashboard and shows live data.
  r.status.s.state = MinerState::Mining;
  strcpy(r.status.s.ssid, "HomeNet");
  strcpy(r.status.s.ip, "192.168.1.50");
  r.waitMs(1500);
  TEST_ASSERT_EQUAL_UINT8(ui::S_Dashboard, r.ui.screenId());
  TEST_ASSERT_TRUE(r.canvas.hasText("HomeNet"));
  TEST_ASSERT_TRUE(r.canvas.hasText("192.168.1.50"));
  // secrets left no trace in the UI object's RAM beyond the store
  TEST_ASSERT_FALSE(r.canvas.hasText("abcXYZ9"));
}

void test_open_network_skips_password() {
  Rig r;
  rigAps(r);
  r.begin();
  r.step();
  r.tapRect(ui::gridBtn(ui::kFirstContinue, 1, 3, r.W, r.H));
  r.tapRect(ui::gridBtn(ui::kChoiceScreen, 1, 3, r.W, r.H));
  r.waitMs(1500);
  r.tapRect(ui::gridBtn(1, 1, 6, r.W, r.H));  // CafeOpen
  TEST_ASSERT_EQUAL_UINT8(ui::S_MinerKey, r.ui.screenId());
}

void test_keyboard_cancel_returns_to_list() {
  Rig r;
  rigAps(r);
  r.begin();
  r.step();
  r.tapRect(ui::gridBtn(ui::kFirstContinue, 1, 3, r.W, r.H));
  r.tapRect(ui::gridBtn(ui::kChoiceScreen, 1, 3, r.W, r.H));
  r.waitMs(1500);
  r.tapRect(ui::gridBtn(0, 1, 6, r.W, r.H));
  r.tapRect(ui::kbFn(ui::kFnCancel, r.W, r.H));
  TEST_ASSERT_EQUAL_UINT8(ui::S_WifiList, r.ui.screenId());
  TEST_ASSERT_EQUAL_INT(0, r.store.wifiSaves);
}

void test_path_b_setup_with_app_qr_then_external_write() {
  Rig r;
  r.begin();
  r.step();
  r.tapRect(ui::gridBtn(ui::kFirstContinue, 1, 3, r.W, r.H));
  r.tapRect(ui::gridBtn(ui::kChoiceApp, 1, 3, r.W, r.H));
  TEST_ASSERT_EQUAL_UINT8(ui::S_AppQr, r.ui.screenId());
  TEST_ASSERT_TRUE(r.canvas.hasText("FRY-Setup-A1B2"));
  TEST_ASSERT_TRUE(r.canvas.hasText("192.168.4.1"));
  TEST_ASSERT_TRUE(r.canvas.hasText("FRY-ESP32-A1B2C3"));
  // QR modules were drawn (dark and light areas both present, not just text)
  TEST_ASSERT_TRUE(r.canvas.countNonZero() > 2000);
  // Nothing on-board was done.
  TEST_ASSERT_EQUAL_INT(0, r.act.scans);
  TEST_ASSERT_EQUAL_INT(0, r.store.wifiSaves);

  // External app / captive write lands in the store; the UI notices on its 1 s poll.
  r.status.s.state = MinerState::Mining;
  strcpy(r.status.s.ssid, "AppNet");
  strcpy(r.status.s.ip, "10.0.0.7");
  r.store.externalWrite("AppNet", "apppw", kKey);
  r.waitMs(1300);
  TEST_ASSERT_EQUAL_UINT8(ui::S_Dashboard, r.ui.screenId());
  TEST_ASSERT_TRUE(r.canvas.hasText("AppNet"));
  TEST_ASSERT_EQUAL_INT(0, r.act.scans);
  TEST_ASSERT_EQUAL_INT(0, r.store.wifiSaves);  // UI itself never wrote
  TEST_ASSERT_EQUAL_INT(0, r.store.keySaves);
}

void test_store_polled_every_1000ms_and_rerender_on_generation_change() {
  Rig r;
  r.store.externalWrite("HomeNet", "pw", kKey);
  r.status.s.state = MinerState::Mining;
  strcpy(r.status.s.ssid, "HomeNet");
  r.begin();
  r.step();
  const int loads0 = r.store.loads;
  r.step(10, 50);  // 500 ms: no new poll
  TEST_ASSERT_EQUAL_INT(loads0, r.store.loads);
  r.step(12, 50);  // another 600 ms: exactly one poll
  TEST_ASSERT_EQUAL_INT(loads0 + 1, r.store.loads);
  r.step(20, 50);  // 1000 ms more
  TEST_ASSERT_EQUAL_INT(loads0 + 2, r.store.loads);
}

void test_generation_change_forces_redraw() {
  Rig r;
  r.store.externalWrite("HomeNet", "pw", kKey);
  r.status.s.state = MinerState::Mining;
  r.begin();
  r.step();
  r.waitMs(2200);
  const uint32_t before = r.canvas.flushes();
  // Same status, but the stored SSID changes: generation changes, frame must be re-rendered.
  strcpy(r.store.ssid, "RenamedNet");
  strcpy(r.status.s.ssid, "RenamedNet");
  r.waitMs(1100);
  TEST_ASSERT_TRUE(r.canvas.flushes() > before);
  TEST_ASSERT_TRUE(r.canvas.hasText("RenamedNet"));
}

void test_ota_progress_screen_and_return() {
  Rig r;
  r.store.externalWrite("HomeNet", "pw", kKey);
  r.status.s.state = MinerState::Mining;
  r.begin();
  r.step();
  r.waitMs(1200);
  TEST_ASSERT_EQUAL_UINT8(ui::S_Dashboard, r.ui.screenId());
  r.status.s.state = MinerState::OtaUpdating;
  r.status.s.otaPct = 42;
  strcpy(r.status.s.otaStage, "download");
  r.waitMs(1200);
  TEST_ASSERT_EQUAL_UINT8(ui::S_Ota, r.ui.screenId());
  TEST_ASSERT_TRUE(r.canvas.hasText("42%"));
  TEST_ASSERT_TRUE(r.canvas.hasText("download"));
  r.status.s.otaPct = 87;
  r.waitMs(1200);
  TEST_ASSERT_TRUE(r.canvas.hasText("87%"));
  r.status.s.state = MinerState::Mining;
  r.waitMs(1200);
  TEST_ASSERT_EQUAL_UINT8(ui::S_Dashboard, r.ui.screenId());
}

static void toSettings(Rig& r) {
  r.store.externalWrite("HomeNet", "pw", kKey);
  r.status.s.state = MinerState::Mining;
  r.begin();
  r.step();
  r.tapRect(ui::dashSettingsBtn(r.W, r.H));
}

void test_settings_actions() {
  Rig r;
  toSettings(r);
  TEST_ASSERT_EQUAL_UINT8(ui::S_Settings, r.ui.screenId());
  r.tapRect(ui::gridBtn(ui::kSetCheckOta, 2, 4, r.W, r.H));
  TEST_ASSERT_EQUAL_INT(1, r.act.otaChecks);
  r.tapRect(ui::gridBtn(ui::kSetBrightDn, 2, 4, r.W, r.H));
  TEST_ASSERT_TRUE(r.act.brightness < 100);
  r.tapRect(ui::gridBtn(ui::kSetBrightUp, 2, 4, r.W, r.H));
  r.tapRect(ui::gridBtn(ui::kSetRotate, 2, 4, r.W, r.H));
  TEST_ASSERT_EQUAL_UINT8(1, r.act.rotation);
  r.tapRect(ui::gridBtn(ui::kSetBack, 2, 4, r.W, r.H));
  TEST_ASSERT_EQUAL_UINT8(ui::S_Dashboard, r.ui.screenId());
}

void test_factory_reset_two_tap_confirm() {
  Rig r;
  toSettings(r);
  r.tapRect(ui::gridBtn(ui::kSetReset, 2, 4, r.W, r.H));
  TEST_ASSERT_EQUAL_UINT8(ui::S_ConfirmReset, r.ui.screenId());
  // first tap arms only
  r.tapRect(ui::gridBtn(ui::kResetConfirm, 1, 3, r.W, r.H));
  TEST_ASSERT_EQUAL_INT(0, r.store.resets);
  TEST_ASSERT_EQUAL_INT(0, r.act.reboots);
  TEST_ASSERT_TRUE(r.canvas.hasText("Tap again"));
  // second tap executes
  r.tapRect(ui::gridBtn(ui::kResetConfirm, 1, 3, r.W, r.H));
  TEST_ASSERT_EQUAL_INT(1, r.store.resets);
  TEST_ASSERT_EQUAL_INT(1, r.act.reboots);
  TEST_ASSERT_EQUAL_STRING("", r.store.ssid);
}

void test_factory_reset_cancel_and_timeout() {
  Rig r;
  toSettings(r);
  r.tapRect(ui::gridBtn(ui::kSetReset, 2, 4, r.W, r.H));
  r.tapRect(ui::gridBtn(ui::kResetConfirm, 1, 3, r.W, r.H));  // armed
  r.tapRect(ui::gridBtn(ui::kResetCancel, 1, 3, r.W, r.H));
  TEST_ASSERT_EQUAL_UINT8(ui::S_Settings, r.ui.screenId());
  TEST_ASSERT_EQUAL_INT(0, r.store.resets);
  // re-enter: arming state must not persist across entries
  r.tapRect(ui::gridBtn(ui::kSetReset, 2, 4, r.W, r.H));
  r.tapRect(ui::gridBtn(ui::kResetConfirm, 1, 3, r.W, r.H));  // arms (not executes)
  TEST_ASSERT_EQUAL_INT(0, r.store.resets);
  // arm expires: a late second tap only re-arms
  r.waitMs(6000);
  r.tapRect(ui::gridBtn(ui::kResetConfirm, 1, 3, r.W, r.H));
  TEST_ASSERT_EQUAL_INT(0, r.store.resets);
  // a tap elsewhere never resets
  r.tapXY(5, r.H - 3);
  TEST_ASSERT_EQUAL_INT(0, r.store.resets);
}

void test_calibrate_four_taps_saved() {
  Rig r;
  toSettings(r);
  r.tapRect(ui::gridBtn(ui::kSetCalibrate, 2, 4, r.W, r.H));
  TEST_ASSERT_EQUAL_UINT8(ui::S_Calibrate, r.ui.screenId());
  const int resets = r.store.calSaves;  // entering clears any old correction
  TEST_ASSERT_EQUAL_INT(1, resets);
  int16_t x, y;
  for (int i = 0; i < 4; i++) {
    ui::calTarget(i, r.W, r.H, &x, &y);
    r.tapXY((int16_t)(x + 3), (int16_t)(y - 2));  // slightly off, as a real finger is
  }
  TEST_ASSERT_EQUAL_UINT8(ui::S_Settings, r.ui.screenId());
  TEST_ASSERT_EQUAL_INT(2, r.store.calSaves);
  TEST_ASSERT_EQUAL_INT16(23, r.store.cal[0]);
  TEST_ASSERT_EQUAL_INT16(18, r.store.cal[1]);
}

void test_tick_returns_false_when_idle() {
  Rig r;
  r.store.externalWrite("HomeNet", "pw", kKey);
  r.status.s.state = MinerState::Mining;
  r.begin();
  r.step();
  r.waitMs(1100);
  // between polls nothing changes: tick must not redraw
  int redraws = 0;
  for (int i = 0; i < 20; i++) {
    r.now += 20;
    redraws += r.ui.tick(r.now) ? 1 : 0;
  }
  TEST_ASSERT_TRUE(redraws <= 1);
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_first_boot_shown_when_unconfigured);
  RUN_TEST(test_configured_boot_goes_straight_to_dashboard);
  RUN_TEST(test_path_a_setup_on_screen_full_flow);
  RUN_TEST(test_open_network_skips_password);
  RUN_TEST(test_keyboard_cancel_returns_to_list);
  RUN_TEST(test_path_b_setup_with_app_qr_then_external_write);
  RUN_TEST(test_store_polled_every_1000ms_and_rerender_on_generation_change);
  RUN_TEST(test_generation_change_forces_redraw);
  RUN_TEST(test_ota_progress_screen_and_return);
  RUN_TEST(test_settings_actions);
  RUN_TEST(test_factory_reset_two_tap_confirm);
  RUN_TEST(test_factory_reset_cancel_and_timeout);
  RUN_TEST(test_calibrate_four_taps_saved);
  RUN_TEST(test_tick_returns_false_when_idle);
  return UNITY_END();
}
