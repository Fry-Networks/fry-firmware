// Smoke test proving the native_boards env runs: the board HAL header compiles on the host.
#include <unity.h>

#include "fry_board_hal.h"

void setUp() {}
void tearDown() {}

void test_flash_info_is_a_plain_struct() {
  fry::board::FlashInfo f = {4u * 1024 * 1024, 4u * 1024 * 1024, 1024, 2048};
  TEST_ASSERT_EQUAL_UINT32(4u * 1024 * 1024, f.realSize);
  TEST_ASSERT_EQUAL_UINT32(1024, f.otaFreeBytes);
  TEST_ASSERT_EQUAL_UINT32(2048, f.sketchSize);
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_flash_info_is_a_plain_struct);
  return UNITY_END();
}
