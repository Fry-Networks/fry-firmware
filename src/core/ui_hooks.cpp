// Weak no-op defaults for the display/touch UI hooks (see include/fry_touch_ui.h). Always compiled
// (unconditional), so every build variant links; the UI track overrides them with strong definitions.
#include "fry_touch_ui.h"

extern "C" __attribute__((weak)) void fry_ui_setup(void) {}

extern "C" __attribute__((weak)) void fry_ui_loop(void) {}
