// Entry points for FRY_UI_BARE images only (display bring-up for boards whose firmware core is not ported
// yet, see ui_glue.cpp). Every other build has its own setup()/loop() in src/main.cpp.
#if defined(FRY_UI_BARE)

#include <Arduino.h>

#include "../../include/fry_touch_ui.h"

void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.println("FRY ui-bare boot");
  fry_ui_setup();
  Serial.println("[boot] ready");
}

void loop() {
  fry_ui_loop();
  delay(5);
}

#endif
