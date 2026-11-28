// Include-by-macro helpers. PlatformIO's library finder matches literal #include lines and ignores #if,
// so a literal "#include <Wire.h>" or an include of lib/fry_ui inside a FRY_HAS_DISPLAY guard would still
// pull Wire / the fry_ui library into the DEFAULT envs. Spelling the include through a macro keeps the
// finder blind to it; the compiler (and the display envs, whose lib_deps name every driver) see it fine.
#pragma once

#define FRY_INC_STR2(x) #x
#define FRY_INC_STR(x) FRY_INC_STR2(x)
#define FRY_INC_LIB(f) FRY_INC_STR(../../lib/fry_ui/f)  // from src/ui or src/display
#define FRY_INC_SYS(f) <f>
