// Builds lib/fry_ui/ui_widgets.cpp into display-enabled envs only. The lib is pure C++ shared with the host
// tests; it is pulled in by path (not by LDF header lookup) so the default envs never see it.
#if defined(FRY_HAS_DISPLAY)
#include "fry_inc.h"
#include FRY_INC_LIB(ui_widgets.cpp)
#endif
