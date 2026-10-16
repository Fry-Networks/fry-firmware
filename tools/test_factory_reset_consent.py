# Static source test: factoryReset() must clear the Olostep opt-in in opt-in builds and leave
# default builds untouched. Reads src/core/fry_config.{cpp,h}; no compiler needed. Every mutant
# control must fail the same checker the real sources pass, so none of this is vacuous.
#
#   python3 -m pytest tools/test_factory_reset_consent.py -q
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CPP_PATH = os.path.join(ROOT, "src", "core", "fry_config.cpp")
H_PATH = os.path.join(ROOT, "src", "core", "fry_config.h")

MACRO = "FRY_OLOSTEP_ON_FACTORY_RESET"
BODY = "setOlostepOptIn(false); fry_olostep_optin_changed();"
USE_LINE = "  o.end(); " + MACRO + "()"
USE_LINENO = 559  # the existing o.end(); line: the macro must not move any production line


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def factory_reset_body(cpp):
    m = re.search(r"\nvoid factoryReset\(\) \{\n(.*?)\n\}\n", cpp, re.S)
    return m.group(1) if m else ""


def define_blocks(h):
    """Returns (olostep_branch, default_branch) text of the #if FRY_HAS_OLOSTEP ... #else ... #endif."""
    m = re.search(r"#if FRY_HAS_OLOSTEP\n(.*?)#else\n(.*?)#endif", h, re.S)
    return (m.group(1), m.group(2)) if m else ("", "")


def problems(cpp, h):
    """Every rule the real sources must satisfy; an empty list means all hold."""
    out = []
    body = factory_reset_body(cpp)
    lines = cpp.split("\n")
    if USE_LINE not in body.split("\n"):
        out.append("factoryReset lacks the macro on the o.end() line")
    if len(lines) < USE_LINENO or lines[USE_LINENO - 1] != USE_LINE:
        out.append("macro line is not line %d" % USE_LINENO)
    if body.count(MACRO) != 1:
        out.append("macro not used exactly once in factoryReset")
    if body.find('o.begin("fry_ota", false);') > body.find(MACRO) or body.find(MACRO) < 0:
        out.append("macro must come after the fry_ota clear")
    if cpp.count(MACRO) != 1:
        out.append("macro used outside factoryReset")
    if "setOlostepOptIn" in cpp or "fry_olostep_optin_changed" in cpp:
        out.append("fry_config.cpp must not call the setter directly")
    on, off = define_blocks(h)
    if not on or not off:
        out.append("no #if FRY_HAS_OLOSTEP / #else / #endif block")
    if "#define %s() %s\n" % (MACRO, BODY) not in on:
        out.append("opt-in branch body is not the pinned text")
    if not re.search(r"^#define %s\(\)\s*$" % MACRO, off, re.M):
        out.append("default branch macro is not empty")
    if MACRO in off.replace("#define %s()" % MACRO, ""):
        out.append("default branch references the macro body")
    if h.count("#define %s()" % MACRO) != 2:
        out.append("macro must be defined once per branch")
    head = h.split("#if FRY_HAS_OLOSTEP")[0]
    if '#include "olostep_flag.h"' not in head:
        out.append("olostep_flag.h include must be unconditional")
    if '#include "olostep_exec.h"' not in on:
        out.append("opt-in branch must include olostep_exec.h")
    if "olostep_exec.h" in off or "olostep_consent.h" in off:
        out.append("default branch must not include olostep headers")
    if re.search(r"\n#include \"olostep_(exec|consent)\.h\"", head):
        out.append("olostep_exec/consent included unconditionally")
    return out


@pytest.fixture(scope="module")
def real():
    return read(CPP_PATH), read(H_PATH)


def test_real_sources_satisfy_every_rule(real):
    assert problems(*real) == []


def test_factory_reset_uses_macro_on_existing_line(real):
    assert USE_LINE in factory_reset_body(real[0]).split("\n")


def test_macro_does_not_move_production_lines(real):
    assert real[0].split("\n")[USE_LINENO - 1] == USE_LINE


def test_macro_follows_the_ota_clear(real):
    body = factory_reset_body(real[0])
    assert 0 <= body.find('o.begin("fry_ota", false);') < body.find(MACRO)


def test_opt_in_branch_body_is_pinned(real):
    assert "#define %s() %s\n" % (MACRO, BODY) in define_blocks(real[1])[0]


def test_default_branch_is_empty(real):
    assert re.search(r"^#define %s\(\)\s*$" % MACRO, define_blocks(real[1])[1], re.M)


def test_flag_header_is_unconditional(real):
    assert '#include "olostep_flag.h"' in real[1].split("#if FRY_HAS_OLOSTEP")[0]


MUTANTS = {
    "macro_removed_from_cpp": lambda c, h: (c.replace(USE_LINE, "  o.end();"), h),
    "macro_on_own_line": lambda c, h: (c.replace(USE_LINE, "  o.end();\n  " + MACRO + "()"), h),
    "macro_before_ota_clear": lambda c, h: (
        c.replace('  o.begin("fry_ota", false);', "  " + MACRO + "()\n  o.begin(\"fry_ota\", false);", 1)
         .replace(USE_LINE, "  o.end();"), h),
    "macro_used_twice": lambda c, h: (c.replace("  clearVpn();", "  clearVpn(); " + MACRO + "()", 1), h),
    "direct_setter_call_in_cpp": lambda c, h: (
        c.replace(USE_LINE, "  o.end(); setOlostepOptIn(false);"), h),
    "opt_in_body_empty": lambda c, h: (c, h.replace("#define %s() %s\n" % (MACRO, BODY), "#define %s()\n" % MACRO)),
    "opt_in_body_missing_changed_hook": lambda c, h: (
        c, h.replace(BODY, "setOlostepOptIn(false);")),
    "opt_in_body_sets_true": lambda c, h: (c, h.replace("setOlostepOptIn(false)", "setOlostepOptIn(true)")),
    "opt_in_body_order_swapped": lambda c, h: (
        c, h.replace(BODY, "fry_olostep_optin_changed(); setOlostepOptIn(false);")),
    "opt_in_body_no_trailing_semicolon": lambda c, h: (
        c, h.replace(BODY, BODY[:-1])),
    "default_branch_nonempty": lambda c, h: (
        c, re.sub(r"(#else\n)#define %s\(\)\n" % MACRO, r"\1#define %s() (void)0\n" % MACRO, h)),
    "default_branch_has_setter": lambda c, h: (
        c, re.sub(r"(#else\n)#define %s\(\)\n" % MACRO, r"\1#define %s() %s\n" % (MACRO, BODY), h)),
    "flag_include_dropped": lambda c, h: (c, h.replace('#include "olostep_flag.h"\n', "")),
    "flag_include_made_conditional": lambda c, h: (
        c, h.replace('#include "olostep_flag.h"\n', "").replace(
            "#if FRY_HAS_OLOSTEP\n", '#if FRY_HAS_OLOSTEP\n#include "olostep_flag.h"\n', 1)),
    "exec_include_unconditional": lambda c, h: (
        c, h.replace("#if FRY_HAS_OLOSTEP\n", '#include "olostep_exec.h"\n#if FRY_HAS_OLOSTEP\n', 1)),
    "exec_include_dropped_from_opt_in": lambda c, h: (
        c, h.replace('#include "olostep_exec.h"\n', "", 1)),
    "macro_line_shifted": lambda c, h: ("// shifted\n" + c, h),
}


def test_every_mutant_is_killed(real):
    assert problems(*real) == []  # the control: mutants are judged against a passing baseline
    survivors = []
    for name, mutate in MUTANTS.items():
        cpp, h = mutate(*real)
        if (cpp, h) == real:
            survivors.append(name + " (mutation did not apply)")
        elif problems(cpp, h) == []:
            survivors.append(name)
    assert survivors == []


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_mutant_fails_the_checker(real, name):
    assert problems(*real) == []
    cpp, h = MUTANTS[name](*real)
    assert (cpp, h) != real, "mutation did not apply"
    assert problems(cpp, h) != []
