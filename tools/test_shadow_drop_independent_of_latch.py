# Source pin (T8P1-6): putPoc must drop the stale-token shadow pair on an accepted heartbeat whenever the
# heal left shadows pending, NOT only while the per-boot heal latch (s_staleTokenHealed) is still set:
# healStaleTokenIfDue releases that latch after the 6 h window. Comments and string literals are
# stripped first so a comment cannot satisfy the pin. Dependency-free; runs under pytest or directly.
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
SRC = os.path.join(ROOT, "src", "core", "hardwareapi_client.cpp")


def strip(code):
    out = re.sub(r"//[^\n]*|/\*.*?\*/", lambda m: " " * len(m.group(0)), code, flags=re.S)
    return re.sub(r'"(?:\\.|[^"\\\n])*"', '""', out)


def func_body(code, name_re):
    m = re.search(name_re, code)
    assert m, "function not found: " + name_re
    i = code.index("{", m.end())
    depth = 0
    for j in range(i, len(code)):
        depth += code[j] == "{"
        depth -= code[j] == "}"
        if depth == 0:
            return code[i:j + 1]
    raise AssertionError("unbalanced braces")


def check(code):
    c = strip(code)
    put = func_body(c, r"\bint\s+putPoc\s*\([^)]*\)")
    # test_stale_token_heal_wiring pins the latch-gated line verbatim, so it stays; a SECOND drop must exist
    # that is gated on a shadow-pending flag and not on the releasable latch.
    conds = [m.group(1) for m in re.finditer(r"if\s*\(([^;{}]*?\bcode\s*<\s*300[^;{}]*?)\)\s*\{?\s*dropTokenPairShadow\s*\(", put)]
    assert conds, "no accepted-heartbeat dropTokenPairShadow call in putPoc"
    free = [c for c in conds if "s_staleTokenHealed" not in c and re.search(r"\bs_\w*[Ss]hadow\w*\b", c)]
    assert free, "no drop independent of the releasable heal latch: " + repr(conds)
    name = re.search(r"\bs_\w*[Ss]hadow\w*\b", free[0]).group(0)
    heal = func_body(c, r"\bbool\s+healStaleTokenIfDue\s*\(")
    assert re.search(r"\b" + name + r"\s*=\s*true\s*;", heal), "flag never set by the heal"
    assert re.search(r"\b" + name + r"\s*=\s*false\s*;", put), "flag never cleared after the drop"


def test_shadow_drop_independent_of_latch():
    with open(SRC, encoding="utf-8") as f:
        check(f.read())


def test_control_rejects_latch_gate_and_comment():
    old = "int putPoc(int a) {\n if (code >= 200 && code < 300 && s_staleTokenHealed) dropTokenPairShadow();\n}\n"
    try:
        check("bool healStaleTokenIfDue(int a) { s_staleTokenHealed = true; }\n" + old)
    except AssertionError:
        pass
    else:
        raise AssertionError("control: latch-gated code accepted")
    cm = old.replace("dropTokenPairShadow();", "dropTokenPairShadow(); // s_shadowPending = false; s_shadowPending = true;")
    try:
        check(cm)
    except AssertionError:
        return
    raise AssertionError("control: comment satisfied the pin")


if __name__ == "__main__":
    fails = 0
    for fn in (test_shadow_drop_independent_of_latch, test_control_rejects_latch_gate_and_comment):
        try:
            fn()
            print("PASS", fn.__name__)
        except AssertionError as e:
            fails += 1
            print("FAIL", fn.__name__, e)
    sys.exit(1 if fails else 0)
