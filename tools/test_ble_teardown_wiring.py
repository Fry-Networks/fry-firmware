# Source checks for the BLE stack release (src/esp32/ble_provisioning.cpp tick()). Dependency-free:
#
#   python3 tools/test_ble_teardown_wiring.py                  # check src/esp32/ble_provisioning.cpp
#   python3 tools/test_ble_teardown_wiring.py <path-to-a-copy> # check a specific copy
#
# NimBLE glue cannot run on the host, so this pins the facts the release depends on:
#   - NimBLEDevice::deinit(true) deletes the server, and the server deletes the callbacks object it
#     was given unless it holds the default one. Ours is a static, so tick() detaches it
#     (setCallbacks(nullptr)) before deinit;
#   - the release is compiled out of opt-in builds that use BLE (FRY_HAS_OLOSTEP);
#   - every characteristic pointer is nulled and the staged key cleared BEFORE deinit, and the
#     "stack is up" flag is cleared after it;
#   - the idle timer gets the real Connected state and the real attached-central count.
# Each check must also fail on a mutant of the real source (the controls at the end).
#
# Exit 0 = all pass, 1 = a failure.
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "..", "src", "esp32", "ble_provisioning.cpp")


def strip_comments(code):
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    return re.sub(r"//[^\n]*", "", code)


def func_body(code, signature_regex):
    m = re.search(signature_regex, code)
    if not m:
        return ""
    i = code.index("{", m.end() - 1)
    depth = 0
    for j in range(i, len(code)):
        depth += {"{": 1, "}": -1}.get(code[j], 0)
        if depth == 0:
            return code[i + 1:j]
    return ""


CHARS = ["s_chSsid", "s_chPass", "s_chWallet", "s_chStatus", "s_chKey", "s_chKeyWrite", "s_chDevStatus"]


def checks(code):
    code = strip_comments(code)
    r = {}
    tick = func_body(code, r"\bvoid\s+tick\s*\(\s*\)\s*\{")
    guard = re.search(r"#if\s+!\s*FRY_HAS_OLOSTEP(.*?)#endif", tick, re.S)
    inner = guard.group(1) if guard else ""
    deinit = inner.find("NimBLEDevice::deinit(true)")
    r["the release is compiled out of opt-in builds"] = guard is not None and deinit != -1
    r["the server's static callbacks are detached before deinit"] = (
        deinit != -1 and re.search(r"if\s*\(\s*server\s*\)\s*server->setCallbacks\(\s*nullptr\s*\)\s*;", inner[:deinit]) is not None
        and not re.search(r"setCallbacks\(\s*&s_serverCallbacks\s*,\s*true", code))
    nulled = [inner.find(c) for c in CHARS]
    r["every characteristic pointer is nulled before deinit"] = (
        deinit != -1 and all(i != -1 and i < deinit for i in nulled)
        and re.search(r"=\s*nullptr\s*;", inner[:deinit]) is not None
        and all(re.search(re.escape(c) + r"\s*=", inner[:deinit]) for c in CHARS))
    cs = inner.find("clearStagedKey()")
    r["the staged key is cleared before deinit"] = cs != -1 and deinit != -1 and cs < deinit
    up = re.search(r"s_bleUp\s*=\s*false\s*;", inner)
    r["the stack-up flag is cleared after deinit"] = up is not None and deinit != -1 and up.start() > deinit
    r["the idle timer sees the real Connected state and central count"] = bool(
        re.search(r"s_bleIdle\.poll\(\s*s_bleUp\s*,\s*s_fsm\.state\(\)\s*==\s*fry::ProvState::Connected\s*,\s*centrals\s*,\s*millis\(\)\s*\)", inner)
        and re.search(r"centrals\s*=\s*server\s*\?\s*static_cast<int>\(\s*server->getConnectedCount\(\)\s*\)\s*:\s*0", inner))
    return r


with open(SRC, encoding="utf-8") as f:
    code = f.read()

passed = failed = 0
for name, ok in checks(code).items():
    print(("ok   " if ok else "FAIL ") + name)
    passed += ok
    failed += not ok

MUTANTS = [
    ("the server's static callbacks are detached before deinit", lambda c: c.replace("if (server) server->setCallbacks(nullptr);", "")),
    ("the release is compiled out of opt-in builds", lambda c: c.replace("#if !FRY_HAS_OLOSTEP\n  NimBLEServer* server = s_bleUp", "#if 1\n  NimBLEServer* server = s_bleUp")),
    ("every characteristic pointer is nulled before deinit", lambda c: c.replace("s_chKeyWrite = s_chDevStatus = nullptr;", "s_chKeyWrite = nullptr;")),
    ("the staged key is cleared before deinit", lambda c: c.replace("    clearStagedKey();\n    NimBLEDevice::deinit(true);", "    NimBLEDevice::deinit(true);")),
    ("the stack-up flag is cleared after deinit", lambda c: c.replace("    s_bleUp = false;\n", "")),
    ("the idle timer sees the real Connected state and central count", lambda c: c.replace("s_fsm.state() == fry::ProvState::Connected, centrals", "true, 0")),
]
for name, mutate in MUTANTS:
    mutant = mutate(code)
    ok = mutant != code and not checks(mutant)[name]
    print(("ok   " if ok else "FAIL ") + f"control: the mutant for '{name}' is caught")
    passed += ok
    failed += not ok

print(f"{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
