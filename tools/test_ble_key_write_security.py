# Source checks for BLE provisioning (PROTOCOL.md 11.9). Dependency-free, same style as
# tools/test_scan_identity.py:
#
#   python3 tools/test_ble_key_write_security.py                  # check src/esp32/ble_provisioning.cpp
#   python3 tools/test_ble_key_write_security.py <path-to-a-copy> # check a specific copy
#
# NimBLE glue cannot run on the host, so this pins the facts BLE provisioning depends on:
#   - 09 is a plain WRITE. In Secure Connections Only mode NimBLE answers every attribute that
#     needs security with "insufficient authentication" unless the link is AUTHENTICATED (MITM);
#     Just Works never is, so a WRITE_ENC 09 could not be written at all (fw 0.4.0).
#   - the 09 handler refuses the key unless the link is encrypted, before reading it, and clears
#     the attribute value NimBLE stored before the callback, on both paths;
#   - Secure Connections Only stays on, so an encrypted link is always an LE Secure Connections one;
#   - 0A reports "enc" for the reader's link, so a client can prove the link before writing 09;
#   - the board advertises again after a disconnect unless it is Connected (NimBLE-Arduino 2.x does
#     not by itself), and stops advertising once Connected, so a running board does not keep
#     offering its readable 05.
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
    """The brace-balanced body of the first function whose signature matches."""
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


def checks(code):
    """Returns {name: ok} for every fact above."""
    r = {}
    m = re.search(r"s_chKeyWrite\s*=\s*service->createCharacteristic\(\s*kUuidKeyWrite\s*,([^;]*)\);", code, re.S)
    props = m.group(1) if m else ""
    r["09 is created writable"] = m is not None and "NIMBLE_PROPERTY::WRITE" in props
    r["09 needs no ATT-level security"] = m is not None and not re.search(r"WRITE_(ENC|AUTHEN|AUTHOR)", props)
    r["09 is not readable"] = m is not None and "READ" not in props

    branch = re.search(r"if\s*\(\s*ch\s*==\s*s_chKeyWrite\s*\)\s*\{(.*?)\n    \}\s*else if", code, re.S)
    body = branch.group(1) if branch else ""
    enc = re.search(r"if\s*\(\s*!\s*connInfo\.isEncrypted\(\)\s*\)\s*\{([^}]*)return\s*;", body, re.S)
    reads = [i for i in (body.find("copyAttrValue"), body.find("getValue")) if i != -1]
    first_read = min(reads) if reads else -1
    r["09 refuses an unencrypted link"] = enc is not None
    r["... before the value is read"] = enc is not None and first_read != -1 and enc.start() < first_read
    r["... and clears what NimBLE stored"] = enc is not None and re.search(r'ch->setValue\(\s*""\s*\)', enc.group(1)) is not None
    after = body[enc.end():] if enc else ""
    r["an accepted or refused key is cleared too"] = re.search(r'ch->setValue\(\s*""\s*\)', after) is not None

    r["Secure Connections Only stays on"] = re.search(r"ble_hs_cfg\.sm_sc_only\s*=\s*1\s*;", code) is not None
    r["Secure Connections is requested"] = re.search(r"setSecurityAuth\([^)]*true\s*\)", code) is not None

    status = func_body(code, r"void\s+setDevStatusValue\s*\([^)]*\)\s*\{")
    r["0A carries enc"] = '\\"enc\\":' in status and "isEncrypted()" in status
    on_read = func_body(code, r"void\s+onRead\s*\(\s*NimBLECharacteristic\*[^)]*\)\s*override\s*\{")
    r["0A reads report the reader's own link"] = re.search(r"setDevStatusValue\(\s*connInfo\.isEncrypted\(\)", on_read) is not None

    on_disc = func_body(code, r"void\s+onDisconnect\s*\(\s*NimBLEServer\*[^)]*\)\s*override\s*\{")
    r["advertising restarts after a disconnect unless Connected"] = re.search(
        r"if\s*\(\s*s_fsm\.state\(\)\s*!=\s*fry::ProvState::Connected\s*\)\s*NimBLEDevice::startAdvertising\(\)", on_disc) is not None
    r["no unconditional advertiseOnDisconnect"] = re.search(r"advertiseOnDisconnect\(\s*true\s*\)", code) is None
    api_ok = func_body(code, r"void\s+notifyApiOk\s*\(\s*\)\s*\{")
    r["advertising stops once Connected"] = "ProvState::Connected" in api_ok and "NimBLEDevice::stopAdvertising()" in api_ok
    return r


code = strip_comments(open(SRC, encoding="utf-8").read())
passed = failed = 0
for name, ok in checks(code).items():
    print(("ok   " if ok else "FAIL ") + name)
    passed += ok
    failed += not ok

# Controls: each mutant of the real source must break the check named with it.
MUTANTS = [
    ("09 needs no ATT-level security", lambda c: c.replace("kUuidKeyWrite, NIMBLE_PROPERTY::WRITE)", "kUuidKeyWrite, NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_ENC)")),
    ("09 refuses an unencrypted link", lambda c: c.replace("if (!connInfo.isEncrypted()) {", "if (false) {", 1)),
    ("... before the value is read", lambda c: re.sub(r"(if \(ch == s_chKeyWrite\) \{)", r"\1\n      (void)ch->getValue();", c, count=1)),
    ("... and clears what NimBLE stored", lambda c: re.sub(r'(if \(!connInfo\.isEncrypted\(\)\) \{\s*)ch->setValue\(""\);', r"\1", c, count=1)),
    ("Secure Connections Only stays on", lambda c: c.replace("ble_hs_cfg.sm_sc_only = 1;", "ble_hs_cfg.sm_sc_only = 0;")),
    ("0A reads report the reader's own link", lambda c: c.replace("setDevStatusValue(connInfo.isEncrypted() ? 1 : 0);", "setDevStatusValue();")),
    ("advertising restarts after a disconnect unless Connected", lambda c: c.replace("if (s_fsm.state() != fry::ProvState::Connected) NimBLEDevice::startAdvertising();", "")),
    ("no unconditional advertiseOnDisconnect", lambda c: c.replace("server->setCallbacks(&s_serverCallbacks);", "server->setCallbacks(&s_serverCallbacks);\n  server->advertiseOnDisconnect(true);")),
    ("advertising stops once Connected", lambda c: c.replace("NimBLEDevice::stopAdvertising();", "")),
]
for name, mutate in MUTANTS:
    mutant = mutate(code)
    ok = mutant != code and not checks(mutant)[name]
    print(("ok   " if ok else "FAIL ") + f"control: the mutant for '{name}' is caught")
    passed += ok
    failed += not ok

print(f"{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
