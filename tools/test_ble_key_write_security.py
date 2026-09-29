# Source checks for the BLE miner-key write (characteristic 09, PROTOCOL.md 11.9). Dependency-free,
# same style as tools/test_scan_identity.py:
#
#   python3 tools/test_ble_key_write_security.py                  # check src/esp32/ble_provisioning.cpp
#   python3 tools/test_ble_key_write_security.py <path-to-a-copy> # check a specific copy
#
# NimBLE glue cannot run on the host, so this pins the facts BLE provisioning depends on:
#   - 09 is a plain WRITE. In Secure Connections Only mode NimBLE answers every attribute that
#     needs security with "insufficient authentication" unless the link is AUTHENTICATED (MITM);
#     Just Works never is, so a WRITE_ENC 09 could not be written at all (fw 0.4.0).
#   - the 09 handler refuses the key unless the link is encrypted, before copying it anywhere;
#   - Secure Connections Only stays on, so an encrypted link is always an LE Secure Connections one.
#   - the board advertises again after every disconnect (NimBLE-Arduino 2.x does not by default).
#
# Exit 0 = all pass, 1 = a failure.
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "..", "src", "esp32", "ble_provisioning.cpp")

passed = 0
failed = 0


def check(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print(f"ok   {name}")
    else:
        failed += 1
        print(f"FAIL {name} {detail}")


def strip_comments(code):
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    return re.sub(r"//[^\n]*", "", code)


code = strip_comments(open(SRC, encoding="utf-8").read())

m = re.search(r"s_chKeyWrite\s*=\s*service->createCharacteristic\(\s*kUuidKeyWrite\s*,([^;]*)\);", code, re.S)
check("09 is created", m is not None)
props = m.group(1) if m else ""
check("09 is writable", "NIMBLE_PROPERTY::WRITE" in props, props.strip())
check("09 needs no ATT-level security (SC-only would demand MITM)",
      not re.search(r"WRITE_(ENC|AUTHEN|AUTHOR)", props), props.strip())
check("09 is not readable", "READ" not in props, props.strip())

branch = re.search(r"if\s*\(\s*ch\s*==\s*s_chKeyWrite\s*\)\s*\{(.*?)\n    \}\s*else if", code, re.S)
check("the 09 branch exists in onWrite", branch is not None)
body = branch.group(1) if branch else ""
enc = re.search(r"if\s*\(\s*!\s*connInfo\.isEncrypted\(\)\s*\)\s*\{[^}]*return\s*;", body, re.S)
copy = body.find("copyAttrValue")
check("the 09 branch refuses an unencrypted link", enc is not None)
check("... before the key is copied", enc is not None and copy != -1 and enc.start() < copy,
      f"refusal at {enc.start() if enc else None}, copy at {copy}")

check("Secure Connections Only stays on", re.search(r"ble_hs_cfg\.sm_sc_only\s*=\s*1\s*;", code) is not None)
check("Secure Connections is requested", re.search(r"setSecurityAuth\([^)]*true\s*\)", code) is not None)

# NimBLE-Arduino 2.x does not advertise again after a disconnect unless told to (its default is
# off): without this a board was undiscoverable after any BLE session until it rebooted.
check("advertising restarts after every disconnect",
      re.search(r"server->advertiseOnDisconnect\(\s*true\s*\)\s*;", code) is not None)

# Positive control: the checks above must fail on the 0.4.0 shape (09 WRITE_ENC, no refusal).
bad = code.replace(props, " NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_ENC") if props else code
check("control: a WRITE_ENC 09 is caught",
      re.search(r"WRITE_(ENC|AUTHEN|AUTHOR)",
                re.search(r"createCharacteristic\(\s*kUuidKeyWrite\s*,([^;]*)\);", bad, re.S).group(1)) is not None)

print(f"{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
