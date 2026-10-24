# Tests for tools/redact.py. Dependency-free, same style as tools/test_check_no_token.py:
#
#   python3 tools/test_redact.py                   # test the sibling redact.py
#   python3 tools/test_redact.py <path-to-a-copy>  # test a specific copy
#
# Exit 0 = all pass, 1 = a failure. Every synthetic value below is generated at run time and never
# hardcoded, and each test asserts the value does not survive the filter.
import os
import random
import string
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "redact.py")
sys.path.insert(0, os.path.dirname(TOOL))
import redact  # noqa: E402

FAILURES = []


def check(name, cond, detail=""):
    if cond:
        print("PASS %s" % name)
    else:
        FAILURES.append(name)
        print("FAIL %s %s" % (name, detail))


def token(n=32):
    return "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(n))


def test_miner_key_forms_are_masked():
    r = redact.Redactor()
    key = "FEM-" + token()
    legacy = "IOT-" + token(16)
    line = "FRY boot v0.4.11 chip=ESP8266 mac=AA:BB:CC:DD:EE:FF minerkey=%s" % key
    out = r.line(line)
    check("miner_key gone", key not in out and key[-12:] not in out, out)
    check("miner_key counted", r.hits.get("miner_key") == 1, str(r.hits))
    out2 = redact.Redactor().line("legacy key IOT-%s written" % legacy[4:])
    check("legacy key gone", legacy[4:] not in out2, out2)


def test_the_firmware_mask_and_pending_state_survive():
    r = redact.Redactor()
    masked = "FEM-…GOGQ"
    out = r.line("banner minerkey=%s" % masked)
    check("masked banner key untouched", masked in out, out)
    out = r.line("banner minerkey=FEM-PENDING")
    check("FEM-PENDING untouched", "FEM-PENDING" in out, out)
    check("no hits on a masked line", r.total_hits() == 0, str(r.hits))


def test_the_improv_key_url_fragment_is_masked_but_the_url_survives():
    r = redact.Redactor()
    key = "FEM-" + token()
    url = "https://dashboard.frynetworks.com/new_registration#key=%s" % key
    out = r.line(url)
    check("url key gone", key not in out and key[-12:] not in out, out)
    check("url still a url", out.startswith("https://dashboard.frynetworks.com/new_registration#key="), out)
    check("url key counted", r.hits.get("url_key") == 1, str(r.hits))


def test_ssid_and_setup_code_and_password_are_masked():
    r = redact.Redactor()
    ssid = "Home" + token(8)
    out = r.line("[serial] set_wifi: ssid=%s (12 chars) password=<9 chars>" % ssid)
    check("ssid gone", ssid not in out, out)
    check("ssid len kept", "len=%d" % len(ssid) in out, out)
    check("password length form untouched", "password=<9 chars>" in out, out)
    code = token(8)
    out = r.line("AP started FRY-SETUP-112233 ip=192.168.4.1 wpa2 setup-code=%s (no miner key yet)" % code)
    check("setup code gone", code not in out, out)
    check("ap name kept", "FRY-SETUP-112233" in out, out)
    raw_pw = "hunter" + token(6)
    out = r.line("[serial] set_wifi: ssid=x password=%s" % raw_pw)
    check("raw password gone", raw_pw not in out, out)


def test_wireguard_and_bearer_material_is_masked():
    r = redact.Redactor()
    priv = token(44)
    psk = token(44)
    tok = token(40)
    line = "wg priv=%s psk=%s peer_pub=%s" % (priv, psk, token(44))
    out = r.line(line)
    check("wg priv gone", priv not in out, out)
    check("wg psk gone", psk not in out, out)
    out = r.line("POST /PoC Authorization: Bearer %s" % tok)
    check("bearer gone", tok not in out, out)


def test_an_ordinary_line_is_unchanged():
    r = redact.Redactor()
    line = "[health] up=30s heap=153608 blk=110580 rssi=-42 vpn=down relayed=0 temp=na"
    check("ordinary line unchanged", r.line(line) == line, r.line(line))
    check("ordinary line no hits", r.total_hits() == 0, str(r.hits))


def test_raw_to_is_refused_outside_run_secret():
    with tempfile.TemporaryDirectory() as run:
        os.makedirs(os.path.join(run, "secret"))
        ok = redact.resolve_raw_path(os.path.join(run, "secret", "boot.log"), run)
        check("inside secret accepted", ok.endswith(os.path.join("secret", "boot.log")), ok)
        for bad in (os.path.join(run, "lo", "boot.log"), os.path.join(run, "boot.log"),
                    os.path.join(run, "secret", "..", "x.log"), "/tmp/x.log"):
            try:
                redact.resolve_raw_path(bad, run)
                check("refused %s" % bad, False, "accepted")
            except redact.RawPathRefused:
                check("refused outside-secret path", True)
        try:
            redact.resolve_raw_path(os.path.join(run, "secret", "boot.log"), None)
            old = os.environ.pop("RUN", None)
            try:
                redact.resolve_raw_path(os.path.join(run, "secret", "boot.log"), None)
                check("refused without a run dir", False, "accepted")
            except redact.RawPathRefused:
                check("refused without a run dir", True)
            if old is not None:
                os.environ["RUN"] = old
        except redact.RawPathRefused:
            check("refused without a run dir", True)


def main():
    random.seed()
    test_miner_key_forms_are_masked()
    test_the_firmware_mask_and_pending_state_survive()
    test_the_improv_key_url_fragment_is_masked_but_the_url_survives()
    test_ssid_and_setup_code_and_password_are_masked()
    test_wireguard_and_bearer_material_is_masked()
    test_an_ordinary_line_is_unchanged()
    test_raw_to_is_refused_outside_run_secret()
    if FAILURES:
        print("\n%d FAILURE(S): %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("\nall redact.py checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
