# Source pin: ESP32/C3 credential-bearing POSTs must not follow redirects. fry_http::beginHttpsUrl
# (src/esp32/http_tls.cpp) turns follow-redirects ON for the OTA download; ESP32 HTTPClient re-sends the
# body and the Authorization header to the redirect target on 301/307. So each credentialed call site
# must call setFollowRedirects(HTTPC_DISABLE_FOLLOW_REDIRECTS) after beginHttpsUrl and before the POST.
# Dependency-free; runs under pytest or directly: python3 tools/test_no_credentialed_redirects.py
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
SITES = ["src/core/telemetry.cpp", "src/esp32/wg_provision_client.cpp"]
DISABLE = re.compile(r"\bsetFollowRedirects\s*\(\s*HTTPC_DISABLE_FOLLOW_REDIRECTS\s*\)")


def strip(code):
    """Remove comments and string/char literals so a comment cannot satisfy the check."""
    out = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    out = re.sub(r"//[^\n]*", "", out)
    out = re.sub(r'"(?:\\.|[^"\\\n])*"', '""', out)
    return out


def violations(code):
    code = strip(code)
    begins = [m.start() for m in re.finditer(r"\bbeginHttpsUrl\s*\(", code)]
    problems = []
    if not begins:
        return ["no beginHttpsUrl call found"]
    for b in begins:
        post = re.search(r"\.\s*POST\s*\(", code[b:])
        if not post:
            problems.append("beginHttpsUrl at offset %d has no following POST" % b)
            continue
        between = code[b:b + post.start()]
        if not DISABLE.search(between):
            problems.append("POST after beginHttpsUrl at offset %d without HTTPC_DISABLE_FOLLOW_REDIRECTS" % b)
    return problems


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def test_sites_disable_redirects():
    for rel in SITES:
        assert violations(read(rel)) == [], rel


def test_control_mutant_fails():
    # The check must reject: the fix removed, and the fix present only in a comment.
    good = read(SITES[0])
    no_fix = DISABLE.sub("(void)0", good)
    assert violations(no_fix), "mutant without the call must fail"
    commented = DISABLE.sub("/* setFollowRedirects(HTTPC_DISABLE_FOLLOW_REDIRECTS) */ (void)0", good)
    assert violations(commented), "mutant with the call only in a comment must fail"


if __name__ == "__main__":
    fails = 0
    for fn in (test_sites_disable_redirects, test_control_mutant_fails):
        try:
            fn()
            print("PASS", fn.__name__)
        except AssertionError as e:
            fails += 1
            print("FAIL", fn.__name__, e)
    sys.exit(1 if fails else 0)
