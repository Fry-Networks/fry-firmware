# Source pin: every request src/core/hardwareapi_client.cpp makes carries credentials (the bearer
# token, or the miner key in the URL and body), and fry_http::beginHttpsUrl() turns follow-redirects
# ON for the OTA download. So each request in this client must call noRedirects() after
# beginHttpsUrl() and before it is sent, and noRedirects() must disable redirect following.
# Dependency-free; runs under pytest or directly: python3 tools/test_hwapi_no_redirects.py
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
SRC = "src/core/hardwareapi_client.cpp"
SEND = re.compile(r"\.\s*(?:POST|PUT|GET)\s*\(|\.\s*sendRequest\s*\(")


def strip(code):
    """Remove comments and string/char literals so a comment cannot satisfy the check."""
    out = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    out = re.sub(r"//[^\n]*", "", out)
    return re.sub(r'"(?:\\.|[^"\\\n])*"', '""', out)


def violations(code):
    code = strip(code)
    problems = []
    helper = re.search(r"void\s+noRedirects\s*\(\s*HTTPClient&\s*\w+\s*\)\s*\{([^}]*)\}", code)
    if not helper or not re.search(r"setFollowRedirects\s*\(\s*HTTPC_DISABLE_FOLLOW_REDIRECTS\s*\)", helper.group(1)):
        problems.append("noRedirects() does not disable redirect following")
    begins = [m.start() for m in re.finditer(r"\bbeginHttpsUrl\s*\(", code)]
    sends = [m.start() for m in SEND.finditer(code)]
    if not begins:
        return problems + ["no beginHttpsUrl call found"]
    if len(sends) != len(begins):
        problems.append("%d beginHttpsUrl calls but %d requests" % (len(begins), len(sends)))
    for b in begins:
        nxt = [s for s in sends if s > b]
        if not nxt:
            problems.append("beginHttpsUrl at offset %d has no following request" % b)
            continue
        if not re.search(r"\bnoRedirects\s*\(\s*http\s*\)", code[b:nxt[0]]):
            problems.append("request after beginHttpsUrl at offset %d without noRedirects()" % b)
    return problems


def read():
    with open(os.path.join(ROOT, SRC), encoding="utf-8") as f:
        return f.read()


def test_every_request_disables_redirects():
    assert violations(read()) == []


def test_control_mutants_fail():
    code = read()
    # Dropping each noRedirects(http) call in turn must be caught.
    hits = [m.start() for m in re.finditer(r"\n\s*noRedirects\(http\);", code)]
    assert len(hits) == 5, hits
    for h in hits:
        end = code.index(";", h) + 1
        assert violations(code[:h] + code[end:]) != [], h
    # A helper that follows redirects must be caught.
    assert violations(code.replace("HTTPC_DISABLE_FOLLOW_REDIRECTS", "HTTPC_FORCE_FOLLOW_REDIRECTS", 1)) != []
    # A new request with no beginHttpsUrl/noRedirects pair must be caught.
    assert violations(code + "\nvoid extra(HTTPClient& http) { http.POST(\"x\"); }\n") != []


if __name__ == "__main__":
    test_every_request_disables_redirects()
    test_control_mutants_fail()
    print("ok")
    sys.exit(0)
