# Tests that tools/scan_identity.py strips whitespace from each FRY_SCAN_NEEDLES entry before it
# searches for it. Dependency-free, same style as tools/test_scan_identity.py:
#
#   python3 tools/test_scan_identity_needle_strip.py                 # test the sibling scanner
#   python3 tools/test_scan_identity_needle_strip.py <path-to-copy>  # test a specific copy
#
# "alice, bob" must search for "bob", not " bob": the scanner already filtered on the stripped
# entry, but used to encode the unstripped one, so a padded needle silently found nothing.
# Exit 0 = all pass, 1 = a failure.
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "scan_identity.py")

passed = 0
failed = 0


def check(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print("  PASS  %s" % name)
    else:
        failed += 1
        print("  FAIL  %s  %s" % (name, detail))


def scan(needles, content):
    """Runs the scanner on a one-file directory, with FRY_SCAN_NEEDLES set to needles."""
    d = tempfile.mkdtemp(prefix="scanid-strip-")
    with open(os.path.join(d, "sample.txt"), "wb") as f:
        f.write(content)
    env = dict(os.environ)
    env["FRY_SCAN_NEEDLES"] = needles
    proc = subprocess.run([sys.executable, SCANNER, d], capture_output=True, text=True, env=env)
    return proc.returncode, proc.stdout + proc.stderr


print("testing scanner: %s" % SCANNER)

# The needles sit INSIDE a longer word, so only the stripped spelling can match them.
rc, out = scan("alice, bob", b"xxbobyy")
check("leading space: ' bob' is searched as 'bob'", rc == 1 and "bob" in out, "rc=%d %s" % (rc, out))

rc, out = scan("alice ,bob", b"xxalicezz")
check("trailing space: 'alice ' is searched as 'alice'", rc == 1 and "alice" in out, "rc=%d %s" % (rc, out))

rc, out = scan("alice,\tbob", b"xxbobyy")
check("leading tab: tab-bob is searched as 'bob'", rc == 1 and "bob" in out, "rc=%d %s" % (rc, out))

rc, out = scan("alice,  bob  ", b"xxbobyy")
check("padding on both sides is removed", rc == 1 and "bob" in out, "rc=%d %s" % (rc, out))

# Controls: stripping must neither invent matches nor lose the plain case.
rc, out = scan("alice, ,\t,bob", b"some clean text with spaces\tand a tab\n")
check("blank and whitespace-only entries add no needle", rc == 0, "rc=%d %s" % (rc, out))

rc, out = scan("alice,bob", b"xxbobyy")
check("an unpadded needle is still found", rc == 1 and "bob" in out, "rc=%d %s" % (rc, out))

rc, out = scan("alice, bob", b"alicX bo b")
check("near-miss text is not reported", rc == 0, "rc=%d %s" % (rc, out))

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
