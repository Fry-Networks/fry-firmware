# Tests for tools/scan_identity.py. Dependency-free on purpose: this repo has no Python test
# runner (test/ is Unity C++ plus one node --test file), and adding pytest for one tool would be a
# bigger change than the tool.
#
#   py -3 tools/test_scan_identity.py                 # test the sibling scan_identity.py
#   py -3 tools/test_scan_identity.py <path-to-copy>  # test a specific copy (e.g. a pre-fix backup)
#
# Exit 0 = all pass, 1 = a failure. The second form is how the fix was proven: the pre-fix scanner
# fails cases 1, 2 and 4 below, the post-fix one passes all five.
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "scan_identity.py")

# A real leak, built at runtime so this test file does not itself contain the shape it looks for
# (which is the very trap the scanner had). chr(92) is a backslash.
BS = chr(92)
LEAK_TEXT = "C:" + BS + "Users" + BS + "someoperator" + BS + "project" + BS + "main.cpp"

passed = 0
failed = 0


def run(*args):
    proc = subprocess.run([sys.executable, SCANNER] + list(args),
                          capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def check(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print("  PASS  %s" % name)
    else:
        failed += 1
        print("  FAIL  %s%s" % (name, ("\n        " + detail.replace("\n", "\n        ")) if detail else ""))


print("testing scanner: %s" % SCANNER)

tmp = tempfile.mkdtemp(prefix="scanid-")
try:
    # ---- case 1: a directory argument is walked, not rejected -------------------------------
    # Pre-fix this raised PermissionError (Windows) / IsADirectoryError (POSIX) and produced a
    # traceback, so the tool could not be pointed at a source tree at all.
    clean_dir = os.path.join(tmp, "clean")
    os.makedirs(clean_dir)
    with open(os.path.join(clean_dir, "a.txt"), "w") as f:
        f.write("nothing to see here\n")
    with open(os.path.join(clean_dir, "b.txt"), "w") as f:
        f.write("also fine\n")
    rc, out = run(clean_dir)
    check("directory argument is accepted and walked",
          rc == 0 and "Traceback" not in out and "a.txt" in out and "b.txt" in out,
          "rc=%d\n%s" % (rc, out))

    # ---- case 2: the scanner does not report itself ------------------------------------------
    # Its own needle literals and the drive-letter path example in its header always matched, so
    # any gate built on scanning a source tree failed permanently.
    # NB: this comment deliberately does NOT spell out that example path. An earlier draft did,
    # and the scanner correctly flagged THIS file - which is the tool working, not a false hit.
    rc, out = run(HERE)
    verdicts = {}  # realpath -> verdict text, parsed from "[scan_identity] <path>: <verdict>"
    for line in out.splitlines():
        if not line.startswith("[scan_identity] ") or ": " not in line:
            continue
        body = line[len("[scan_identity] "):]
        path, verdict = body.rsplit(": ", 1)
        verdicts[os.path.realpath(path)] = verdict
    own = verdicts.get(os.path.realpath(SCANNER))
    check("scanner excludes its own source when scanning tools/",
          own is not None and "skipped" in own,
          "rc=%d\nverdict for the scanner itself: %r" % (rc, own))

    # ---- case 3: POSITIVE CONTROL - a real leak is still caught -------------------------------
    # Without this, cases 1 and 2 could be satisfied by a scanner that detects nothing at all.
    leak_dir = os.path.join(tmp, "leaky")
    os.makedirs(leak_dir)
    with open(os.path.join(leak_dir, "leak.txt"), "w") as f:
        f.write(LEAK_TEXT + "\n")
    rc, out = run(leak_dir)
    check("positive control: a real Windows path is still detected",
          rc == 1 and "hit(s)" in out,
          "rc=%d\n%s" % (rc, out))

    # ---- case 4: an unreadable path is neither 'clean' nor a 'leak' ---------------------------
    # Pre-fix a missing file raised FileNotFoundError, exiting 1 - indistinguishable from a leak.
    rc, out = run(os.path.join(tmp, "does-not-exist.bin"))
    check("missing path exits 2, not 0 or 1",
          rc == 2 and "Traceback" not in out,
          "rc=%d\n%s" % (rc, out))

    # ---- case 5: a clean single file still passes --------------------------------------------
    rc, out = run(os.path.join(clean_dir, "a.txt"))
    check("clean single file exits 0",
          rc == 0 and "PASS" in out,
          "rc=%d\n%s" % (rc, out))
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print("%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
