# Tests for tools/check_device_key_shapes.py. Dependency-free:
#
#   python3 tools/test_check_device_key_shapes.py
#
# Exit 0 = all pass, 1 = a failure. No key-shaped literal appears in this file: every value is
# built at run time (a random one for the "unlisted" cases), and the tool's output is asserted
# never to contain more than the first 6 characters of it.
import os
import secrets
import string
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "check_device_key_shapes.py")
ALNUM = string.ascii_letters + string.digits
FAILS = []


def rand_key(prefix="FEM"):
    return prefix + "-" + "".join(secrets.choice(ALNUM) for _ in range(32))


def synthetic_key(prefix="FEM"):
    return prefix + "-" + "ab" * 16


def run(root, allow_text):
    allow = os.path.join(root, "tools", "device_key_fixtures.allow")
    os.makedirs(os.path.dirname(allow), exist_ok=True)
    with open(allow, "w") as fh:
        fh.write(allow_text)
    r = subprocess.run([sys.executable, "-I", TOOL, "--root", root], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else "  " + detail))
    if not cond:
        FAILS.append(name)


def write(root, rel, text, mode="w"):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, mode) as fh:
        fh.write(text)


def main():
    base = os.environ.get("TMPDIR") or tempfile.gettempdir()

    # (a1) unlisted random key-shaped string -> non-zero, masked output, file:line.
    with tempfile.TemporaryDirectory(dir=base) as d:
        k = rand_key()
        write(d, "src/a.txt", "line one\nvalue = %s;\n" % k)
        rc, out = run(d, "# empty\n")
        check("unlisted key fails", rc == 1, "rc=%d" % rc)
        check("output names file:line", "src/a.txt:2:" in out, out)
        check("output shows only 6 chars + ...", k[:6] + "..." in out, out)
        check("output never contains the string or its tail", k not in out and k[10:] not in out, "leak")
        check("random key labelled high-entropy", "HIGH-ENTROPY" in out, out)

    # (a2) allowlisted synthetic key -> exit 0.
    with tempfile.TemporaryDirectory(dir=base) as d:
        s = synthetic_key()
        write(d, "t/test.cpp", 'const char k[] = "%s";\n' % s)
        rc, out = run(d, "# fixtures\n%s\n" % s)
        check("allowlisted key passes", rc == 0, "rc=%d %s" % (rc, out))

    # (a3) a different key in a file next to an allowlisted one still fails.
    with tempfile.TemporaryDirectory(dir=base) as d:
        s, k = synthetic_key(), rand_key("IOT")
        write(d, "a.md", "%s and %s\n" % (s, k))
        rc, out = run(d, "%s\n" % s)
        check("unlisted next to listed fails", rc == 1 and k not in out, out)

    # (a4) all prefixes are covered; 31 chars and 33 chars are not key-shaped.
    with tempfile.TemporaryDirectory(dir=base) as d:
        for p in ("FEM", "IOT", "RDN", "BM", "IDM", "SDN", "AEM", "ISM", "SVN", "OSM"):
            write(d, "p/%s.txt" % p, rand_key(p) + "\n")
        rc, out = run(d, "")
        check("all 10 prefixes found", rc == 1 and out.count("FOUND ") == 10, out)
    with tempfile.TemporaryDirectory(dir=base) as d:
        write(d, "short.txt", rand_key()[:-1] + "\n")
        write(d, "long.txt", rand_key() + "x\n")
        rc, out = run(d, "")
        check("31 and 33 char strings are not flagged", rc == 0, out)

    # (a5) binary files skipped; the allowlist file itself is not scanned.
    with tempfile.TemporaryDirectory(dir=base) as d:
        write(d, "blob.bin", b"\0\1\2" + rand_key().encode(), mode="wb")
        rc, out = run(d, "# no entries\n")
        check("binary file skipped", rc == 0, out)

    # (a6) a random-looking allowlist entry is rejected (exit 2), even if the string is present.
    with tempfile.TemporaryDirectory(dir=base) as d:
        k = rand_key()
        write(d, "a.txt", k + "\n")
        rc, out = run(d, k + "\n")
        check("random-looking allowlist entry rejected", rc == 2 and k not in out, "rc=%d %s" % (rc, out))

    # (a7) missing allowlist -> exit 2.
    with tempfile.TemporaryDirectory(dir=base) as d:
        r = subprocess.run([sys.executable, "-I", TOOL, "--root", d], capture_output=True, text=True)
        check("missing allowlist is an error", r.returncode == 2, "rc=%d" % r.returncode)

    # (b) the real repo tree is clean with the committed allowlist.
    r = subprocess.run([sys.executable, "-I", TOOL, "--root", os.path.join(HERE, "..")], capture_output=True, text=True)
    check("repository tree is clean", r.returncode == 0, r.stdout + r.stderr)

    print("FAILED: %s" % ", ".join(FAILS) if FAILS else "ALL PASSED")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
