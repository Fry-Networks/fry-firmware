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

    # (a4) all prefixes are covered.
    with tempfile.TemporaryDirectory(dir=base) as d:
        for p in ("FEM", "IOT", "RDN", "BM", "IDM", "SDN", "AEM", "ISM", "SVN", "OSM"):
            write(d, "p/%s.txt" % p, rand_key(p) + "\n")
        rc, out = run(d, "")
        check("all 10 prefixes found", rc == 1 and out.count("FOUND ") == 10, out)

    # (a5) the allowlist file itself is not scanned.
    with tempfile.TemporaryDirectory(dir=base) as d:
        s = synthetic_key()
        rc, out_ = run(d, "%s\n" % s)
        check("allowlist file is not scanned", rc == 0, out_)

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

    # (c) widened forms: each must be caught, with masked output only.
    def body(n):
        return "".join(secrets.choice(ALNUM) for _ in range(n))

    forms = [
        ("31-char body", "FEM-" + body(31)),
        ("33-char body", "FEM-" + body(33)),
        ("28-char body", "IOT-" + body(28)),
        ("40-char body", "IOT-" + body(40)),
        ("lowercase prefix", "fem-" + body(32)),
        ("mixed-case prefix", "Iot-" + body(32)),
        ("underscore separator", "FEM_" + body(32)),
        ("percent-encoded separator", "FEM%2D" + body(32)),
        ("lowercase percent-encoded separator", "fem%2d" + body(33)),
        ("followed by a letter", "FEM-" + body(32) + "q"),
        ("followed by digits", "RDN-" + body(32) + "99"),
    ]
    for name, k in forms:
        with tempfile.TemporaryDirectory(dir=base) as d:
            write(d, "f/x.txt", "a\nkey: %s end\n" % k)
            rc, out = run(d, "")
            tail = k[len(k) // 2:]
            check("form caught: " + name, rc == 1 and "f/x.txt:2:" in out and k[:6] + "..." in out and tail not in out, "rc=%d %s" % (rc, out))

    # (c2) a NUL-containing file is scanned for printable runs, not skipped; output masked.
    with tempfile.TemporaryDirectory(dir=base) as d:
        k = rand_key("OSM")
        write(d, "img/fw.bin", b"\0\1\2\xff" + b"junk\0" + k.encode() + b"\0\0tail", mode="wb")
        rc, out = run(d, "")
        check("key inside a NUL-containing file is caught", rc == 1 and "img/fw.bin" in out and k[10:] not in out, "rc=%d %s" % (rc, out))
    with tempfile.TemporaryDirectory(dir=base) as d:
        write(d, "img/fw.bin", b"\0\1\2\xff" + os.urandom(4096), mode="wb")
        rc, out = run(d, "")
        check("random binary without a key stays clean", rc == 0, out)

    # (c3) near misses that must NOT be flagged.
    with tempfile.TemporaryDirectory(dir=base) as d:
        write(d, "n.txt", "FEM-" + body(27) + "\nFEM_API_TOKEN=abc\nmechanism_" + body(30) + "\nFEM-short\n")
        rc, out = run(d, "")
        check("27-char body, identifiers and in-word prefixes are not flagged", rc == 0, out)

    # (c4) an allowlisted entry only passes in its exact canonical form.
    with tempfile.TemporaryDirectory(dir=base) as d:
        s = synthetic_key()
        write(d, "v.txt", s.lower() + "\n" + s.replace("-", "_") + "\n" + s + "z\n" + s + "\n")
        rc, out = run(d, s + "\n")
        check("allowlisted key passes only in exact form", rc == 1 and out.count("FOUND ") == 3, out)

    # (b) the real repo tree is clean with the committed allowlist.
    r = subprocess.run([sys.executable, "-I", TOOL, "--root", os.path.join(HERE, "..")], capture_output=True, text=True)
    check("repository tree is clean", r.returncode == 0, r.stdout + r.stderr)

    print("FAILED: %s" % ", ".join(FAILS) if FAILS else "ALL PASSED")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
