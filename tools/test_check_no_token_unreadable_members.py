# Tests for how tools/check_no_token.py treats zip members it cannot read. Dependency-free, same
# style as tools/test_check_no_token.py:
#
#   python3 tools/test_check_no_token_unreadable_members.py                   # test the sibling tool
#   python3 tools/test_check_no_token_unreadable_members.py <path-to-a-copy>  # test a specific copy
#
# A member whose read fails (bad CRC, encrypted, unsupported compression method) must never end the
# scan and never produce an OK: the report names it as UNREADABLE, a hit anywhere still exits 1,
# an unreadable member with no hit exits 2, and a read error inside the planted control exits 3.
# Every "token" is random and handed to the tool only through an environment variable.
import contextlib
import importlib.util
import io
import os
import secrets
import struct
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "check_no_token.py")

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


def run(args, env_extra=None):
    env = dict(os.environ)
    env.update(env_extra or {})
    proc = subprocess.run([sys.executable, TOOL] + args, capture_output=True, text=True, env=env)
    return proc.returncode, proc.stdout + proc.stderr


def zip_bytes(members):
    """Members under deep/ are deflated, so a token in them is invisible to a raw scan of the zip."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for name, data in members:
            z.writestr(name, data, zipfile.ZIP_DEFLATED if name.startswith("deep/") else zipfile.ZIP_STORED)
    return buf.getvalue()


def flip_payload_byte(data, marker):
    """Changes one byte of a stored member's payload, so its CRC-32 no longer matches."""
    i = data.index(marker)
    return data[:i] + bytes([data[i] ^ 0xFF]) + data[i + 1:]


def patch_member(data, name, flag_or=0, method=None):
    """Rewrites the general-purpose flag bits and/or compression method in both headers."""
    buf = bytearray(data)
    nm = name.encode()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        local = z.getinfo(name).header_offset
    cd = buf.find(b"PK\x01\x02")
    while cd != -1 and bytes(buf[cd + 46:cd + 46 + len(nm)]) != nm:
        cd = buf.find(b"PK\x01\x02", cd + 1)
    assert cd != -1 and buf[local:local + 4] == b"PK\x03\x04"
    if flag_or:
        for pos in (local + 6, cd + 8):
            struct.pack_into("<H", buf, pos, struct.unpack_from("<H", buf, pos)[0] | flag_or)
    if method is not None:
        for pos in (local + 8, cd + 10):
            struct.pack_into("<H", buf, pos, method)
    return bytes(buf)


def load_tool():
    spec = importlib.util.spec_from_file_location("check_no_token_under_test", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    tmp = tempfile.mkdtemp(prefix="no-token-unreadable-")
    token = "tok" + secrets.token_hex(16)
    env = {"T1": token}
    outputs = []

    def scan(path, extra=None):
        rc, out = run(["--artifact", path, "--needle-env", "T1"] + (extra or []), env)
        outputs.append(out)
        return rc, out

    bad_marker = b"BADMEMBER" + secrets.token_hex(8).encode()
    bad_payload = bad_marker + b"\x00" * 200
    clean = ("clean.txt", b"nothing to see " * 20)
    hit = ("deep/hit.bin", b"\x00" * 64 + token.encode() + b"\xff" * 64)

    def damage_corrupt(z):
        return flip_payload_byte(z, bad_marker)

    def damage_encrypted(z):
        return patch_member(z, "bad.bin", flag_or=0x1)

    def damage_unsupported(z):
        return patch_member(z, "bad.bin", method=99)

    kinds = [("corrupt-crc", damage_corrupt), ("encrypted", damage_encrypted),
             ("unsupported-method", damage_unsupported)]

    for kind, damage in kinds:
        # Errors only: a single zip file, the unreadable member first, a clean member after it.
        p = os.path.join(tmp, "%s-only.zip" % kind)
        with open(p, "wb") as f:
            f.write(damage(zip_bytes([("bad.bin", bad_payload), clean])))
        rc, out = scan(p)
        check("%s, no hit: exit 2" % kind, rc == 2, "rc=%d out=%r" % (rc, out))
        check("%s, no hit: member reported UNREADABLE" % kind,
              "UNREADABLE" in out and "bad.bin" in out, out)
        check("%s, no hit: never prints OK" % kind, "check_no_token: OK" not in out, out)
        check("%s, no hit: no traceback" % kind, "Traceback" not in out, out)

        # A hit in a member AFTER the unreadable one must still be found.
        p = os.path.join(tmp, "%s-then-hit.zip" % kind)
        with open(p, "wb") as f:
            f.write(damage(zip_bytes([("bad.bin", bad_payload), clean, hit])))
        rc, out = scan(p)
        check("%s then hit: exit 1" % kind, rc == 1, "rc=%d out=%r" % (rc, out))
        check("%s then hit: hit found after the bad member" % kind,
              "HIT T1 in" in out and "hit.bin" in out, out)
        check("%s then hit: bad member still reported" % kind, "UNREADABLE" in out, out)
        check("%s then hit: no traceback" % kind, "Traceback" not in out, out)

    # Nested: an unreadable member inside a zip held by another zip.
    inner = flip_payload_byte(zip_bytes([("bad.bin", bad_payload), clean]), bad_marker)
    p = os.path.join(tmp, "nested.zip")
    with open(p, "wb") as f:
        f.write(zip_bytes([("inner.zip", inner)]))
    rc, out = scan(p)
    check("nested corrupt member: exit 2 and never OK",
          rc == 2 and "check_no_token: OK" not in out, "rc=%d out=%r" % (rc, out))

    # Controls: a clean zip is still OK, and the same zip with a hit still fails.
    p = os.path.join(tmp, "clean.zip")
    with open(p, "wb") as f:
        f.write(zip_bytes([clean, ("other.txt", b"more clean bytes")]))
    rc, out = scan(p)
    check("control: clean zip exits 0 with OK", rc == 0 and "check_no_token: OK" in out, out)
    rc, out = scan(p, ["--plant-control"])
    check("control: planted control passes on a clean zip", rc == 0 and "control OK" in out, out)
    p = os.path.join(tmp, "hit.zip")
    with open(p, "wb") as f:
        f.write(zip_bytes([clean, hit]))
    rc, out = scan(p)
    check("control: zip with a planted hit exits 1", rc == 1 and "HIT T1" in out, out)

    # A read error inside the planted control means the scan cannot be trusted: exit 3.
    mod = load_tool()
    p = os.path.join(tmp, "for-control.zip")
    with open(p, "wb") as f:
        f.write(zip_bytes([clean]))
    real_read = zipfile.ZipFile.read

    def failing_read(self, name, pwd=None):
        raise RuntimeError("simulated read failure")

    old_argv, old_env = sys.argv, os.environ.get("T1")
    buf = io.StringIO()
    rc = None
    err = ""
    zipfile.ZipFile.read = failing_read
    try:
        sys.argv = ["check_no_token.py", "--artifact", p, "--needle-env", "T1", "--plant-control"]
        os.environ["T1"] = token
        with contextlib.redirect_stdout(buf):
            rc = mod.main()
    except BaseException as e:  # a crash is a failure of the check below, not of the harness
        err = "%s: %s" % (type(e).__name__, e)
    finally:
        zipfile.ZipFile.read = real_read
        sys.argv = old_argv
        if old_env is None:
            os.environ.pop("T1", None)
        else:
            os.environ["T1"] = old_env
    outputs.append(buf.getvalue())
    check("unreadable member inside the planted control: exit 3", rc == 3,
          "rc=%r err=%s out=%r" % (rc, err, buf.getvalue()))
    check("unreadable control never prints OK", "check_no_token: OK" not in buf.getvalue(), buf.getvalue())

    check("the token value never appears in any output", all(token not in o for o in outputs))

    print("\n%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
