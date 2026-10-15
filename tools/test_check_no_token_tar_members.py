# Tests for how tools/check_no_token.py treats tar members it cannot read. Dependency-free, same
# style as tools/test_check_no_token.py:
#
#   python3 tools/test_check_no_token_tar_members.py                   # test the sibling tool
#   python3 tools/test_check_no_token_tar_members.py <path-to-a-copy>  # test a specific copy
#
# An error reading one tar member must not end the scan of the members after it, and a tar that
# breaks part-way must never produce an OK: the member is reported UNREADABLE, a hit anywhere still
# exits 1, and unreadable members with no hit exit 2. Every "token" is random and handed to the tool
# only through an environment variable.
import contextlib
import importlib.util
import io
import os
import secrets
import subprocess
import sys
import tarfile
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


def tar_bytes(members, mode="w"):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as t:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def corrupt_crc_zip(marker):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("bad.bin", marker + b"\x00" * 200)
    data = buf.getvalue()
    i = data.index(marker)
    return data[:i] + bytes([data[i] ^ 0xFF]) + data[i + 1:]


def load_tool():
    spec = importlib.util.spec_from_file_location("check_no_token_under_test", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def write(path, data):
    with open(path, "wb") as f:
        f.write(data)
    return path


def main():
    tmp = tempfile.mkdtemp(prefix="no-token-tar-")
    token = "tok" + secrets.token_hex(16)
    env = {"T1": token}
    outputs = []

    def scan(path):
        rc, out = run(["--artifact", path, "--needle-env", "T1"], env)
        outputs.append(out)
        return rc, out

    clean = ("clean.txt", b"nothing to see " * 20)
    hit = ("deep/hit.bin", b"\x00" * 64 + token.encode() + b"\xff" * 64)
    big = ("big.bin", os.urandom(200000))

    # Controls first: a clean tar is OK and a tar holding the token still fails.
    rc, out = scan(write(os.path.join(tmp, "clean.tar"), tar_bytes([clean, big])))
    check("control: clean tar exits 0 with OK", rc == 0 and "check_no_token: OK" in out, out)
    rc, out = scan(write(os.path.join(tmp, "hit.tar"), tar_bytes([clean, hit])))
    check("control: tar holding the token exits 1", rc == 1 and "HIT T1" in out, out)

    # A plain tar cut off in the middle of a member: nothing was found, but the scan is incomplete.
    cut = tar_bytes([clean, big])
    rc, out = scan(write(os.path.join(tmp, "truncated.tar"), cut[:len(cut) // 2]))
    check("truncated tar, no hit: exit 2", rc == 2, "rc=%d out=%r" % (rc, out))
    check("truncated tar, no hit: member reported UNREADABLE", "UNREADABLE" in out, out)
    check("truncated tar, no hit: never prints OK", "check_no_token: OK" not in out, out)
    check("truncated tar, no hit: no traceback", "Traceback" not in out, out)

    # A hit read BEFORE the tar breaks is still reported, and so is the breakage.
    cut = tar_bytes([hit, big])
    rc, out = scan(write(os.path.join(tmp, "hit-then-truncated.tar"), cut[:len(cut) // 2]))
    check("hit then truncated tar: exit 1", rc == 1 and "HIT T1" in out, "rc=%d out=%r" % (rc, out))
    check("hit then truncated tar: breakage still reported", "UNREADABLE" in out, out)

    # A gzip stream cut off part-way through the tar.
    gz = tar_bytes([hit, big], "w:gz")
    rc, out = scan(write(os.path.join(tmp, "truncated.tar.gz"), gz[:len(gz) // 2]))
    check("truncated tar.gz: hit found and exit 1", rc == 1 and "HIT T1" in out,
          "rc=%d out=%r" % (rc, out))
    check("truncated tar.gz: breakage reported UNREADABLE", "UNREADABLE" in out, out)
    rc, out = scan(write(os.path.join(tmp, "truncated-clean.tar.gz"),
                         tar_bytes([clean, big], "w:gz")[:len(gz) // 2]))
    check("truncated tar.gz, no hit: exit 2 and never OK",
          rc == 2 and "check_no_token: OK" not in out, "rc=%d out=%r" % (rc, out))

    # An unreadable zip held by a tar must not hide a plain member after it.
    marker = b"BADMEMBER" + secrets.token_hex(8).encode()
    rc, out = scan(write(os.path.join(tmp, "zip-then-hit.tar.gz"),
                         tar_bytes([("bad.zip", corrupt_crc_zip(marker)), clean, hit], "w:gz")))
    check("tar: corrupt zip member then a hit: exit 1", rc == 1 and "HIT T1" in out and "hit.bin" in out,
          "rc=%d out=%r" % (rc, out))
    check("tar: corrupt zip member is reported UNREADABLE", "UNREADABLE" in out and "bad.zip" in out, out)

    # In process: one tar member whose read raises, followed by a member holding the token.
    mod = load_tool()
    real_extract = tarfile.TarFile.extractfile

    def make_failing(exc_type):
        def failing(self, member):
            name = member.name if hasattr(member, "name") else member
            if name == "bad.bin":
                raise exc_type("simulated read failure")
            return real_extract(self, member)
        return failing

    def scan_in_process(path, exc_type):
        old_argv, old_env = sys.argv, os.environ.get("T1")
        buf = io.StringIO()
        rc, err = None, ""
        tarfile.TarFile.extractfile = make_failing(exc_type)
        try:
            sys.argv = ["check_no_token.py", "--artifact", path, "--needle-env", "T1"]
            os.environ["T1"] = token
            with contextlib.redirect_stdout(buf):
                rc = mod.main()
        except BaseException as e:  # a crash is a failure of the checks below
            err = "%s: %s" % (type(e).__name__, e)
        finally:
            tarfile.TarFile.extractfile = real_extract
            sys.argv = old_argv
            if old_env is None:
                os.environ.pop("T1", None)
            else:
                os.environ["T1"] = old_env
        outputs.append(buf.getvalue())
        return rc, buf.getvalue(), err

    p = write(os.path.join(tmp, "bad-then-hit.tar"),
              tar_bytes([("bad.bin", b"filler " * 50), clean, ("deep/hit.bin", hit[1])], "w:gz"))
    for exc_type in (OSError, tarfile.ReadError, EOFError):
        rc, out, err = scan_in_process(p, exc_type)
        check("%s on one member, then a hit: exit 1" % exc_type.__name__, rc == 1,
              "rc=%r err=%s out=%r" % (rc, err, out))
        check("%s on one member: later member's hit still found" % exc_type.__name__,
              "HIT T1" in out and "hit.bin" in out, out)
        check("%s on one member: reported UNREADABLE" % exc_type.__name__,
              "UNREADABLE" in out and "bad.bin" in out, out)

    p = write(os.path.join(tmp, "bad-only.tar"),
              tar_bytes([("bad.bin", b"filler " * 50), clean], "w:gz"))
    rc, out, err = scan_in_process(p, OSError)
    check("unreadable member, no hit: exit 2 and never OK",
          rc == 2 and "check_no_token: OK" not in out, "rc=%r err=%s out=%r" % (rc, err, out))

    check("the token value never appears in any output", all(token not in o for o in outputs))

    print("\n%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
