# Tests for tools/check_no_token.py. Dependency-free, same style as tools/test_scan_identity.py:
#
#   python3 tools/test_check_no_token.py                   # test the sibling check_no_token.py
#   python3 tools/test_check_no_token.py <path-to-a-copy>  # test a specific copy
#
# Exit 0 = all pass, 1 = a failure. Every "token" here is random and generated at run time, handed
# to the tool ONLY through an environment variable, and asserted never to appear in its output.
import io
import os
import secrets
import shutil
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


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def github_pages_like(path, member_bytes):
    """A zip holding artifact.tar holding the file - the shape of a github-pages artifact."""
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as t:
        info = tarfile.TarInfo("flash/fw/firmware-esp32.bin")
        info.size = len(member_bytes)
        t.addfile(info, io.BytesIO(member_bytes))
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("artifact.tar", tar_buf.getvalue())


def main():
    tmp = tempfile.mkdtemp(prefix="no-token-")
    token = "T0K" + secrets.token_hex(20)
    other = "OTHER" + secrets.token_hex(12)
    try:
        print("header mode:")
        empty = os.path.join(tmp, "empty", "fry_secrets.h")
        write(empty, b'#pragma once\n#define FRY_API_TOKEN ""\n')
        rc, out = run(["--header", empty])
        check("an empty token passes", rc == 0, out)

        full = os.path.join(tmp, "full", "fry_secrets.h")
        write(full, ('#pragma once\n#define FRY_API_TOKEN "%s"\n' % token).encode())
        rc, out = run(["--header", full])
        check("a compiled-in token fails", rc == 1, out)
        check("reports its length, not its value", str(len(token)) in out and token not in out, out)

        rc, out = run(["--header", os.path.join(tmp, "missing.h")])
        check("a missing header is a usage error", rc == 2, out)

        print("artifact mode:")
        clean_dir = os.path.join(tmp, "clean")
        write(os.path.join(clean_dir, "firmware-esp32.bin"), os.urandom(4096))
        github_pages_like(os.path.join(clean_dir, "github-pages.zip"), os.urandom(2048))
        env = {"IV1_TEST_TOKEN_A": token, "IV1_TEST_TOKEN_B": other}

        rc, out = run(["--artifact", clean_dir, "--needle-env", "IV1_TEST_TOKEN_A", "IV1_TEST_TOKEN_B",
                       "--plant-control"], env)
        check("clean artifacts pass with the planted control", rc == 0, out)
        check("the control ran", "control OK" in out, out)
        check("nested members were scanned", "0 hits" in out, out)

        dirty_dir = os.path.join(tmp, "dirty")
        write(os.path.join(dirty_dir, "plain.bin"), b"\x00" * 100 + token.encode() + b"\x00" * 100)
        github_pages_like(os.path.join(dirty_dir, "github-pages.zip"),
                          b"\xff" * 300 + other.encode() + b"\xff" * 300)
        rc, out = run(["--artifact", dirty_dir, "--needle-env", "IV1_TEST_TOKEN_A", "IV1_TEST_TOKEN_B"], env)
        check("a token in a plain file fails", rc == 1 and "HIT IV1_TEST_TOKEN_A" in out, out)
        check("a token inside zip -> tar is found with its member path",
              "HIT IV1_TEST_TOKEN_B" in out and "artifact.tar!flash/fw/firmware-esp32.bin" in out, out)
        check("no value is ever printed", token not in out and other not in out, out)

        rc, out = run(["--artifact", clean_dir, "--needle-env", "IV1_TEST_UNSET_VAR"], env)
        check("an unset needle variable is a usage error", rc == 2, out)
        rc, out = run(["--artifact", clean_dir, "--needle-env", "IV1_TEST_SHORT"], {"IV1_TEST_SHORT": "abc"})
        check("a too-short needle is a usage error", rc == 2, out)
        rc, out = run(["--artifact", os.path.join(tmp, "nope"), "--needle-env", "IV1_TEST_TOKEN_A"], env)
        check("a missing artifact path is a usage error", rc == 2, out)
        rc, out = run(["--artifact", clean_dir, "--needle", token], env)
        check("there is no way to pass a value on argv", rc != 0, out)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
