# Tests for tools/check_prod_channel.py. Dependency-free, same style as tools/test_scan_identity.py:
#
#   python3 tools/test_check_prod_channel.py                   # test the sibling check_prod_channel.py
#   python3 tools/test_check_prod_channel.py <path-to-a-copy>  # test a specific copy
#   python3 tools/test_check_prod_channel.py --images PROD.bin TEST.bin   # also run it on real builds
#
# Exit 0 = all pass, 1 = a failure.
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
args = sys.argv[1:]
real = None
if "--images" in args:
    i = args.index("--images")
    real = args[i + 1:i + 3]
    args = args[:i]
TOOL = os.path.abspath(args[0]) if args else os.path.join(HERE, "check_prod_channel.py")
URL = b"https://github.com/Fry-Networks/fry-firmware/releases/download/ota-test/manifest.json"

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


def run(*a):
    proc = subprocess.run([sys.executable, TOOL] + list(a), capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def main():
    tmp = tempfile.mkdtemp(prefix="prod-channel-")
    try:
        prod = os.path.join(tmp, "firmware-esp32.bin")
        test = os.path.join(tmp, "firmware-esp32_test.bin")
        with open(prod, "wb") as f:
            f.write(os.urandom(2048) + b"https://github.com/Fry-Networks/fry-firmware/releases/latest/"
                    b"download/manifest.json" + os.urandom(2048))
        with open(test, "wb") as f:
            f.write(os.urandom(2048) + URL + os.urandom(2048))

        rc, out = run(prod)
        check("a prod image passes", rc == 0, out)
        rc, out = run(test)
        check("a test-channel image fails the prod check", rc == 1 and "FAIL" in out, out)
        rc, out = run(prod, test)
        check("one bad image in a batch fails the batch", rc == 1, out)
        rc, out = run("--expect-test", test)
        check("the positive control passes on a test image", rc == 0, out)
        rc, out = run("--expect-test", prod)
        check("the positive control fails on a prod image", rc == 1 and "CONTROL FAILED" in out, out)
        rc, out = run(os.path.join(tmp, "missing.bin"))
        check("a missing image is a usage error, not a pass", rc == 2, out)

        if real:
            rc, out = run(real[0])
            check("real prod build %s passes" % os.path.basename(real[0]), rc == 0, out)
            rc, out = run("--expect-test", real[1])
            check("real *_test build %s is caught" % os.path.basename(real[1]), rc == 0, out)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
