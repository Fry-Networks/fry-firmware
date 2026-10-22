# Tests for tools/check_esp8266_stack_budget.py. Dependency-free, same style as tools/test_check_prod_channel.py:
#
#   python3 tools/test_check_esp8266_stack_budget.py                  # fixtures only
#   python3 tools/test_check_esp8266_stack_budget.py --su DIR         # also run the tool on a real -fstack-usage build
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
if "--su" in args:
    real = args[args.index("--su") + 1]
TOOL = os.path.join(HERE, "check_esp8266_stack_budget.py")

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


def su(rows):
    # gcc -fstack-usage: <file>:<line>:<col>:<signature>\t<bytes>\t<static|dynamic|...>
    return "".join("%s\t%d\tstatic\n" % (sig, n) for sig, n in rows)


def write(dirpath, name, text):
    os.makedirs(dirpath, exist_ok=True)
    with open(os.path.join(dirpath, name), "w") as f:
        f.write(text)


def run(d):
    proc = subprocess.run([sys.executable, TOOL, d], capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


MAIN = ("main.cpp:212:6:void loop()", 176)
HW = ("hardwareapi_client.cpp:306:6:void fry_hwapi::tick()", 16)
OTA_TICK = ("ota_client.cpp:645:6:void fry_ota::tick()", 16)
CHECK = "ota_client.cpp:476:6:bool fry_ota::checkNow()"
DL = "ota_client.cpp:192:31:bool fry_ota::{anonymous}::downloadAndApply(const String&, const String&, const String&)"


def tree(tmp, name, check_n, dl_n, extra=(), loop_n=176):
    d = os.path.join(tmp, name)
    write(d, "main.cpp.su", su([(MAIN[0], loop_n)]))
    write(d, "hardwareapi_client.cpp.su", su([HW]))
    write(d, "ota_client.cpp.su", su([OTA_TICK, (CHECK, check_n), (DL, dl_n)] + list(extra)))
    return d


def main():
    tmp = tempfile.mkdtemp(prefix="stack-budget-")
    try:
        # the bench numbers of 54e6358 (download inlined into checkNow) and of 05ffb66
        rc, out = run(tree(tmp, "inlined", 1920, 0))
        check("checkNow 1920 B (download inlined) fails", rc == 1 and "FAIL" in out and "1920" in out, out)
        rc, out = run(tree(tmp, "noinline", 560, 512))
        check("checkNow 560 B + download 512 B (05ffb66) fails", rc == 1 and "560" in out, out)
        rc, out = run(tree(tmp, "now", 112, 112))
        check("checkNow 112 B + download 112 B passes", rc == 0 and "FAIL" not in out, out)
        rc, out = run(tree(tmp, "edge", 160, 160))
        check("checkNow and download at their own budgets still pass", rc == 0, out)
        rc, out = run(tree(tmp, "loopgrew", 160, 160, loop_n=200))
        check("loop() growing (not budgeted alone) fails through the path sum", rc == 1 and "path sum" in out, out)
        # a decision helper that is NOT budgeted must not fail the check, however large
        rc, out = run(tree(tmp, "helper", 112, 112, [("ota_client.cpp:600:6:bool fry_ota::evaluateManifest()", 4000)]))
        check("an unbudgeted decision frame is ignored", rc == 0, out)
        # controls: the tool must not pass on nothing, nor on a renamed function
        empty = os.path.join(tmp, "empty")
        os.makedirs(empty)
        rc, out = run(empty)
        check("no .su files -> exit 2, not a pass", rc == 2, out)
        d = os.path.join(tmp, "renamed")
        write(d, "main.cpp.su", su([MAIN]))
        write(d, "hardwareapi_client.cpp.su", su([HW]))
        write(d, "ota_client.cpp.su", su([OTA_TICK, ("ota_client.cpp:476:6:bool fry_ota::checkOnce()", 112), (DL, 112)]))
        rc, out = run(d)
        check("a budgeted function missing from the .su files fails", rc == 1 and "not found" in out, out)

        if real:
            rc, out = run(real)
            check("real build %s is within budget" % real, rc == 0, out)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
