# Tests for tools/bench_guard.py (used by tools/fry_prebuild.py): the bench fault macro may only reach
# a build that the fault-images workflow marked, only on the ESP32-family production envs, only with a
# fault number the bench uses (2-5), and never through FRY_BENCH_IMAGE directly.
#
#   python3 tools/test_bench_guard.py        # exit 0 = all pass, 1 = a failure
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
passed = 0
failed = 0


def check(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
    else:
        failed += 1
        print("  FAIL  %s %s" % (name, detail))


def load():
    path = os.path.join(HERE, "bench_guard.py")
    if not os.path.isfile(path):
        return None
    spec = importlib.util.spec_from_file_location("bench_guard", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


g = load()
check("bench_guard.py exists", g is not None)
if g is None:
    print("%d passed, %d failed" % (passed, failed))
    sys.exit(1)

MARK = {"FRY_BENCH_BUILD": "1"}

# normal builds: nothing to say, with or without the marker
check("normal build, no flags", g.check("esp32s3", "-DFOO=1", {}) is None)
check("normal build, marker set", g.check("esp32s3", "", MARK) is None)
check("esp8266 normal", g.check("esp8266", "", {}) is None)
check("a lookalike name is not the macro", g.check("esp32s3", "-DFRY_BENCH_FAULTY=1", {}) is None)

# the macro without the marker is refused, whatever the value or env
for env in ("esp32", "esp32s3", "esp32c3", "esp8266", "esp32s3_test"):
    check("refused without marker: " + env, g.check(env, "-DFRY_BENCH_FAULT=3", {}) is not None)
check("refused with a wrong marker value", g.check("esp32s3", "-DFRY_BENCH_FAULT=3", {"FRY_BENCH_BUILD": "0"}) is not None)
check("refused with an empty marker", g.check("esp32s3", "-DFRY_BENCH_FAULT=3", {"FRY_BENCH_BUILD": ""}) is not None)

# with the marker: only ESP32-family production envs, values 2-5
for v in ("2", "3", "4", "5"):
    check("allowed value " + v, g.check("esp32s3", "-DFRY_BENCH_FAULT=" + v, MARK) is None)
for v in ("0", "1", "6", "9", "10", "", "x", "3x", "-1"):
    check("refused value %r" % v, g.check("esp32s3", "-DFRY_BENCH_FAULT=" + v, MARK) is not None)
check("allowed on esp32", g.check("esp32", "-DFRY_BENCH_FAULT=3", MARK) is None)
check("allowed on esp32c3", g.check("esp32c3", "-DFRY_BENCH_FAULT=3", MARK) is None)
check("refused on esp8266", g.check("esp8266", "-DFRY_BENCH_FAULT=3", MARK) is not None)
check("refused on a test env", g.check("esp32s3_test", "-DFRY_BENCH_FAULT=3", MARK) is not None)
check("refused when given with two values", g.check("esp32s3", "-DFRY_BENCH_FAULT=3 -DFRY_BENCH_FAULT=4", MARK) is not None)
check("the same value seen twice is fine (env var folded into build_flags)", g.check("esp32s3", "-DFRY_BENCH_FAULT=3 -DFRY_BENCH_FAULT=3", MARK) is None)

# FRY_BENCH_IMAGE is only ever defined by include/bench_fault.h
check("FRY_BENCH_IMAGE alone is refused", g.check("esp32s3", "-DFRY_BENCH_IMAGE=1", MARK) is not None)
check("FRY_BENCH_IMAGE with the fault is refused", g.check("esp32s3", "-DFRY_BENCH_FAULT=3 -DFRY_BENCH_IMAGE=1", MARK) is not None)

# the macro in the middle of other flags, as PLATFORMIO_BUILD_FLAGS and build_flags are joined
check("found among other flags", g.check("esp32s3", "-O2 -DFOO -DFRY_BENCH_FAULT=5 -Wall", {}) is not None)
check("allowed among other flags", g.check("esp32s3", "-O2 -DFOO -DFRY_BENCH_FAULT=5 -Wall", MARK) is None)

print("%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
