#!/usr/bin/env python3
"""Fails if the ESP8266 OTA path's stack frames exceed their budget (4 KB loop stack, esp6 stack-overflow fix).

The ESP8266 runs loop() on a 4096 B stack (core cont.h CONT_STACKSIZE). The OTA manifest check and the image download
open a TLS connection from inside loop() -> fry_hwapi::tick() -> fry_ota::tick() -> checkNow() [-> downloadAndApply()],
and everything the connect needs (HTTPClient, BearSSL, lwIP, the SDK, an interrupt frame) sits BELOW those frames. On
the bench a 1920 B checkNow() frame overran the stack; with the frames below, the same path left ~350 B free. The
frame sizes exist only in the Xtensa compiler output (-fstack-usage), so this reads the .su files of a real build:

    PLATFORMIO_BUILD_FLAGS=-fstack-usage PLATFORMIO_BUILD_DIR=/some/scratch pio run -e esp8266
    python3 tools/check_esp8266_stack_budget.py /some/scratch/esp8266

Exit codes: 0 within budget, 1 over budget or a budgeted function not found (a rename must update this table), 2 no
.su files under the directory.

The budgets are ceilings with some slack over the committed code, not targets: loop 176 + hwapi tick 16 + ota tick 16 +
checkNow 112 + downloadAndApply 112 = 432 B on the path of a download. evaluateManifest() is not budgeted: it runs
between the manifest GET and the download, never under a connection.
"""
import argparse
import os
import re
import sys

# (label, regex on the demangled signature in the .su line, max frame in bytes or None)
FRAMES = [
    ("loop()", r"\bvoid loop\(\)", None),
    ("fry_hwapi::tick()", r"\bfry_hwapi::tick\(\)", None),
    ("fry_ota::tick()", r"\bfry_ota::tick\(\)", None),
    ("fry_ota::checkNow()", r"\bfry_ota::checkNow\(\)", 160),
    ("fry_ota downloadAndApply()", r"\bfry_ota::\{anonymous\}::downloadAndApply\(", 160),
]
# The frames that are on the stack together while a download's TLS connect runs.
PATH_BUDGET = 544

LINE = re.compile(r"^[^:\t]+:\d+:\d+:(.*)\t(\d+)\t(\w+)\s*$")


def read_su(root):
    rows = []
    for d, _, files in os.walk(root):
        for f in files:
            if f.endswith(".su"):
                with open(os.path.join(d, f), "r", errors="replace") as fh:
                    for line in fh:
                        m = LINE.match(line.rstrip("\n"))
                        if m:
                            rows.append((m.group(1), int(m.group(2))))
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("su_dir", help="build directory holding the .su files (searched recursively)")
    a = ap.parse_args()
    rows = read_su(a.su_dir)
    if not rows:
        print("no .su files (build with PLATFORMIO_BUILD_FLAGS=-fstack-usage) under %s" % a.su_dir)
        return 2
    bad = 0
    path = 0
    for label, rx, limit in FRAMES:
        sizes = [size for sig, size in rows if re.search(rx, sig)]
        if not sizes:
            print("  FAIL  %-28s not found in the .su files (renamed? update FRAMES)" % label)
            bad += 1
            continue
        size = max(sizes)
        path += size
        if limit is None:
            print("  ok    %-28s %5d B" % (label, size))
        elif size > limit:
            print("  FAIL  %-28s %5d B  > budget %d B" % (label, size, limit))
            bad += 1
        else:
            print("  ok    %-28s %5d B  (budget %d B)" % (label, size, limit))
    if bad == 0 and path > PATH_BUDGET:
        print("  FAIL  path sum %d B > budget %d B" % (path, PATH_BUDGET))
        bad += 1
    elif bad == 0:
        print("  ok    path sum %d B (budget %d B)" % (path, PATH_BUDGET))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
