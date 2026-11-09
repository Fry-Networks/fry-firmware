#!/usr/bin/env python3
"""Static-RAM gate for the opt-in olostep ESP8266 image, from saved `size -A` outputs. Pure Python; no PlatformIO.

env:esp8266_olostep replaces extra_scripts, so it does not run tools/check_esp8266_ram_budget.py (and that script only gates
esp8266 and esp8266_test anyway). This script gives the olostep image its own gate, run by hand or before a release:

  python3 tools/check_esp8266_olostep_ram.py --prod-size prod-size-A.txt --olostep-size olo-size-A.txt [--max-delta N]

RULE: olostep total = .data + .rodata + .bss (the parsers of check_esp8266_ram_budget.py, loaded with importlib).
  FAIL (exit 1) if the olostep total exceeds BUDGET_BYTES (34408, the prod budget) + OLOSTEP_MAX_DELTA.
  FAIL (exit 1) if either input is missing or unmeasurable: a guard that cannot measure must not pass.

OLOSTEP_MAX_DELTA is deliberately UNSET (None). The opt-in module adds code, so the prod budget alone is not a valid olostep
limit, but no olostep build has been measured yet (its private module is not available where this was written). Guessing a
number would either gate nothing or fail a good build. So until it is set from the first real measurement (olostep total minus
prod total, plus a small margin, in the same commit), the script refuses to claim PASS and exits 3 UNCALIBRATED. --max-delta N
overrides the constant for a single run.

Exit codes: 0 within budget, 1 over budget or unmeasurable, 2 usage, 3 uncalibrated (no delta set).
"""
import argparse
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OLOSTEP_MAX_DELTA = None  # bytes allowed above the prod BUDGET_BYTES; set from the first real olostep measurement


def _load_prod():
    spec = importlib.util.spec_from_file_location("check_esp8266_ram_budget", os.path.join(HERE, "check_esp8266_ram_budget.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


prod = _load_prod()


def verdict(prod_total, olo_total, max_delta):
    """(ok, message). max_delta must be an int."""
    limit = prod.BUDGET_BYTES + max_delta
    head = "olostep RAM: %d B used, prod %d B, limit %d B (prod budget %d + delta %d)" % (
        olo_total, prod_total, limit, prod.BUDGET_BYTES, max_delta)
    if olo_total <= limit:
        return True, head + ", %d B spare" % (limit - olo_total)
    return False, head + ", EXCEEDED by %d B" % (olo_total - limit)


def measure(path):
    with open(path, "r", errors="replace") as f:
        return prod.ram_bytes(f.read())


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--prod-size", required=True, help="saved `size -A` of the esp8266 build")
    ap.add_argument("--olostep-size", required=True, help="saved `size -A` of the esp8266_olostep build")
    ap.add_argument("--max-delta", type=int, default=None, help="override OLOSTEP_MAX_DELTA")
    a = ap.parse_args(argv)
    try:
        prod_total = measure(a.prod_size)
        olo_total = measure(a.olostep_size)
    except (prod.Unmeasurable, OSError) as e:
        print("olostep RAM: cannot measure: %s" % e)
        return 1
    delta = a.max_delta if a.max_delta is not None else OLOSTEP_MAX_DELTA
    if delta is None:
        print("olostep RAM: UNCALIBRATED (OLOSTEP_MAX_DELTA unset): prod %d B, olostep %d B, delta %d B" % (
            prod_total, olo_total, olo_total - prod_total))
        return 3
    ok, msg = verdict(prod_total, olo_total, delta)
    print(msg)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
