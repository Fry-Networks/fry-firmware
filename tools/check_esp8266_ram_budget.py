#!/usr/bin/env python3
"""Fails an ESP8266 build whose static RAM outgrows its budget (the OTA image download's heap gate).

The ESP8266 heap is what is left of the 80 KB data RAM after the linker places .data, .rodata and .bss, so every static
byte is a byte the image download's TLS session does not have. fw 0.4.15 added 80 B (the stale-token self-heal) on top of a
1072 B Improv scan list and its download then failed the heap gate by 24 B: need free >= 35560 (lib/fry_core/tls_sizing.cpp;
42280 gate - 6720 begin-time clients), have 35536. Nothing in the build noticed. This does.

PROXY: the post-link total of .data + .rodata + .bss of firmware.elf (`size -A`), the same figure PlatformIO prints as
"RAM: used N bytes". It is a proxy, not the heap: it ignores what the firmware allocates at run time and the 8-mod-16 alignment
of the heap start, which the bench (tools/gate_heap.py) measures. It is the part a source change moves silently.

BUDGET: 34152 B (main 85825ac, .data 1652 + .rodata 5500 + .bss 27000) + 256 B margin = 34408 B.
  - 0.4.15 (46666f1) measured 35224 B and missed the gate by 24 B, so the cliff is 35200 B (35224 - 24, if the free heap moves
    one for one with static RAM) and main sits about 1048 B under it.
  - The margin is a quarter of that headroom, over three times the heal's 80 B, and leaves the rest for run-time variance.
  - A change that needs more bumps BUDGET_BYTES below, in the same commit, with the measured new total and why it is safe.

Two ways to run it:
  python3 tools/check_esp8266_ram_budget.py .pio/build/esp8266/firmware.elf [--size-tool PATH] [--budget N]
  python3 tools/check_esp8266_ram_budget.py --size-output saved-size-A.txt
  PlatformIO runs it as a post-link action of env:esp8266 (`extra_scripts = post:tools/check_esp8266_ram_budget.py`). It gates
  ONLY the prod images (esp8266, esp8266_test); lab, bench and olostep builds carry other code and print "skipped".

Exit codes: 0 within budget, 1 over budget (or the ELF could not be measured), 2 usage.
"""
import argparse
import glob
import os
import re
import subprocess
import sys

BASELINE_BYTES = 34152
MARGIN_BYTES = 256
BUDGET_BYTES = BASELINE_BYTES + MARGIN_BYTES  # 34408
GATED_ENVS = ("esp8266", "esp8266_test")
RAM_SECTIONS = (".data", ".rodata", ".bss")

# `size -A`: "<section> <size> <address>"
SECTION_LINE = re.compile(r"^(\.[A-Za-z0-9_.]+)\s+(\d+)\s+(\d+)\s*$")


class Unmeasurable(Exception):
    pass


def ram_sections(size_a_text):
    """{section: bytes} for the RAM sections in `size -A` text. Raises Unmeasurable if one is missing."""
    found = {}
    for line in size_a_text.splitlines():
        m = SECTION_LINE.match(line.strip())
        if m and m.group(1) in RAM_SECTIONS:
            found[m.group(1)] = int(m.group(2))
    missing = [s for s in RAM_SECTIONS if s not in found]
    if missing:
        raise Unmeasurable("no %s in the size output" % ", ".join(missing))
    return found


def ram_bytes(size_a_text):
    return sum(ram_sections(size_a_text).values())


def verdict(total, budget=BUDGET_BYTES):
    """(ok, message)."""
    if total <= budget:
        return True, "esp8266 RAM budget: %d B used, %d B allowed (%d B spare)" % (total, budget, budget - total)
    return False, (
        "esp8266 RAM budget EXCEEDED: %d B used, %d B allowed, %d B over. Static RAM is heap the OTA download's TLS "
        "session needs (heap gate: free >= 35560); 0.4.15 missed it by 24 B at 35224 B. Shrink the change, or move the "
        "data off the static image, or raise BUDGET_BYTES in tools/check_esp8266_ram_budget.py with the measured total "
        "and the bench proof that the download heap gate still passes." % (total, budget, total - budget)
    )


def find_size_tool():
    hits = sorted(glob.glob(os.path.expanduser("~/.platformio/packages/toolchain-xtensa*/bin/xtensa-lx106-elf-size")))
    return hits[0] if hits else "xtensa-lx106-elf-size"


def size_a(elf, size_tool):
    try:
        out = subprocess.run([size_tool, "-A", elf], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Unmeasurable("cannot run %s: %s" % (size_tool, e))
    if out.returncode != 0:
        raise Unmeasurable("%s -A %s failed: %s" % (size_tool, elf, out.stderr.strip()[:200]))
    return out.stdout


def check(size_a_text, budget=BUDGET_BYTES):
    """(exit_code, message) for `size -A` text."""
    try:
        sections = ram_sections(size_a_text)
    except Unmeasurable as e:
        return 1, "esp8266 RAM budget: %s" % e
    total = sum(sections.values())
    ok, msg = verdict(total, budget)
    detail = " [" + " + ".join("%s %d" % (s, sections[s]) for s in RAM_SECTIONS) + "]"
    return (0 if ok else 1), msg + detail


def env_is_gated(pioenv):
    return pioenv in GATED_ENVS


def post_action(env, size_text=None):
    """PlatformIO post-link action. Returns 0 (build continues) or 1 (build fails)."""
    name = env["PIOENV"]
    if not env_is_gated(name):
        print("esp8266 RAM budget: skipped for env %s (gates only %s)" % (name, ", ".join(GATED_ENVS)))
        return 0
    elf = env.subst("$BUILD_DIR/${PROGNAME}.elf")
    try:
        text = size_text if size_text is not None else size_a(elf, env.subst("$SIZETOOL") or find_size_tool())
    except Unmeasurable as e:
        print("esp8266 RAM budget: %s" % e)
        return 1  # a guard that cannot measure must not pass silently
    code, msg = check(text)
    print(msg)
    return code


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("elf", nargs="?", help="firmware.elf of an ESP8266 build")
    ap.add_argument("--size-tool", default=None)
    ap.add_argument("--size-output", default=None, help="a saved `size -A` output instead of an ELF")
    ap.add_argument("--budget", type=int, default=BUDGET_BYTES)
    a = ap.parse_args(argv)
    if bool(a.elf) == bool(a.size_output):
        ap.error("give exactly one of an ELF path or --size-output")
    try:
        if a.size_output:
            with open(a.size_output, "r", errors="replace") as f:
                text = f.read()
        else:
            text = size_a(a.elf, a.size_tool or find_size_tool())
    except (Unmeasurable, OSError) as e:
        print("esp8266 RAM budget: %s" % e)
        return 1
    code, msg = check(text, a.budget)
    print(msg)
    return code


# PlatformIO loads this file as an extra script, where Import() exists; a plain `python3` run does not have it.
try:
    Import("env")  # noqa: F821
except NameError:
    env = None
if env is not None:

    def _ram_budget_action(target, source, env):  # SCons calls function actions with these keyword names
        return post_action(env)

    # env.Action(..., "<text>") names the step in the build log; a bare function prints its repr.
    env.AddPostAction("$BUILD_DIR/${PROGNAME}.elf", env.Action(_ram_budget_action, "Checking the ESP8266 RAM budget"))

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
