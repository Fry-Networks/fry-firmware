#!/usr/bin/env python3
"""Stricter ESP8266 static-RAM guard: fails the esp8266 prod build above (T-ESP measured total + headroom).

tools/check_esp8266_ram_budget.py keeps its 34408 B budget (untouched). T-ESP won ~760 B back (strftime removed, IRAM heap flag
costs +40 B), so that budget would now let a regression spend all of it unnoticed. This guard pins the new measurement
(tools/esp8266_ram_margin.json: measured_total + headroom) on the same proxy: .data + .rodata + .bss of firmware.elf (`size -A`).

  python3 tools/esp8266_ram_margin.py .pio/build/esp8266/firmware.elf [--size-tool PATH] [--limit N]
  python3 tools/esp8266_ram_margin.py --size-output saved-size-A.txt
  PlatformIO runs it as a second post-link action of env:esp8266 (and esp8266_test); other envs print "skipped".

Exit codes: 0 within the limit, 1 over (or unmeasurable), 2 usage.
"""
import argparse
import glob
import json
import os
import re
import subprocess
import sys

RAM_SECTIONS = (".data", ".rodata", ".bss")
SECTION_LINE = re.compile(r"^(\.[A-Za-z0-9_.]+)\s+(\d+)\s+(\d+)\s*$")


class Unmeasurable(Exception):
    pass


def load_config(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        total, head = int(cfg["measured_total"]), int(cfg["headroom"])
        gated = tuple(cfg["env_gated"])
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise Unmeasurable("cannot read %s: %s" % (path, e))
    if head < 0 or head > 256:
        raise Unmeasurable("%s: headroom %d outside 0..256 (a stricter guard must stay strict)" % (path, head))
    return {"limit": total + head, "measured_total": total, "headroom": head, "gated": gated}


def ram_sections(size_a_text):
    found = {}
    for line in size_a_text.splitlines():
        m = SECTION_LINE.match(line.strip())
        if m and m.group(1) in RAM_SECTIONS:
            found[m.group(1)] = int(m.group(2))
    missing = [s for s in RAM_SECTIONS if s not in found]
    if missing:
        raise Unmeasurable("no %s in the size output" % ", ".join(missing))
    return found


def check(size_a_text, limit):
    """(exit_code, message)."""
    try:
        sections = ram_sections(size_a_text)
    except Unmeasurable as e:
        return 1, "esp8266 RAM margin: %s" % e
    total = sum(sections.values())
    detail = " [" + " + ".join("%s %d" % (s, sections[s]) for s in RAM_SECTIONS) + "]"
    if total <= limit:
        return 0, "esp8266 RAM margin: %d B used, %d B allowed (%d B spare)%s" % (total, limit, limit - total, detail)
    return 1, (
        "esp8266 RAM margin EXCEEDED: %d B used, %d B allowed, %d B over%s. The static image grew past what T-ESP measured "
        "(tools/esp8266_ram_margin.json). Shrink the change, or re-measure and raise measured_total in the same commit with "
        "the bench proof that the OTA heap gates still pass." % (total, limit, total - limit, detail)
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


def default_config_path(project_dir=None):
    base = os.path.join(project_dir, "tools") if project_dir else os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "esp8266_ram_margin.json")


def post_action(env, size_text=None):
    """PlatformIO post-link action. 0 = build continues, 1 = build fails."""
    name = env["PIOENV"]
    try:
        cfg = load_config(default_config_path(env.subst("$PROJECT_DIR")))
        if name not in cfg["gated"]:
            print("esp8266 RAM margin: skipped for env %s (gates only %s)" % (name, ", ".join(cfg["gated"])))
            return 0
        text = size_text if size_text is not None else size_a(env.subst("$BUILD_DIR/${PROGNAME}.elf"), env.subst("$SIZETOOL") or find_size_tool())
    except Unmeasurable as e:
        print("esp8266 RAM margin: %s" % e)
        return 1  # a guard that cannot measure must not pass silently
    code, msg = check(text, cfg["limit"])
    print(msg)
    return code


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("elf", nargs="?")
    ap.add_argument("--size-tool", default=None)
    ap.add_argument("--size-output", default=None)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--config", default=None)
    a = ap.parse_args(argv)
    if bool(a.elf) == bool(a.size_output):
        ap.error("give exactly one of an ELF path or --size-output")
    try:
        limit = a.limit if a.limit is not None else load_config(a.config or default_config_path())["limit"]
        if a.size_output:
            with open(a.size_output, "r", errors="replace") as f:
                text = f.read()
        else:
            text = size_a(a.elf, a.size_tool or find_size_tool())
    except (Unmeasurable, OSError) as e:
        print("esp8266 RAM margin: %s" % e)
        return 1
    code, msg = check(text, limit)
    print(msg)
    return code


try:
    Import("env")  # noqa: F821  (PlatformIO extra script)
except NameError:
    env = None
if env is not None:

    def _ram_margin_action(target, source, env):
        return post_action(env)

    env.AddPostAction("$BUILD_DIR/${PROGNAME}.elf", env.Action(_ram_margin_action, "Checking the ESP8266 RAM margin (T-ESP)"))

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
