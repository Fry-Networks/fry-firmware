# Scans a built artifact (firmware.bin/.elf, or any file) for identity/path leaks: the operator's
# Windows username, "Users\\", or any absolute Windows path (e.g. C:\Users\...). A build that
# embeds a compile-time __FILE__/path string could leak the developer's machine layout into a
# public release binary.
#   py -3 tools/scan_identity.py <path> [<path> ...]
# A path may be a file or a DIRECTORY; directories are walked recursively.
# Exit 0 = clean, 1 = hit(s) found, 2 = a path could not be read. Never loosen the patterns to pass.
import os
import sys
import re
import argparse

# Drive-letter + BACKSLASH only (a real absolute Windows path shape), with a lookbehind so
# "https:" (letter-colon, then a forward slash) never matches as a false "s:" drive reference.
WINPATH_RE = re.compile(rb"(?<![A-Za-z0-9])[A-Za-z]:\\[^\x00-\x1f]{0,200}")
# Literal needles come from the environment so this public file never has to contain the
# very username it is meant to detect. Set FRY_SCAN_NEEDLES to a comma-separated list,
# e.g. FRY_SCAN_NEEDLES=alice,bob. "Users\\" is always checked because it is generic.
NEEDLES = tuple(
    n.encode("utf-8")
    for n in os.environ.get("FRY_SCAN_NEEDLES", "").split(",")
    if n.strip()
) + (b"Users\\",)

# This file necessarily CONTAINS the patterns it searches for - the b"Users\\" needle literal and
# the C:\Users\... example in the header. Scanning itself therefore always reported hits, so any
# gate built on `scan_identity.py <dir>` failed permanently and the tool could not be pointed at a
# source tree at all. Skipping exactly one file - this one, resolved through symlinks so it cannot
# be dodged by path spelling - is the narrowest possible exemption. Nothing else is ever exempt,
# and the skip is printed rather than silent so a reader can see what was not scanned.
SELF_PATH = os.path.realpath(__file__)

# Directories that are never source and would only add noise (and minutes) to a recursive scan.
# Build output is deliberately NOT excluded: .pio/build/*/firmware.bin is the primary target.
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}


def iter_files(path):
    """Yield scannable files for a path. A directory is walked recursively; a file yields itself."""
    if os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            for name in sorted(files):
                yield os.path.join(root, name)
    else:
        yield path


def scan_file(path):
    hits = []
    with open(path, "rb") as f:
        data = f.read()
    for needle in NEEDLES:
        idx = 0
        while True:
            idx = data.find(needle, idx)
            if idx < 0:
                break
            start = max(0, idx - 20)
            end = min(len(data), idx + 40)
            hits.append((needle.decode("latin1"), data[start:end]))
            idx += 1
    for m in WINPATH_RE.finditer(data):
        hits.append(("winpath", m.group(0)[:120]))
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    a = ap.parse_args()

    total = 0
    errors = 0
    for arg in a.paths:
        for p in iter_files(arg):
            if os.path.realpath(p) == SELF_PATH:
                print("[scan_identity] %s: skipped (scanner's own source)" % p)
                continue
            try:
                hits = scan_file(p)
            except OSError as exc:
                # Catch OSError, not PermissionError: opening a directory raises PermissionError on
                # Windows but IsADirectoryError on POSIX, and only OSError covers both. A missing or
                # unreadable path must also never be reported as "clean", nor be mistaken for a leak,
                # so it exits 2 rather than 0 or 1.
                print("[scan_identity] %s: ERROR %s" % (p, exc))
                errors += 1
                continue
            if hits:
                print("[scan_identity] %s: %d hit(s)" % (p, len(hits)))
                for kind, ctx in hits[:20]:
                    safe = ctx.decode("latin1", "replace").replace("\n", " ").replace("\r", " ")
                    print("  %-10s %r" % (kind, safe))
                total += len(hits)
            else:
                print("[scan_identity] %s: clean" % p)

    if errors:
        print("[scan_identity] ERROR: %d path(s) could not be read" % errors)
        sys.exit(2)
    if total:
        print("[scan_identity] FAIL: %d total hit(s)" % total)
        sys.exit(1)
    print("[scan_identity] PASS: no identity leaks")
    sys.exit(0)


if __name__ == "__main__":
    main()
