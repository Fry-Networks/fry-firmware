# Scans a built artifact (firmware.bin/.elf, or any file) for identity/path leaks: the operator's
# Windows username, "Users\\", or any absolute Windows path (e.g. C:\Users\...). A build that
# embeds a compile-time __FILE__/path string could leak the developer's machine layout into a
# public release binary.
#   py -3 tools/scan_identity.py <path> [<path> ...]
# Exit 0 = clean, 1 = hit(s) found. Never loosen the patterns to pass.
import sys
import re
import argparse

# Drive-letter + BACKSLASH only (a real absolute Windows path shape), with a lookbehind so
# "https:" (letter-colon, then a forward slash) never matches as a false "s:" drive reference.
WINPATH_RE = re.compile(rb"(?<![A-Za-z0-9])[A-Za-z]:\\[^\x00-\x1f]{0,200}")
NEEDLES = (b"saf70", b"Users\\")


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
    for p in a.paths:
        hits = scan_file(p)
        if hits:
            print("[scan_identity] %s: %d hit(s)" % (p, len(hits)))
            for kind, ctx in hits[:20]:
                safe = ctx.decode("latin1", "replace").replace("\n", " ").replace("\r", " ")
                print("  %-10s %r" % (kind, safe))
            total += len(hits)
        else:
            print("[scan_identity] %s: clean" % p)

    if total:
        print("[scan_identity] FAIL: %d total hit(s)" % total)
        sys.exit(1)
    print("[scan_identity] PASS: no identity leaks")
    sys.exit(0)


if __name__ == "__main__":
    main()
