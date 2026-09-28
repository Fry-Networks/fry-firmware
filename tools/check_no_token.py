#!/usr/bin/env python3
"""Fails if a bearer token is compiled into, or published inside, a firmware artifact (D-5 / A4).

Two modes.

Header mode (default) - run after `pio run`, before anything is uploaded:
    python3 tools/check_no_token.py [--header include/generated/fry_secrets.h]
tools/fry_prebuild.py writes the FRY_API_TOKEN environment variable into that header. A release
build must leave the variable unset, so the header must read `#define FRY_API_TOKEN ""`. Anything
else fails, and only the token's LENGTH is printed.

Artifact mode - exact-byte scan of files, directories, zips and tars (nested, e.g. the github-pages
artifact: a zip holding artifact.tar):
    python3 tools/check_no_token.py --artifact PATH [PATH ...] --needle-env NAME [NAME ...] [--plant-control]
The token VALUES never appear on the command line (argv is visible to every process on the host):
each NAME is an environment variable holding one value. The report names the variable and the
path, never the value. --plant-control first scans an in-memory zip-in-tar with every needle
planted inside and fails unless the scanner finds each one: a clean result then means something.

Exit codes: 0 clean, 1 a token found (or the header is not empty), 2 usage error (missing or too
short needle, unreadable path), 3 the planted control was NOT found (the scan cannot be trusted).
"""
import argparse
import io
import os
import re
import sys
import tarfile
import zipfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_HEADER = os.path.join(HERE, "include", "generated", "fry_secrets.h")
MIN_NEEDLE = 8
MAX_DEPTH = 4


def check_header(path):
    if not os.path.isfile(path):
        print("check_no_token: %s does not exist - run `pio run` first" % path)
        return 2
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    m = re.search(r'#define\s+FRY_API_TOKEN\s+"((?:[^"\\]|\\.)*)"', text)
    if not m:
        print("check_no_token: FAIL - %s has no FRY_API_TOKEN define" % path)
        return 1
    if m.group(1):
        print("check_no_token: FAIL - %s carries a %d-character FRY_API_TOKEN. Build with the "
              "variable unset." % (path, len(m.group(1))))
        return 1
    print("check_no_token: OK - %s has an empty FRY_API_TOKEN" % path)
    return 0


def scan_bytes(data, label, needles, hits, depth, counter):
    """Records (needle name, label) for every needle in data, then recurses into archives."""
    counter[0] += 1
    for name, value in needles:
        if value in data:
            hits.append((name, label))
    if depth >= MAX_DEPTH:
        return
    bio = io.BytesIO(data)
    if zipfile.is_zipfile(bio):
        try:
            with zipfile.ZipFile(bio) as z:
                for info in z.infolist():
                    if not info.is_dir():
                        scan_bytes(z.read(info), "%s!%s" % (label, info.filename), needles, hits,
                                   depth + 1, counter)
        except zipfile.BadZipFile:
            pass
        return
    bio.seek(0)
    try:
        with tarfile.open(fileobj=bio, mode="r:*") as t:
            for member in t:
                if member.isfile():
                    f = t.extractfile(member)
                    if f is not None:
                        scan_bytes(f.read(), "%s!%s" % (label, member.name), needles, hits,
                                   depth + 1, counter)
    except (tarfile.TarError, EOFError, OSError):
        pass  # not a tar: the raw bytes were already scanned


def scan_paths(paths, needles):
    hits, counter = [], [0]
    for path in paths:
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for fn in sorted(files):
                    p = os.path.join(root, fn)
                    with open(p, "rb") as f:
                        scan_bytes(f.read(), p, needles, hits, 0, counter)
        elif os.path.isfile(path):
            with open(path, "rb") as f:
                scan_bytes(f.read(), path, needles, hits, 0, counter)
        else:
            raise FileNotFoundError(path)
    return hits, counter[0]


def planted_control(needles):
    """A zip inside a tar, each needle buried in filler: every one must be found."""
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as z:
        for i, (_, value) in enumerate(needles):
            z.writestr("fw/firmware-%d.bin" % i, b"\x00" * 1000 + value + b"\xff" * 1000)
    outer = io.BytesIO()
    with tarfile.open(fileobj=outer, mode="w:gz") as t:
        payload = inner.getvalue()
        info = tarfile.TarInfo("artifact/control.zip")
        info.size = len(payload)
        t.addfile(info, io.BytesIO(payload))
    found = []
    scan_bytes(outer.getvalue(), "<planted-control>", needles, found, 0, [0])
    names = {n for n, _ in found}
    return [n for n, _ in needles if n not in names]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--header", default=DEFAULT_HEADER)
    ap.add_argument("--artifact", nargs="+", metavar="PATH")
    ap.add_argument("--needle-env", nargs="+", metavar="NAME",
                    help="names of environment variables holding the token values")
    ap.add_argument("--plant-control", action="store_true")
    a = ap.parse_args()

    if not a.artifact:
        return check_header(a.header)

    if not a.needle_env:
        print("check_no_token: --artifact needs --needle-env NAME [NAME ...]")
        return 2
    needles = []
    for name in a.needle_env:
        value = os.environ.get(name, "")
        if not value:
            print("check_no_token: environment variable %s is unset or empty" % name)
            return 2
        if len(value) < MIN_NEEDLE:
            print("check_no_token: %s is only %d characters - too short to scan for" % (name, len(value)))
            return 2
        needles.append((name, value.encode("utf-8")))

    if a.plant_control:
        missed = planted_control(needles)
        if missed:
            print("check_no_token: CONTROL FAILED - planted %s not found; the scan proves nothing"
                  % ", ".join(missed))
            return 3
        print("check_no_token: control OK - every planted needle found (%d)" % len(needles))

    try:
        hits, scanned = scan_paths(a.artifact, needles)
    except FileNotFoundError as e:
        print("check_no_token: no such file or directory: %s" % e)
        return 2
    for name, label in hits:
        print("check_no_token: HIT %s in %s" % (name, label))
    if hits:
        print("check_no_token: FAIL - %d hit(s) across %d files/members" % (len(hits), scanned))
        return 1
    print("check_no_token: OK - %d files/members scanned, 0 hits for %d needle(s): %s"
          % (scanned, len(needles), ", ".join(n for n, _ in needles)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
