#!/usr/bin/env python3
"""Fails if a device-key-shaped string appears in a tracked text file and is not on the fixture allowlist.

    python3 tools/check_device_key_shapes.py [--root DIR] [--allow FILE]

Shape: one of the known prefixes (FEM, IOT, RDN, BM, IDM, SDN, AEM, ISM, SVN, OSM), a dash, then exactly
32 ASCII letters/digits that are not followed by another letter/digit. Every tracked text file is
scanned (docs and tests included); files containing a NUL byte are treated as binary and skipped.
Outside a git checkout the whole tree under --root is walked (minus .git).

The allowlist (default tools/device_key_fixtures.allow next to this script's repo root) lists the
synthetic fixture strings that tests use, one per line, '#' starts a comment. It is itself a tracked
file and is not scanned. Adding a line there is the review point: every entry must also look
synthetic (low per-character entropy, or a plain counting pattern); an entry that looks random is
rejected, so a random-looking value cannot be waved through just by listing it.

The check never prints a matched string: only file:line, the first 6 characters and "...", and a label.

Exit codes: 0 clean, 1 at least one finding, 2 usage or allowlist error.
"""
import argparse
import collections
import math
import os
import re
import subprocess
import sys

PREFIXES = ("FEM", "IOT", "RDN", "BM", "IDM", "SDN", "AEM", "ISM", "SVN", "OSM")
SHAPE = re.compile(r"(?:%s)-[A-Za-z0-9]{32}(?![A-Za-z0-9])" % "|".join(PREFIXES))
FULL = re.compile(r"(?:%s)-[A-Za-z0-9]{32}\Z" % "|".join(PREFIXES))
LOW_ENTROPY_BITS = 2.5
COUNTING_ALPHABETS = (
    "0123456789ABCDEF", "0123456789abcdef", "0123456789",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz",
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789abcdefghijklmnopqrstuvwxyz",
)


def entropy(s):
    c = collections.Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def looks_synthetic(key):
    body = key.split("-", 1)[1]
    if entropy(body) < LOW_ENTROPY_BITS:
        return True
    return any(body in alpha * 4 for alpha in COUNTING_ALPHABETS)


def mask(key):
    return key[:6] + "..."


def load_allow(path):
    """Returns (set_of_keys, list_of_error_strings). Errors never contain a full key."""
    keys, errs = set(), []
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError as e:
        return keys, ["cannot read allowlist %s: %s" % (path, type(e).__name__)]
    for n, line in enumerate(lines, 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if not FULL.match(s):
            errs.append("%s:%d: allowlist line is not a bare key-shaped string (%s)" % (path, n, mask(s)))
        elif not looks_synthetic(s):
            errs.append("%s:%d: allowlist entry %s looks random, not synthetic; entries must be obvious fixtures" % (path, n, mask(s)))
        else:
            keys.add(s)
    return keys, errs


def list_files(root):
    if os.path.isdir(os.path.join(root, ".git")) or os.path.isfile(os.path.join(root, ".git")):
        r = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True)
        if r.returncode == 0:
            return [f.decode("utf-8", "replace") for f in r.stdout.split(b"\0") if f]
    out = []
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x != ".git"]
        for f in files:
            out.append(os.path.relpath(os.path.join(d, f), root))
    return sorted(out)


def scan(root, allow_path):
    keys, errs = load_allow(allow_path)
    if errs:
        return [], errs
    allow_abs = os.path.abspath(allow_path)
    findings = []
    for rel in list_files(root):
        p = os.path.join(root, rel)
        if os.path.abspath(p) == allow_abs or os.path.islink(p) or not os.path.isfile(p):
            continue
        try:
            with open(p, "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        if b"\0" in data:
            continue
        text = data.decode("utf-8", "replace")
        for n, line in enumerate(text.split("\n"), 1):
            for m in SHAPE.finditer(line):
                k = m.group(0)
                if k in keys:
                    continue
                label = "synthetic-looking but not on the allowlist" if looks_synthetic(k) else "HIGH-ENTROPY and not on the allowlist"
                findings.append("%s:%d: %s %s" % (rel, n, mask(k), label))
    return findings, []


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    ap.add_argument("--allow", default=None)
    a = ap.parse_args(argv)
    root = os.path.abspath(a.root)
    allow = a.allow or os.path.join(root, "tools", "device_key_fixtures.allow")
    findings, errs = scan(root, allow)
    for e in errs:
        print("ERROR " + e)
    if errs:
        return 2
    for f in findings:
        print("FOUND " + f)
    if findings:
        print("FAIL: %d device-key-shaped string(s) outside the fixture allowlist" % len(findings))
        return 1
    print("OK: no device-key-shaped strings outside the fixture allowlist")
    return 0


if __name__ == "__main__":
    sys.exit(main())
