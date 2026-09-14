#!/usr/bin/env python3
"""Fails if the published web flasher would serve a different firmware than the release.

The GitHub Pages flasher (docs/flash) serves firmware SAME-ORIGIN from docs/flash/fw, because
GitHub release assets are not fetchable cross-origin. That directory is committed, and nothing in
the release pipeline regenerates it -- so it is entirely possible to tag a release while the
flasher keeps handing users the previous firmware. That happened: v0.2.0 shipped and the flasher
stayed on it while the fix users needed sat unreleased on main.

This check makes that state impossible to ship silently. It verifies that:
  1. the manifest's firmware_version matches the version being released,
  2. every url the manifest names actually exists in docs/flash/fw, and
  3. each file's sha256 matches what the manifest claims.

Usage:
    py -3 tools/check_flasher_assets.py --expect-version 0.3.0
    py -3 tools/check_flasher_assets.py --expect-version "$GITHUB_REF_NAME"   # accepts a v-prefix
"""
import argparse
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FLASH_DIR = os.path.join(HERE, "docs", "flash")
MANIFEST = os.path.join(FLASH_DIR, "fw", "manifest.json")


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--expect-version", required=True,
                    help="version the flasher must be serving, with or without a leading 'v'")
    a = ap.parse_args()
    expected = a.expect_version.lstrip("v")

    if not os.path.isfile(MANIFEST):
        sys.exit("check_flasher_assets: %s does not exist" % MANIFEST)

    with open(MANIFEST, encoding="utf-8") as f:
        manifest = json.load(f)

    failures = []

    got_version = manifest.get("firmware_version")
    if got_version != expected:
        failures.append(
            "flasher manifest says firmware_version=%r but the release is %r. Rebuild the assets:\n"
            "    py -3 tools/make_manifest.py --version %s --release-base fw \\\n"
            "        --build-dir .pio/build --dist docs/flash/fw --out docs/flash/fw/manifest.json"
            % (got_version, expected, expected))

    for env, build in sorted(manifest.get("builds", {}).items()):
        entries = [("plain", build.get("url"), build.get("sha256"))]
        if "factory" in build:
            entries.append(("factory", build["factory"].get("url"), build["factory"].get("sha256")))
        for kind, url, want in entries:
            if not url or not want:
                failures.append("%s %s: manifest entry is missing url or sha256" % (env, kind))
                continue
            # The page resolves asset urls against document.baseURI, which is .../flash/ -- so a
            # manifest url is relative to docs/flash, NOT to the manifest's own directory.
            path = os.path.join(FLASH_DIR, url.replace("/", os.sep))
            if not os.path.isfile(path):
                failures.append("%s %s: %s is named by the manifest but not present in docs/flash"
                                % (env, kind, url))
                continue
            got = sha256_of(path)
            if got != want:
                failures.append("%s %s: %s sha256 is %s, manifest claims %s"
                                % (env, kind, url, got, want))

    if failures:
        sys.stderr.write("check_flasher_assets: FAILED\n")
        for line in failures:
            sys.stderr.write("  - %s\n" % line)
        sys.exit(1)

    count = sum(1 + (1 if "factory" in b else 0) for b in manifest["builds"].values())
    print("check_flasher_assets: OK - flasher serves %s, %d assets verified"
          % (got_version, count))


if __name__ == "__main__":
    main()
