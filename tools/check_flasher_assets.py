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

It then checks the ESP Web Tools manifest the page actually flashes from
(docs/flash/manifest.json), which is a different shape and has more ways to go wrong:
  4. its version matches too,
  5. its "name" is still the exact string the firmware reports over Improv Serial - they are
     compared with === by the flasher, and a drift silently turns every update into a new
     install with an erase prompt,
  6. every parts[].path exists and its sha256 matches,
  7. every offset agrees with the partition table in the partitions part that ships beside it,
     and no part overlaps a data partition other than otadata. That last one is the whole reason
     the web manifest lists parts instead of a merged factory image: NVS sits in a gap that a
     merged image pads with 0xFF, and flashing over it would wipe the miner key.

Usage:
    py -3 tools/check_flasher_assets.py --expect-version 0.3.0
    py -3 tools/check_flasher_assets.py --expect-version "$GITHUB_REF_NAME"   # accepts a v-prefix
"""
import argparse
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, "tools"))
from make_manifest import (  # noqa: E402  (path set up immediately above)
    PART_SUBTYPE_DATA_OTA, PART_TYPE_APP, PART_TYPE_DATA, parse_partition_table)

FLASH_DIR = os.path.join(HERE, "docs", "flash")
MANIFEST = os.path.join(FLASH_DIR, "fw", "manifest.json")
EWT_MANIFEST = os.path.join(FLASH_DIR, "manifest.json")
IMPROV_GLUE = os.path.join(HERE, "src", "core", "improv_serial_glue.cpp")


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def improv_firmware_name():
    """The firmware NAME the device reports over Improv, read out of the firmware source."""
    with open(IMPROV_GLUE, encoding="utf-8") as f:
        src = f.read()
    m = re.search(r'kImprovFirmwareName\[\]\s*=\s*"([^"]*)"', src)
    if not m:
        sys.exit("check_flasher_assets: could not find kImprovFirmwareName in %s" % IMPROV_GLUE)
    return m.group(1)


def check_ewt_manifest(expected, failures):
    """Validates docs/flash/manifest.json - the manifest the browser flasher actually reads."""
    if not os.path.isfile(EWT_MANIFEST):
        failures.append("%s does not exist" % EWT_MANIFEST)
        return 0

    with open(EWT_MANIFEST, encoding="utf-8") as f:
        manifest = json.load(f)

    if manifest.get("version") != expected:
        failures.append("web manifest says version=%r but the release is %r"
                        % (manifest.get("version"), expected))

    want_name = improv_firmware_name()
    if manifest.get("name") != want_name:
        failures.append(
            "web manifest name=%r but the firmware reports %r over Improv "
            "(src/core/improv_serial_glue.cpp kImprovFirmwareName). ESP Web Tools compares these "
            "with ===, so a mismatch makes every update look like a new install."
            % (manifest.get("name"), want_name))

    checked = 0
    for build in manifest.get("builds", []):
        family = build.get("chipFamily", "?")
        parts = build.get("parts", [])
        if not parts:
            failures.append("%s: build has no parts" % family)
            continue

        resolved = []  # (offset, absolute path, size)
        for part in parts:
            path, offset, want = part.get("path"), part.get("offset"), part.get("sha256")
            if path is None or offset is None:
                failures.append("%s: a part is missing path or offset" % family)
                continue
            # Parts are resolved against the MANIFEST's own url by ESP Web Tools
            # (new URL(part.path, manifestUrl)), and the manifest sits in docs/flash.
            abspath = os.path.join(FLASH_DIR, path.replace("/", os.sep))
            if not os.path.isfile(abspath):
                failures.append("%s: %s is named by the web manifest but not present" % (family, path))
                continue
            checked += 1
            resolved.append((offset, abspath, os.path.getsize(abspath)))
            if not want:
                failures.append("%s: %s has no sha256 in the web manifest" % (family, path))
            elif sha256_of(abspath) != want:
                failures.append("%s: %s sha256 is %s, the web manifest claims %s"
                                % (family, path, sha256_of(abspath), want))

        table_part = [p for _, p, _ in resolved if os.path.basename(p).startswith("partitions-")]
        if not table_part:
            continue  # ESP8266 ships one whole-flash image and has no partition table here
        table = parse_partition_table(table_part[0])
        apps = sorted((p for p in table if p["type"] == PART_TYPE_APP), key=lambda p: p["offset"])
        otadata = [p for p in table
                   if p["type"] == PART_TYPE_DATA and p["subtype"] == PART_SUBTYPE_DATA_OTA]

        for offset, abspath, size in resolved:
            name = os.path.basename(abspath)
            if name.startswith("firmware") and apps and offset != apps[0]["offset"]:
                failures.append("%s: app part is at 0x%x but partition '%s' is at 0x%x"
                                % (family, offset, apps[0]["label"], apps[0]["offset"]))
            if name.startswith("boot_app0") and otadata and offset != otadata[0]["offset"]:
                failures.append("%s: boot_app0 part is at 0x%x but otadata is at 0x%x"
                                % (family, offset, otadata[0]["offset"]))
            for entry in table:
                if entry["type"] != PART_TYPE_DATA or entry["subtype"] == PART_SUBTYPE_DATA_OTA:
                    continue
                if offset < entry["offset"] + entry["size"] and entry["offset"] < offset + size:
                    failures.append(
                        "%s: part %s (0x%x..0x%x) overlaps data partition '%s' (0x%x..0x%x) - "
                        "flashing it would erase stored settings, including the miner key"
                        % (family, name, offset, offset + size, entry["label"],
                           entry["offset"], entry["offset"] + entry["size"]))
    return checked


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

    ewt_checked = check_ewt_manifest(expected, failures)

    if failures:
        sys.stderr.write("check_flasher_assets: FAILED\n")
        for line in failures:
            sys.stderr.write("  - %s\n" % line)
        sys.exit(1)

    count = sum(1 + (1 if "factory" in b else 0) for b in manifest["builds"].values())
    print("check_flasher_assets: OK - flasher serves %s, %d assets + %d web-manifest parts verified"
          % (got_version, count, ewt_checked))


if __name__ == "__main__":
    main()
