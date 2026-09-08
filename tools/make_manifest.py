#!/usr/bin/env python3
"""Generates ota/manifest.json (PROTOCOL.md section 6) from built firmware.bin files.

Usage:
    py -3 tools/make_manifest.py --version 0.1.1 --release-base \
        https://github.com/Fry-Networks/fry-firmware/releases/download/v0.1.1

Reads <build-dir>/<env>/firmware.bin for each of esp8266/esp32/esp32s3/esp32c3 (run `pio run`
for each env first), computes a real sha256 over the exact bytes, and writes ota/manifest.json
with "{release_base}/firmware-<env>.bin" as each build's url — matching the asset naming the
release CI job (.github/workflows/build.yml) publishes.
"""
import argparse
import hashlib
import json
import os
import sys

ENVS = ("esp8266", "esp32", "esp32s3", "esp32c3")


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True, help="firmware_version to embed, e.g. 0.1.1")
    ap.add_argument("--release-base", required=True,
                     help="base URL under which firmware-<env>.bin assets are published")
    ap.add_argument("--build-dir", default=os.path.join(".pio", "build"),
                     help="directory containing <env>/firmware.bin (default: .pio/build)")
    ap.add_argument("--out", default=os.path.join("ota", "manifest.json"))
    a = ap.parse_args()

    builds = {}
    missing = []
    for env in ENVS:
        bin_path = os.path.join(a.build_dir, env, "firmware.bin")
        if not os.path.isfile(bin_path):
            missing.append(bin_path)
            continue
        builds[env] = {
            "url": a.release_base.rstrip("/") + "/firmware-%s.bin" % env,
            "sha256": sha256_of(bin_path),
        }

    if missing:
        sys.stderr.write("make_manifest: missing built binaries, run `pio run -e <env>` first:\n")
        for m in missing:
            sys.stderr.write("  %s\n" % m)
        sys.exit(1)

    manifest = {"firmware_version": a.version, "builds": builds}

    out_dir = os.path.dirname(a.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")

    print("make_manifest: wrote %s (version=%s, %d builds)" % (a.out, a.version, len(builds)))


if __name__ == "__main__":
    main()
