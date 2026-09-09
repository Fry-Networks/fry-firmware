#!/usr/bin/env python3
"""Generates ota/manifest.json (PROTOCOL.md section 6) from built firmware.bin files.

Usage:
    py -3 tools/make_manifest.py --version 0.2.0 --release-base \
        https://github.com/Fry-Networks/fry-firmware/releases/download/v0.2.0

Reads <build-dir>/<env>/firmware.bin for each of esp8266/esp32/esp32s3/esp32c3 (run `pio run`
for each env first), computes a real sha256 over the exact bytes, and writes ota/manifest.json
with "{release_base}/firmware-<env>.bin" as each build's url — matching the asset naming the
release CI job (.github/workflows/build.yml) publishes.

For the ESP32 family it ALSO merges a factory image. This matters because those
firmware.bin files are APP-ONLY images destined for flash offset 0x10000; writing one at
offset 0x0 produces a board that never boots. The OTA client only ever replaces the app
partition, so the plain url stays the OTA artifact — but the browser flasher (docs/flash)
writes a blank board from offset 0x0 and needs bootloader + partition table + boot_app0 +
app in one image. Each ESP32-family build therefore gains a "factory" entry alongside it.
The ESP8266 needs no such thing: its firmware.bin is already a complete 0x0 image.

Offsets and flash settings below are not guesses — they were read back from the actual
`pio run -t upload` command line for each environment.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys

ENVS = ("esp8266", "esp32", "esp32s3", "esp32c3")

# env -> (esptool chip, bootloader offset, flash_mode, flash_freq, flash_size)
FACTORY = {
    "esp32":   ("esp32",   "0x1000", "dio", "40m", "4MB"),
    "esp32s3": ("esp32s3", "0x0",    "dio", "80m", "8MB"),
    "esp32c3": ("esp32c3", "0x0",    "dio", "80m", "4MB"),
}

PIO_PACKAGES = os.path.join(os.path.expanduser("~"), ".platformio", "packages")
DEFAULT_ESPTOOL = os.path.join(PIO_PACKAGES, "tool-esptoolpy", "esptool.py")
DEFAULT_BOOT_APP0 = os.path.join(
    PIO_PACKAGES, "framework-arduinoespressif32", "tools", "partitions", "boot_app0.bin")


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def merge_factory(env, build_dir, out_path, esptool, boot_app0, python):
    """Merge bootloader + partitions + boot_app0 + app into one 0x0-flashable image."""
    chip, bl_off, mode, freq, size = FACTORY[env]
    env_dir = os.path.join(build_dir, env)
    parts = [
        (bl_off, os.path.join(env_dir, "bootloader.bin")),
        ("0x8000", os.path.join(env_dir, "partitions.bin")),
        ("0xe000", boot_app0),
        ("0x10000", os.path.join(env_dir, "firmware.bin")),
    ]
    if not os.path.isfile(out_path):
        for _, part in parts:
            if not os.path.isfile(part):
                raise SystemExit("make_manifest: missing %s (run `pio run -e %s`)" % (part, env))
    # A pre-merged image may already be sitting in the output directory: CI merges inside the
    # build job, which is the only place the Arduino framework (and therefore boot_app0.bin
    # and esptool) is installed, and hands the result to the release job as an artifact.
    # Reuse it rather than re-merging, but still run the verification below either way.
    if not os.path.isfile(out_path):
        cmd = [python, esptool, "--chip", chip, "merge_bin", "-o", out_path,
               "--flash_mode", mode, "--flash_freq", freq, "--flash_size", size]
        for off, part in parts:
            cmd += [off, part]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)

    # Prove the merge landed where the flasher will expect it, rather than trusting exit 0.
    app = open(os.path.join(env_dir, "firmware.bin"), "rb").read()
    merged = open(out_path, "rb").read()
    if merged[0x10000:0x10000 + len(app)] != app:
        raise SystemExit("make_manifest: %s factory image does not carry the app at 0x10000" % env)
    return out_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True, help="firmware_version to embed, e.g. 0.2.0")
    ap.add_argument("--release-base", required=True,
                    help="base URL under which firmware-<env>.bin assets are published")
    ap.add_argument("--build-dir", default=os.path.join(".pio", "build"),
                    help="directory containing <env>/firmware.bin (default: .pio/build)")
    ap.add_argument("--out", default=os.path.join("ota", "manifest.json"))
    ap.add_argument("--dist", default=None,
                    help="where to write merged factory images (default: alongside --out)")
    ap.add_argument("--esptool", default=DEFAULT_ESPTOOL)
    ap.add_argument("--boot-app0", default=DEFAULT_BOOT_APP0)
    ap.add_argument("--python", default=sys.executable,
                    help="interpreter used to run esptool.py")
    ap.add_argument("--no-factory", action="store_true",
                    help="skip merged factory images (OTA-only manifest)")
    ap.add_argument("--only", default=None,
                    help="restrict to a single environment. CI builds one env per matrix job, "
                         "so the merge step there can only see its own binaries.")
    a = ap.parse_args()

    envs = (a.only,) if a.only else ENVS
    if a.only and a.only not in ENVS:
        raise SystemExit("make_manifest: unknown env %s" % a.only)

    dist = a.dist or (os.path.dirname(a.out) or ".")
    os.makedirs(dist, exist_ok=True)

    builds = {}
    missing = []
    for env in envs:
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

    if not a.no_factory:
        for env in envs:
            if env not in FACTORY:
                continue
            name = "firmware-%s-factory.bin" % env
            out_path = os.path.join(dist, name)
            merge_factory(env, a.build_dir, out_path, a.esptool, a.boot_app0, a.python)
            builds[env]["factory"] = {
                "url": a.release_base.rstrip("/") + "/" + name,
                "sha256": sha256_of(out_path),
            }
            print("make_manifest: merged %s (%d bytes)" % (name, os.path.getsize(out_path)))

    manifest = {"firmware_version": a.version, "builds": builds}

    out_dir = os.path.dirname(a.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")

    print("make_manifest: wrote %s (version=%s, %d builds)" % (a.out, a.version, len(builds)))


if __name__ == "__main__":
    main()
