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

With --ewt-out it ALSO writes an ESP Web Tools manifest (docs/flash/manifest.json) for the
browser flasher. That one lists the SEPARATE PARTS at their real offsets rather than the merged
factory image, and the difference matters: merge_bin pads the gaps between parts with 0xFF, and
the NVS partition sits in one of those gaps (0x9000-0xe000 here). Flashing a merged image over a
working board therefore overwrites NVS with 0xFF and silently destroys the miner key and the
stored Wi-Fi credentials — exactly what "leave Erase unchecked to keep your settings" promises not
to do. Parts skip the gaps, so NVS is never touched. The merged factory images stay: the OTA
release path and the existing docs/flash/fw/manifest.json still use them.

Offsets and flash settings below are not guesses — they were read back from the actual
`pio run -t upload` command line for each environment, and every offset this tool writes is
re-checked against the partition table in the build's own partitions.bin before it is emitted.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys

ENVS = ("esp8266", "esp32", "esp32s3", "esp32c3")

# env -> (esptool chip, bootloader offset, flash_mode, flash_freq, flash_size)
#
# flash_size is the value esptool stamps into the BOOTLOADER image header (byte 0x3, high nibble)
# via merge_bin's _update_image_flash_params, and only at the bootloader offset. It must describe
# a size the receiving chip actually has, NOT the size of the dev board we happen to build on.
#
# esp32s3 declared "8MB" here because esp32-s3-devkitc-1 is the N8 part. That is a brick risk for
# anyone else: docs/flash/index.html writes the merged image with flashSize:"keep", so this header
# reaches the chip verbatim, and docs/flash/chipfamily.js maps EVERY ESP32-S3 to this one image
# with no N4/N8/N16 discrimination (esptool reports the die, never the module). A 4 MB S3 - the
# S3-WROOM-1-N4 and the common clone DevKitC-1s - would then boot a header claiming more flash
# than it has, which the second-stage bootloader treats as a hard failure, whereas a header
# claiming LESS than the chip has is only a benign warning.
#
# "4MB" is therefore strictly safer and costs nothing: board_build.partitions = min_spiffs.csv
# (platformio.ini [esp32common]) ends at exactly 0x400000, so no environment addresses flash
# beyond 4 MB regardless of the part fitted.
FACTORY = {
    "esp32":   ("esp32",   "0x1000", "dio", "40m", "4MB"),
    "esp32s3": ("esp32s3", "0x0",    "dio", "80m", "4MB"),
    "esp32c3": ("esp32c3", "0x0",    "dio", "80m", "4MB"),
}

# ESP Web Tools treats a connected board as an UPDATE of this product, rather than a different
# product to install, only when the firmware NAME the board reports over Improv Serial equals this
# string exactly (`firmware===this._manifest.name` in the vendored bundle). The device side is
# kImprovFirmwareName in src/core/improv_serial_glue.cpp; tools/check_flasher_assets.py asserts the
# two are still the same string, because a silent drift turns every future update into a new
# install and an erase prompt.
IMPROV_FIRMWARE_NAME = "Fry Firmware"

# Seconds ESP Web Tools waits after a flash for the board to answer over Improv Serial before it
# gives up and shows the plain "installed" screen. THIS IS THE ONE PLACE TO CHANGE IT: measure
# boot banner -> first Improv response on real hardware and put the measured value here. The
# library's own default when the field is absent is 10 s.
IMPROV_WAIT_TIME_S = 20

# env -> the chipFamily string ESP Web Tools matches against the chip it detects over serial.
EWT_CHIP_FAMILY = {
    "esp8266": "ESP8266",
    "esp32": "ESP32",
    "esp32s3": "ESP32-S3",
    "esp32c3": "ESP32-C3",
}

# Fixed offsets shared by every ESP32-family layout here (the bootloader offset is per-chip and
# comes from FACTORY above). Both are asserted against the build's partitions.bin.
OTADATA_OFFSET = 0xE000
APP_OFFSET = 0x10000

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


# ESP-IDF partition table: 32-byte entries, each starting with the magic 0x50AA, ending at an MD5
# entry (0xEBEB) or 0xFF padding. Parsed rather than assumed so the offsets written into the web
# manifest are the offsets the firmware itself was linked against.
PART_MAGIC = b"\xaa\x50"
PART_MD5_MAGIC = b"\xeb\xeb"
PART_TYPE_APP = 0
PART_TYPE_DATA = 1
PART_SUBTYPE_DATA_OTA = 0x00  # "otadata"


def parse_partition_table(path):
    """Returns [{type, subtype, offset, size, label}] from a partitions.bin."""
    with open(path, "rb") as f:
        raw = f.read()
    entries = []
    for pos in range(0, len(raw) - 31, 32):
        chunk = raw[pos:pos + 32]
        if chunk[:2] == PART_MD5_MAGIC:
            continue
        if chunk[:2] != PART_MAGIC:
            break
        ptype, subtype = chunk[2], chunk[3]
        offset = int.from_bytes(chunk[4:8], "little")
        size = int.from_bytes(chunk[8:12], "little")
        label = chunk[12:28].rstrip(b"\x00").decode("utf-8", "replace")
        entries.append({"type": ptype, "subtype": subtype, "offset": offset,
                        "size": size, "label": label})
    if not entries:
        raise SystemExit("make_manifest: %s holds no partition entries" % path)
    return entries


def check_parts_against_table(env, parts, table):
    """Fails unless every part lands where the partition table says it should.

    The app must sit at the app partition's own offset and fit inside it, boot_app0 must sit on
    otadata, and NOTHING may touch a data partition other than otadata - nvs is where the miner
    key and the Wi-Fi credentials live, and a part that overlapped it would wipe them on an
    update that promised to keep them.
    """
    app_parts = [p for p in table if p["type"] == PART_TYPE_APP]
    if not app_parts:
        raise SystemExit("make_manifest: %s partition table has no app partition" % env)
    app = min(app_parts, key=lambda p: p["offset"])
    otadata = [p for p in table
               if p["type"] == PART_TYPE_DATA and p["subtype"] == PART_SUBTYPE_DATA_OTA]

    for offset, path in parts:
        size = os.path.getsize(path)
        name = os.path.basename(path)
        if name.startswith("firmware"):
            if offset != app["offset"]:
                raise SystemExit("make_manifest: %s app part at 0x%x but partition '%s' is at 0x%x"
                                 % (env, offset, app["label"], app["offset"]))
            if size > app["size"]:
                raise SystemExit("make_manifest: %s app is %d bytes, partition '%s' holds %d"
                                 % (env, size, app["label"], app["size"]))
        if name.startswith("boot_app0"):
            if not otadata or offset != otadata[0]["offset"]:
                raise SystemExit("make_manifest: %s boot_app0 part at 0x%x but otadata is at %s"
                                 % (env, offset, "0x%x" % otadata[0]["offset"] if otadata else "absent"))
        for entry in table:
            if entry["type"] != PART_TYPE_DATA or entry["subtype"] == PART_SUBTYPE_DATA_OTA:
                continue
            if offset < entry["offset"] + entry["size"] and entry["offset"] < offset + size:
                raise SystemExit(
                    "make_manifest: %s part %s (0x%x..0x%x) overlaps data partition '%s' "
                    "(0x%x..0x%x) - flashing it would erase stored settings"
                    % (env, name, offset, offset + size, entry["label"],
                       entry["offset"], entry["offset"] + entry["size"]))


def check_parts_against_factory(env, parts, factory_path):
    """Cross-check: every part must appear verbatim at its offset in the merged factory image."""
    with open(factory_path, "rb") as f:
        merged = f.read()
    for offset, path in parts:
        with open(path, "rb") as f:
            data = f.read()
        if merged[offset:offset + len(data)] != data:
            raise SystemExit("make_manifest: %s part %s does not match the factory image at 0x%x"
                             % (env, os.path.basename(path), offset))


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


def copy_file(src, dst):
    with open(src, "rb") as fsrc, open(dst, "wb") as fdst:
        fdst.write(fsrc.read())
    return dst


def write_ewt_manifest(envs, version, build_dir, dist, asset_base, boot_app0, out_path):
    """Writes the ESP Web Tools manifest, copying each part into `dist` next to the images.

    Parts, deliberately, not the merged factory image - see the module docstring.
    """
    builds = []
    for env in envs:
        env_dir = os.path.join(build_dir, env)
        app = os.path.join(env_dir, "firmware.bin")
        if env == "esp8266":
            # A complete 0x0 image already: bootloader, user1 and everything else in one file.
            parts = [(0x0, copy_file(app, os.path.join(dist, "firmware-esp8266.bin")))]
        else:
            bl_off = int(FACTORY[env][1], 16)
            parts = [
                (bl_off, copy_file(os.path.join(env_dir, "bootloader.bin"),
                                   os.path.join(dist, "bootloader-%s.bin" % env))),
                (0x8000, copy_file(os.path.join(env_dir, "partitions.bin"),
                                   os.path.join(dist, "partitions-%s.bin" % env))),
                (OTADATA_OFFSET, copy_file(boot_app0,
                                           os.path.join(dist, "boot_app0-%s.bin" % env))),
                (APP_OFFSET, copy_file(app, os.path.join(dist, "firmware-%s.bin" % env))),
            ]
            check_parts_against_table(env, parts,
                                      parse_partition_table(os.path.join(env_dir, "partitions.bin")))
            factory = os.path.join(dist, "firmware-%s-factory.bin" % env)
            if os.path.isfile(factory):
                check_parts_against_factory(env, parts, factory)

        builds.append({
            "chipFamily": EWT_CHIP_FAMILY[env],
            "parts": [{
                "path": "%s/%s" % (asset_base.rstrip("/"), os.path.basename(path)),
                "offset": offset,
                # Not an ESP Web Tools field - it reads only path and offset and ignores the
                # rest. tools/check_flasher_assets.py uses it to prove the published bytes are
                # the bytes this tool measured, which the upstream format has no way to express.
                "sha256": sha256_of(path),
            } for offset, path in parts],
        })

    manifest = {
        "name": IMPROV_FIRMWARE_NAME,
        "version": version,
        "new_install_prompt_erase": True,
        "new_install_improv_wait_time": IMPROV_WAIT_TIME_S,
        "builds": builds,
    }
    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    print("make_manifest: wrote %s (ESP Web Tools, %d builds, %d parts)"
          % (out_path, len(builds), sum(len(b["parts"]) for b in builds)))


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
    ap.add_argument("--ewt-out", default=None,
                    help="also write an ESP Web Tools manifest here (e.g. docs/flash/manifest.json)")
    ap.add_argument("--ewt-asset-base", default="fw",
                    help="path prefix, relative to --ewt-out, under which the parts are published")
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

    # Copy the plain per-env images into the dist directory alongside the merged factory ones.
    # The manifest names them unconditionally, and ESP8266 has no factory variant at all, so a
    # dist that holds only factory images publishes a manifest whose esp8266 url 404s. This used
    # to be done by hand after running the tool, which is exactly how the published flasher drifted
    # a release behind the source.
    if a.dist:
        for env in envs:
            src = os.path.join(a.build_dir, env, "firmware.bin")
            dst = os.path.join(dist, "firmware-%s.bin" % env)
            if os.path.abspath(src) != os.path.abspath(dst):
                with open(src, "rb") as fsrc, open(dst, "wb") as fdst:
                    fdst.write(fsrc.read())
                print("make_manifest: copied %s (%d bytes)" % (
                    os.path.basename(dst), os.path.getsize(dst)))

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

    if a.ewt_out:
        if a.no_factory:
            # The factory cross-check is the only independent confirmation that a part carries the
            # right bytes at the right offset, and it is cheap. Refuse rather than skip it quietly.
            raise SystemExit("make_manifest: --ewt-out needs the factory images (drop --no-factory)")
        write_ewt_manifest(envs, a.version, a.build_dir, dist, a.ewt_asset_base, a.boot_app0,
                           a.ewt_out)

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
