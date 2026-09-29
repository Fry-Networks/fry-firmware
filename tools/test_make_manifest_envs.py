# Tests for tools/make_manifest.py --envs and --ewt-merge (round 2, R5: this release holds
# esp32s3 and esp8266 back entirely). Dependency-free, same style as tools/test_scan_identity.py:
#
#   python3 tools/test_make_manifest_envs.py                   # test the sibling make_manifest.py
#   python3 tools/test_make_manifest_envs.py <path-to-a-copy>  # test a specific copy (pre-fix proof)
#
# Exit 0 = all pass, 1 = a failure. No esptool: a stand-in writes the merged image.
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "make_manifest.py")

passed = 0
failed = 0

FAKE_ESPTOOL = r'''
import sys
args = sys.argv[1:]
out = args[args.index("-o") + 1]
pairs = args[args.index("--flash_size") + 2:]
image = bytearray()
for off, path in zip(pairs[0::2], pairs[1::2]):
    data = open(path, "rb").read()
    o = int(off, 16)
    if len(image) < o + len(data):
        image.extend(b"\xff" * (o + len(data) - len(image)))
    image[o:o + len(data)] = data
open(out, "wb").write(bytes(image))
'''


def check(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print("  PASS  %s" % name)
    else:
        failed += 1
        print("  FAIL  %s  %s" % (name, detail))


def partition_table():
    """nvs 0x9000+0x5000, otadata 0xe000+0x2000, app0 0x10000+0x1E0000 - min_spiffs-shaped."""
    def entry(ptype, subtype, offset, size, label):
        return (b"\xaa\x50" + bytes([ptype, subtype]) + struct.pack("<II", offset, size)
                + label.encode().ljust(16, b"\x00") + b"\x00" * 4)
    table = (entry(1, 0x02, 0x9000, 0x5000, "nvs") + entry(1, 0x00, 0xE000, 0x2000, "otadata")
             + entry(0, 0x10, 0x10000, 0x1E0000, "app0"))
    return table + b"\xff" * (0xC00 - len(table))


def build_tree(root, envs):
    for env in envs:
        d = os.path.join(root, env)
        os.makedirs(d)
        with open(os.path.join(d, "firmware.bin"), "wb") as f:
            f.write(("app-0.4.0-%s" % env).encode() * 64)
        with open(os.path.join(d, "bootloader.bin"), "wb") as f:
            f.write(b"B" * 64)
        with open(os.path.join(d, "partitions.bin"), "wb") as f:
            f.write(partition_table())


def run(tmp, *extra):
    out = os.path.join(tmp, "out", "manifest.json")
    if os.path.exists(out):
        os.remove(out)
    cmd = [sys.executable, TOOL, "--version", "0.4.0", "--release-base", "fw",
           "--build-dir", os.path.join(tmp, "build"), "--out", out] + list(extra)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    m = None
    if proc.returncode == 0 and os.path.exists(out):
        with open(out, encoding="utf-8") as f:
            m = json.load(f)
    return proc.returncode, proc.stdout + proc.stderr, m


def main():
    tmp = tempfile.mkdtemp(prefix="mm-envs-")
    try:
        # Only the released chips were built: no esp32s3 / esp8266 build dirs at all.
        build_tree(os.path.join(tmp, "build"), ("esp32", "esp32c3"))
        dist = os.path.join(tmp, "dist")
        esptool = os.path.join(tmp, "fake_esptool.py")
        with open(esptool, "w") as f:
            f.write(FAKE_ESPTOOL)
        boot_app0 = os.path.join(tmp, "boot_app0.bin")
        with open(boot_app0, "wb") as f:
            f.write(b"\x00" * 32)
        held_parts = {
            "ESP8266": [{"path": "fw/hold/firmware-esp8266.bin", "offset": 0, "sha256": "3" * 64}],
            "ESP32-S3": [{"path": "fw/hold/%s-esp32s3.bin" % n, "offset": o, "sha256": "4" * 64}
                         for n, o in (("bootloader", 0), ("partitions", 32768), ("boot_app0", 57344),
                                      ("firmware", 65536))],
        }
        hold = os.path.join(tmp, "manifest-hold.json")
        with open(hold, "w") as f:
            json.dump({"name": "Fry Firmware", "version": "0.3.3",
                       "builds": [{"chipFamily": k, "parts": v} for k, v in held_parts.items()]}, f)

        print("--envs esp32,esp32c3 (the held chips were never built):")
        rc, log, m = run(tmp, "--envs", "esp32,esp32c3", "--no-factory", "--dist", dist)
        check("exit 0 without esp32s3/esp8266 build dirs", rc == 0, log)
        check("builds{} is esp32 + esp32c3", sorted((m or {}).get("builds", {})) == ["esp32", "esp32c3"], m)
        check("nothing for the held chips is copied to dist",
              not os.path.exists(os.path.join(dist, "firmware-esp32s3.bin"))
              and not os.path.exists(os.path.join(dist, "firmware-esp8266.bin")))

        print("argument checks:")
        rc, log, _ = run(tmp, "--envs", "esp32,esp32s4", "--no-factory")
        check("an unknown env is refused", rc != 0 and "esp32s4" in log, log)
        rc, log, _ = run(tmp, "--envs", "esp32", "--only", "esp32", "--no-factory")
        check("--only with --envs is refused", rc != 0, log)
        rc, log, _ = run(tmp, "--envs", "esp32", "--ewt-merge", hold, "--no-factory")
        check("--ewt-merge without --ewt-out is refused", rc != 0, log)

        print("--ewt-out with --ewt-merge (the post-canary flasher commit):")
        ewt = os.path.join(tmp, "flash", "manifest.json")
        rc, log, m = run(tmp, "--envs", "esp32,esp32c3", "--dist", os.path.join(tmp, "flash", "fw"),
                         "--esptool", esptool, "--boot-app0", boot_app0, "--ewt-out", ewt,
                         "--ewt-merge", hold)
        check("exit 0", rc == 0, log)
        e = json.load(open(ewt)) if os.path.exists(ewt) else {}
        fams = sorted(b["chipFamily"] for b in e.get("builds", []))
        check("all four chip families are listed", fams == ["ESP32", "ESP32-C3", "ESP32-S3", "ESP8266"], fams)
        check("the manifest version is the new release", e.get("version") == "0.4.0", e.get("version"))
        carried = {b["chipFamily"]: b["parts"] for b in e.get("builds", [])
                   if b["chipFamily"] in held_parts}
        check("held chips keep their previous parts byte-for-byte", carried == held_parts, carried)
        new_paths = [p["path"] for b in e.get("builds", []) if b["chipFamily"] in ("ESP32", "ESP32-C3")
                     for p in b["parts"]]
        check("released chips point at freshly written parts",
              "fw/firmware-esp32.bin" in new_paths and "fw/firmware-esp32c3.bin" in new_paths, new_paths)
        check("no held path is overwritten",
              not os.path.exists(os.path.join(tmp, "flash", "fw", "hold")))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
