# Tests for tools/make_manifest.py's channel + exclusion handling (tools/ota_channels.json).
# Dependency-free, same style as tools/test_scan_identity.py:
#
#   python3 tools/test_make_manifest_exclude.py                   # test the sibling make_manifest.py
#   python3 tools/test_make_manifest_exclude.py <path-to-a-copy>  # test a specific copy (pre-fix proof)
#
# Exit 0 = all pass, 1 = a failure. No esptool is needed: the factory-merge case uses a stand-in
# that writes the app at 0x10000, which is all make_manifest verifies about a merged image.
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "make_manifest.py")
CONFIG = os.path.join(HERE, "ota_channels.json")
ENVS = ("esp8266", "esp32", "esp32s3", "esp32c3")

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


def build_tree(root):
    for env in ENVS:
        d = os.path.join(root, env)
        os.makedirs(d)
        with open(os.path.join(d, "firmware.bin"), "wb") as f:
            f.write(("app-image-for-%s" % env).encode() * 64)
        if env != "esp8266":
            with open(os.path.join(d, "bootloader.bin"), "wb") as f:
                f.write(b"B" * 64)
            with open(os.path.join(d, "partitions.bin"), "wb") as f:
                f.write(b"P" * 64)


def run(tmp, *extra):
    out = os.path.join(tmp, "out", "manifest.json")
    if os.path.exists(out):
        os.remove(out)
    cmd = [sys.executable, TOOL, "--version", "0.4.0",
           "--release-base", "https://github.com/Fry-Networks/fry-firmware/releases/download/fw-v0.4.0",
           "--build-dir", os.path.join(tmp, "build"), "--out", out] + list(extra)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    manifest = None
    if proc.returncode == 0 and os.path.exists(out):
        with open(out, encoding="utf-8") as f:
            manifest = json.load(f)
    return proc.returncode, proc.stdout + proc.stderr, manifest


def main():
    tmp = tempfile.mkdtemp(prefix="mm-exclude-")
    try:
        build_tree(os.path.join(tmp, "build"))
        dist = os.path.join(tmp, "dist")
        esptool = os.path.join(tmp, "fake_esptool.py")
        boot_app0 = os.path.join(tmp, "boot_app0.bin")
        with open(esptool, "w") as f:
            f.write(FAKE_ESPTOOL)
        with open(boot_app0, "wb") as f:
            f.write(b"\x00" * 32)

        print("default (prod channel, committed exclusions):")
        rc, log, m = run(tmp, "--no-factory", "--dist", dist)
        check("exit 0", rc == 0, log)
        builds = sorted((m or {}).get("builds", {}))
        check("builds{} is esp32 + esp32c3 only", builds == ["esp32", "esp32c3"], builds)
        check("channel is prod", (m or {}).get("channel") == "prod", m)
        check("each url is its own chip's app image",
              all((m or {}).get("builds", {}).get(e, {}).get("url", "").endswith("/firmware-%s.bin" % e)
                  for e in ("esp32", "esp32c3")))
        check("excluded images are still copied for manual flashing",
              all(os.path.isfile(os.path.join(dist, "firmware-%s.bin" % e)) for e in ENVS))
        check("the exclusion is logged", "esp32s3 left out" in log and "esp8266 left out" in log, log)

        print("the committed config says what the release relies on:")
        with open(CONFIG, encoding="utf-8") as f:
            cfg = json.load(f)
        check("prod excludes esp32s3 and esp8266",
              sorted(cfg["channels"]["prod"]["exclude_from_builds"]) == ["esp32s3", "esp8266"])
        check("test excludes nothing", cfg["channels"]["test"]["exclude_from_builds"] == [])

        print("--channel test:")
        rc, log, m = run(tmp, "--no-factory", "--channel", "test")
        check("exit 0", rc == 0, log)
        check("all four builds", sorted((m or {}).get("builds", {})) == sorted(ENVS), m)
        check("channel is test", (m or {}).get("channel") == "test", m)

        print("--no-exclusions:")
        rc, log, m = run(tmp, "--no-factory", "--no-exclusions")
        check("all four builds", rc == 0 and sorted((m or {}).get("builds", {})) == sorted(ENVS), log)

        print("CI build-job shape: --only esp32s3 with a factory merge:")
        rc, log, m = run(tmp, "--only", "esp32s3", "--dist", dist, "--esptool", esptool,
                         "--boot-app0", boot_app0)
        check("exit 0 (no KeyError on an excluded env)", rc == 0, log)
        check("factory image still merged",
              os.path.isfile(os.path.join(dist, "firmware-esp32s3-factory.bin")), log)
        check("builds{} empty for the excluded env", (m or {}).get("builds") == {}, m)

        print("a config that names an unknown env is refused:")
        bad = os.path.join(tmp, "bad.json")
        with open(bad, "w") as f:
            json.dump({"channels": {"prod": {"exclude_from_builds": ["esp32s4"]}}}, f)
        rc, log, m = run(tmp, "--no-factory", "--channels-config", bad)
        check("non-zero exit", rc != 0, log)
        check("names the env", "esp32s4" in log, log)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
