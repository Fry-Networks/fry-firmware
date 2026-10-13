# Tests for the ESP8266 entry tools/make_manifest.py writes into builds{}: board_id, flash_size,
# size and version appear on esp8266 only (PROTOCOL.md 11.5). Dependency-free, same style as
# tools/test_make_manifest_exclude.py:
#
#   python3 tools/test_make_manifest_esp8266.py
#
# Exit 0 = all pass, 1 = a failure.
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "make_manifest.py")
ENVS = ("esp8266", "esp32", "esp32s3", "esp32c3")

passed = 0
failed = 0


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
            f.write(("image-%s" % env).encode() * (50 + len(env)))


def run(tmp, *extra):
    out = os.path.join(tmp, "out", "manifest.json")
    if os.path.exists(out):
        os.remove(out)
    cmd = [sys.executable, TOOL, "--version", "0.4.2", "--no-factory",
           "--release-base", "https://github.com/Fry-Networks/fry-firmware/releases/download/fw-v0.4.2",
           "--build-dir", os.path.join(tmp, "build"), "--out", out] + list(extra)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    manifest = None
    if proc.returncode == 0 and os.path.exists(out):
        with open(out, encoding="utf-8") as f:
            manifest = json.load(f)
    return proc.returncode, proc.stdout + proc.stderr, manifest


def main():
    tmp = tempfile.mkdtemp(prefix="mm-esp8266-")
    try:
        build_tree(os.path.join(tmp, "build"))
        img = os.path.join(tmp, "build", "esp8266", "firmware.bin")
        data = open(img, "rb").read()

        print("prod manifest, esp8266 entry:")
        rc, log, m = run(tmp)
        check("exit 0", rc == 0, log)
        e = ((m or {}).get("builds") or {}).get("esp8266", {})
        check("board_id is esp8266-4m1m", e.get("board_id") == "esp8266-4m1m", e)
        check("flash_size is 4194304 (int)", e.get("flash_size") == 4194304
              and isinstance(e.get("flash_size"), int), e)
        check("size is the image's byte count", e.get("size") == len(data), e)
        check("version defaults to --version", e.get("version") == "0.4.2", e)
        check("sha256 is the image's", e.get("sha256") == hashlib.sha256(data).hexdigest(), e)
        check("url is the esp8266 app image",
              e.get("url", "").endswith("/fw-v0.4.2/firmware-esp8266.bin"), e)
        check("no factory entry", "factory" not in e, e)

        print("--esp8266-version overrides only that field:")
        rc, log, m = run(tmp, "--esp8266-version", "0.4.34")
        e = ((m or {}).get("builds") or {}).get("esp8266", {})
        check("builds.esp8266.version is 0.4.34", e.get("version") == "0.4.34", e)
        check("top-level firmware_version unchanged", (m or {}).get("firmware_version") == "0.4.2", m)

        print("other chips are unchanged:")
        b = (m or {}).get("builds") or {}
        for env in ("esp32", "esp32c3"):
            check("%s has exactly url + sha256" % env, sorted(b.get(env, {})) == ["sha256", "url"],
                  b.get(env))
        rc, log, m = run(tmp, "--no-exclusions")
        check("esp32s3 (kept by --no-exclusions) has exactly url + sha256",
              sorted(((m or {}).get("builds") or {}).get("esp32s3", {})) == ["sha256", "url"], m)

        print("test channel carries the same fields:")
        rc, log, m = run(tmp, "--channel", "test")
        e = ((m or {}).get("builds") or {}).get("esp8266", {})
        check("board_id/flash_size/size/version present",
              sorted(k for k in e if k not in ("url", "sha256")) ==
              ["board_id", "flash_size", "size", "version"], e)

        print("size follows the file (positive control):")
        with open(img, "ab") as f:
            f.write(b"x" * 7)
        rc, log, m = run(tmp)
        e = ((m or {}).get("builds") or {}).get("esp8266", {})
        check("size grew by 7", e.get("size") == len(data) + 7, e)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
