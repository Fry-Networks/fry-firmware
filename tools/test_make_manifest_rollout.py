# Tests for tools/make_manifest.py --rollout-lo / --rollout-hi / --rollout-allow (staged OTA rollout,
# lib/fry_core/ota_rollout.h). Dependency-free, same style as tools/test_make_manifest_envs.py:
#
#   python3 tools/test_make_manifest_rollout.py                   # test the sibling make_manifest.py
#   python3 tools/test_make_manifest_rollout.py <path-to-a-copy>  # test a specific copy (pre-change proof)
#
# Exit 0 = all pass, 1 = a failure. Not part of the release workflow.
#   (a) without the flags the manifest is byte-identical to what the tool wrote before the flags
#       existed (sha256 pinned below, produced by the pre-change tool from the same inputs)
#   (b) with --rollout-lo/--rollout-hi the top-level "rollout" object is emitted, every other key
#       unchanged; --rollout-allow adds the sorted, lower-cased, de-duplicated 16-hex prefixes
#   (c) bad input is refused (non-zero exit, no manifest written)
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "make_manifest.py")

# sha256 of the manifest the PRE-CHANGE tool wrote for exactly the inputs in run() below.
GOLDEN_NO_FLAGS_SHA256 = "93d356929aa53fe4fc2dac9130bdb25eafdb07c3ec3c2b3eedff1c7c328bf091"
ENVS = ("esp32", "esp32c3", "esp8266")

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
            f.write(("app-image-for-%s" % env).encode() * 64)


def run(tmp, *extra):
    """Returns (rc, log, raw manifest bytes or None)."""
    out = os.path.join(tmp, "out", "manifest.json")
    if os.path.exists(out):
        os.remove(out)
    cmd = [sys.executable, TOOL, "--version", "0.4.8", "--release-base", "https://example.invalid/rel",
           "--build-dir", os.path.join(tmp, "build"), "--out", out, "--no-factory", "--no-exclusions",
           "--envs", ",".join(ENVS)] + list(extra)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    raw = None
    if os.path.exists(out):
        with open(out, "rb") as f:
            raw = f.read()
    return proc.returncode, proc.stdout + proc.stderr, raw


def refused(rc, log, raw):
    """Refused by the tool's own validation: argparse not knowing the flag does not count."""
    return rc != 0 and raw is None and "unrecognized arguments" not in log and "rollout" in log


def write(path, text):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    return path


def main():
    tmp = tempfile.mkdtemp(prefix="mm-rollout-")
    try:
        build_tree(os.path.join(tmp, "build"))

        print("no flags (byte-identical to the pre-change tool):")
        rc, log, raw = run(tmp)
        check("exit 0", rc == 0, log)
        check("manifest sha256 equals the pre-change golden",
              raw is not None and hashlib.sha256(raw).hexdigest() == GOLDEN_NO_FLAGS_SHA256,
              hashlib.sha256(raw or b"").hexdigest())
        check("no rollout key", raw is not None and "rollout" not in json.loads(raw))
        base = json.loads(raw) if raw else {}

        print("--rollout-lo / --rollout-hi:")
        rc, log, raw = run(tmp, "--rollout-lo", "0", "--rollout-hi", "10")
        m = json.loads(raw) if raw else {}
        check("exit 0", rc == 0, log)
        check("rollout is {bucket_lo:0, bucket_hi:10} with no allow key",
              m.get("rollout") == {"bucket_lo": 0, "bucket_hi": 10}, m.get("rollout"))
        check("every other key unchanged",
              {k: v for k, v in m.items() if k != "rollout"} == base, m)
        check("rollout values are JSON integers",
              all(type(v) is int for v in m.get("rollout", {}).values()))
        text = (raw or b"").decode()
        check("keys stay sorted and file ends with a newline",
              text.endswith("}\n") and text.index('"olostep_kill"') < text.index('"rollout"'))
        for lo, hi in ((0, 0), (99, 99), (0, 99), (37, 37)):
            rc, log, raw = run(tmp, "--rollout-lo", str(lo), "--rollout-hi", str(hi))
            r = json.loads(raw).get("rollout") if raw else None
            check("boundary %d..%d accepted" % (lo, hi), rc == 0 and r == {"bucket_lo": lo, "bucket_hi": hi}, log)

        print("--rollout-allow:")
        allow = write(os.path.join(tmp, "allow.txt"),
                      "ba7816bf8f01cfea\n\n  9FA03AE3C55D4DEB  \nba7816bf8f01cfea\n")
        rc, log, raw = run(tmp, "--rollout-lo", "0", "--rollout-hi", "5", "--rollout-allow", allow)
        r = json.loads(raw).get("rollout") if raw else None
        check("allow sorted, lower-cased, de-duplicated",
              rc == 0 and r == {"bucket_lo": 0, "bucket_hi": 5,
                                "allow": ["9fa03ae3c55d4deb", "ba7816bf8f01cfea"]}, (log, r))
        empty = write(os.path.join(tmp, "empty.txt"), "\n\n")
        rc, log, raw = run(tmp, "--rollout-lo", "0", "--rollout-hi", "5", "--rollout-allow", empty)
        r = json.loads(raw).get("rollout") if raw else None
        check("an empty allow file gives allow: []", rc == 0 and r == {"bucket_lo": 0, "bucket_hi": 5, "allow": []},
              (log, r))

        print("refused input (non-zero exit, no manifest written):")
        bad_allow = {
            "15 hex chars": "ba7816bf8f01cfe\n",
            "17 hex chars": "ba7816bf8f01cfea0\n",
            "non-hex": "ga7816bf8f01cfea\n",
            "a full 64-hex digest": "ba7816bf8f01cfeac3e5d6e3b4b0e5c2a1d9f8e7b6a5c4d3e2f1a0b9c8d7e6f5\n",
            "a raw key": "FEM-TEST-0001\n",
            "two entries on one line": "ba7816bf8f01cfea 9fa03ae3c55d4deb\n",
        }
        for label, content in bad_allow.items():
            p = write(os.path.join(tmp, "bad.txt"), content)
            rc, log, raw = run(tmp, "--rollout-lo", "0", "--rollout-hi", "5", "--rollout-allow", p)
            check("allow file with %s" % label, refused(rc, log, raw), (rc, log))
        cases = {
            "lo without hi": ["--rollout-lo", "5"],
            "hi without lo": ["--rollout-hi", "5"],
            "allow without lo/hi": ["--rollout-allow", allow],
            "lo > hi": ["--rollout-lo", "6", "--rollout-hi", "5"],
            "lo below 0": ["--rollout-lo", "-1", "--rollout-hi", "5"],
            "hi above 99": ["--rollout-lo", "0", "--rollout-hi", "100"],
            "lo above 99": ["--rollout-lo", "100", "--rollout-hi", "100"],
            "non-integer lo": ["--rollout-lo", "x", "--rollout-hi", "5"],
            "float hi": ["--rollout-lo", "0", "--rollout-hi", "5.5"],
            "missing allow file": ["--rollout-lo", "0", "--rollout-hi", "5",
                                   "--rollout-allow", os.path.join(tmp, "nope.txt")],
        }
        for label, args in cases.items():
            rc, log, raw = run(tmp, *args)
            check(label, refused(rc, log, raw), (rc, log))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
