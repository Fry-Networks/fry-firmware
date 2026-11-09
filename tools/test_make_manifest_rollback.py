# Tests for tools/make_manifest.py --rollback-* (manifest-directed rollback, PROTOCOL.md 11.11,
# lib/fry_core/ota_rollback_json.h). Dependency-free, same style as tools/test_make_manifest_rollout.py:
#
#   python3 tools/test_make_manifest_rollback.py                   # test the sibling make_manifest.py
#   python3 tools/test_make_manifest_rollback.py <path-to-a-copy>  # test a specific copy (pre-change proof)
#
# Exit 0 = all pass, 1 = a failure. Not part of the release workflow.
#   (a) without the flags the manifest is byte-identical to what the tool wrote before the flags existed
#   (b) with them builds.<env>.rollback is emitted, every other key unchanged
#   (c) bad or partial input is refused (non-zero exit, no manifest written)
import hashlib
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "make_manifest.py")

# Same golden as test_make_manifest_rollout.py: the pre-change tool's bytes for the inputs in run() below.
GOLDEN_NO_FLAGS_SHA256 = "93d356929aa53fe4fc2dac9130bdb25eafdb07c3ec3c2b3eedff1c7c328bf091"
ENVS = ("esp32", "esp32c3", "esp8266")
SHA = "ab" * 32
URL = "https://github.com/Fry-Networks/fry-firmware/releases/download/fw-v0.4.24/firmware-esp32.bin"

passed = 0
failed = 0
runs = 0


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


def run(tmp, *extra, version="0.4.8"):
    global runs
    runs += 1
    out = os.path.join(tmp, "out%d" % runs, "manifest.json")  # a fresh path per run: nothing to clear
    cmd = [sys.executable, TOOL, "--version", version, "--release-base", "https://example.invalid/rel",
           "--build-dir", os.path.join(tmp, "build"), "--out", out, "--no-factory", "--no-exclusions",
           "--envs", ",".join(ENVS)] + list(extra)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    raw = None
    if os.path.exists(out):
        with open(out, "rb") as f:
            raw = f.read()
    return proc.returncode, proc.stdout + proc.stderr, raw


def flags(env="esp32", version="0.4.7", url=URL, sha=SHA, frm="0.4.8"):
    return ["--rollback-env", env, "--rollback-version", version, "--rollback-url", url,
            "--rollback-sha256", sha, "--rollback-from", frm]


def refused(rc, log, raw):
    """Refused by the tool's own validation: argparse not knowing the flag does not count."""
    return rc != 0 and raw is None and "unrecognized arguments" not in log and "rollback" in log


def main():
    with tempfile.TemporaryDirectory(prefix="mm-rollback-") as tmp:
        build_tree(os.path.join(tmp, "build"))

        print("no flags (byte-identical to the pre-change tool):")
        rc, log, raw = run(tmp)
        check("exit 0", rc == 0, log)
        check("manifest sha256 equals the pre-change golden",
              raw is not None and hashlib.sha256(raw).hexdigest() == GOLDEN_NO_FLAGS_SHA256,
              hashlib.sha256(raw or b"").hexdigest())
        base = json.loads(raw) if raw else {}
        check("no rollback key anywhere", raw is not None and b"rollback" not in raw)

        print("emission:")
        rc, log, raw = run(tmp, *flags(sha=("AB" * 32), frm="0.4.8, 0.4.8"))
        m = json.loads(raw) if raw else {}
        check("exit 0", rc == 0, log)
        want = {"version": "0.4.7", "url": URL, "sha256": SHA, "from": ["0.4.8"]}
        check("builds.esp32.rollback has version/url/sha256(lower-cased)/from(de-duplicated)",
              m.get("builds", {}).get("esp32", {}).get("rollback") == want, m.get("builds", {}).get("esp32"))
        check("only the named env carries it",
              all("rollback" not in m.get("builds", {}).get(e, {}) for e in ("esp32c3", "esp8266")))
        stripped = json.loads(raw) if raw else {}
        if stripped:
            stripped["builds"]["esp32"].pop("rollback", None)
        check("every other key unchanged", stripped == base)
        rc, log, raw = run(tmp, *flags(frm="0.4.9,0.4.8"), version="0.4.8")
        check("several from-versions are sorted and kept",
              rc == 0 and json.loads(raw)["builds"]["esp32"]["rollback"]["from"] == ["0.4.8", "0.4.9"], log)
        rc, log, raw = run(tmp, *flags(version="0.4.8-rc.1", frm="0.4.8"))
        check("a pre-release target below its release is accepted", rc == 0, log)

        print("refusals (no manifest written):")
        rc, log, raw = run(tmp, "--rollback-env", "esp32", "--rollback-version", "0.4.7")
        check("partial flags", refused(rc, log, raw), log)
        for label, kw in (
            ("empty sha256", dict(sha="")),
            ("short sha256", dict(sha="abcd")),
            ("non-hex sha256", dict(sha="zz" * 32)),
            ("http url", dict(url="http://example.invalid/x.bin")),
            ("empty from", dict(frm="")),
            ("garbage from entry", dict(frm="0.4.8,latest")),
            ("garbage version", dict(version="old")),
            ("version 0.0.0", dict(version="0.0.0")),
            ("version equal to from", dict(version="0.4.8", frm="0.4.8")),
            ("from entry older than the target", dict(version="0.4.8", frm="0.4.9,0.4.7")),
            ("unknown env", dict(env="esp9999")),
        ):
            rc, log, raw = run(tmp, *flags(**kw))
            check(label, refused(rc, log, raw), log)
        rc, log, raw = run(tmp, *flags(frm=",".join("0.5.%d" % i for i in range(17))))
        check("more than 16 from-versions", refused(rc, log, raw), log)
        rc, log, raw = run(tmp, *flags(frm="0.4.8"), version="0.4.9")
        check("manifest --version newer than a from entry (device would update forward)",
              refused(rc, log, raw), log)
        rc, log, raw = run(tmp, *flags(env="esp32s3"))
        check("env that is not among the built envs", rc != 0 and raw is None, log)
    print("%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
