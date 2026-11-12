# Tests for the ESP32-S3 release path of .github/workflows/release-fw.yml:
#
#   (a) make_manifest.py accepts `--include-env esp32s3` next to `--include-env esp8266`, lists esp32s3
#       with url + sha256 only (no rollout), and every other entry is identical to the manifest
#       without the flag (the committed tools/ota_channels.json is not edited);
#   (b) the workflow builds esp32s3, attaches its plain and factory image, and runs the second
#       manifest step with a committed literal flag; the first (three-chip) manifest step is untouched;
#   (c) the second step's assertion (the python heredoc, extracted and EXECUTED here) passes the good
#       manifest and fails each bad one.
#
#   python3 tools/test_release_fw_esp32s3.py
# Exit 0 = all pass, 1 = a failure. Dependency-free; reuses the fixtures of test_make_manifest_envs.py.
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import test_make_manifest_envs as E  # noqa: E402  (helpers: build_tree)

TOOL = os.path.join(HERE, "make_manifest.py")
ALL = ("esp8266", "esp32", "esp32s3", "esp32c3")

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


def run(tmp, tag, *extra):
    out = os.path.join(tmp, "out-" + tag, "manifest.json")
    cmd = [sys.executable, TOOL, "--version", "0.4.29", "--channel", "prod",
           "--release-base", "https://example.invalid/releases/download/fw-v0.4.29",
           "--build-dir", os.path.join(tmp, "build"), "--out", out, "--no-factory",
           "--dist", os.path.join(tmp, "dist-" + tag),
           "--channels-config", os.path.join(HERE, "ota_channels.json")] + list(extra)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    raw = None
    if os.path.exists(out):
        with open(out, "rb") as f:
            raw = f.read()
    return proc.returncode, proc.stdout + proc.stderr, raw


def second_step_assertion(wf):
    """The python heredoc of the 'Add the ESP32-S3 entry' step, dedented, or None."""
    lines = wf.split("\n")
    for i, line in enumerate(lines):
        if line.strip() == "- name: Add the ESP32-S3 entry to the prod manifest":
            for j in range(i, len(lines)):
                if lines[j].strip() == "python3 - <<'EOF'":
                    k = j + 1
                    while k < len(lines) and lines[k].strip() != "EOF":
                        k += 1
                    return textwrap.dedent("\n".join(lines[j + 1:k]))
    return None


def run_assertion(script, before, after, tmp, tag):
    root = os.path.join(tmp, "assert-" + tag)
    os.makedirs(os.path.join(root, "ota"))
    with open(os.path.join(root, "manifest-three-chips.json"), "w", encoding="utf-8") as f:
        json.dump(before, f)
    with open(os.path.join(root, "ota", "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(after, f)
    proc = subprocess.run([sys.executable, "-I", "-c", script], cwd=root, capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def main():
    tmp = tempfile.mkdtemp(prefix="rel-s3-")
    good = three = None
    try:
        E.build_tree(os.path.join(tmp, "build"), ALL)
        cfg = json.load(open(os.path.join(HERE, "ota_channels.json")))

        print("(a) make_manifest --include-env esp32s3:")
        rc, log, raw = run(tmp, "three", "--envs", "esp32,esp32c3,esp8266,esp32s3", "--include-env", "esp8266")
        three = json.loads(raw) if raw else {}
        check("without the s3 flag s3 is left out (committed exclusion)", rc == 0 and "esp32s3" not in three.get("builds", {})
              and "esp32s3 left out" in log, log)
        rc, log, raw = run(tmp, "four", "--envs", "esp32,esp32c3,esp8266,esp32s3",
                           "--include-env", "esp8266", "--include-env", "esp32s3")
        good = json.loads(raw) if raw else {}
        check("exit 0 and four builds", rc == 0 and sorted(good.get("builds", {})) ==
              ["esp32", "esp32c3", "esp32s3", "esp8266"], (rc, log))
        check("esp32s3 entry is url + sha256 only", sorted(good.get("builds", {}).get("esp32s3", {})) == ["sha256", "url"],
              good.get("builds"))
        check("esp32s3 url is the release asset", good.get("builds", {}).get("esp32s3", {}).get("url") ==
              "https://example.invalid/releases/download/fw-v0.4.29/firmware-esp32s3.bin")
        gb, tb = good.get("builds", {}), three.get("builds", {})
        check("the only difference from the no-s3-flag manifest is builds.esp32s3",
              bool(gb) and {k: v for k, v in good.items() if k != "builds"} == {k: v for k, v in three.items() if k != "builds"}
              and {k: v for k, v in gb.items() if k != "esp32s3"} == tb)
        check("the committed prod config is not edited (still excludes esp32s3 and esp8266)",
              sorted(cfg["channels"]["prod"]["exclude_from_builds"]) == ["esp32s3", "esp8266"])

        print("(b) release-fw.yml:")
        wf = open(os.path.join(HERE, "..", ".github", "workflows", "release-fw.yml"), encoding="utf-8").read()
        check("esp32s3 joins the build matrix by include (the three-chip matrix line is untouched)",
              re.search(r"env: \[esp32, esp32c3, esp8266\]\n\s+include:\n\s+- env: esp32s3\n", wf) is not None)
        check("the s3 plain and factory images are attached",
              "release/firmware-esp32s3.bin" in wf and "release/firmware-esp32s3-factory.bin" in wf)
        check("the s3 image is copied into the manifest input layout",
              re.search(r"for env in esp32 esp32c3 esp8266 esp32s3; do", wf) is not None)
        check("the three-chip manifest step is untouched",
              "--envs esp32,esp32c3,esp8266 --include-env esp8266 --release-base" in wf
              and '{"esp32", "esp32c3", "esp8266"} - excluded' in wf)
        check("the second step passes a committed literal --include-env esp32s3",
              re.search(r"--envs esp32,esp32c3,esp8266,esp32s3 --include-env esp8266 --include-env esp32s3 ", wf) is not None)
        check("no repo variable or rollout flag feeds the manifest", "vars." not in wf and "--rollout" not in wf)
        check("the flasher hold check is untouched (the flasher still serves the 0.3.3 S3 parts)",
              'assert sorted(held) == ["ESP32-S3", "ESP8266"], sorted(held)' in wf)
        check("this test runs in the release tooling tests", "tools/test_release_fw_esp32s3.py" in wf)

        print("(c) the second step's assertion:")
        script = second_step_assertion(wf)
        check("the assertion heredoc is found", script is not None)
        if script is not None and good and three:
            def mutated(fn):
                m = json.loads(json.dumps(good))
                fn(m)
                return m

            rc, out = run_assertion(script, three, good, tmp, "good")
            check("passes the good manifest", rc == 0, out)
            bad = (
                ("no esp32s3 entry (the flag removed)", three),
                ("a per-build rollout key on esp32s3", mutated(lambda m: m["builds"]["esp32s3"].update(
                    rollout={"bucket_lo": 0, "bucket_hi": 9}))),
                ("a top-level rollout key", mutated(lambda m: m.update(rollout={"bucket_lo": 0, "bucket_hi": 9}))),
                ("an esp32 entry changed", mutated(lambda m: m["builds"]["esp32"].update(sha256="0" * 64))),
                ("the esp8266 entry missing", mutated(lambda m: m["builds"].pop("esp8266"))),
                ("a short esp32s3 sha256", mutated(lambda m: m["builds"]["esp32s3"].update(sha256="ab"))),
                ("an empty esp32s3 url", mutated(lambda m: m["builds"]["esp32s3"].update(url=""))),
                ("channel test", mutated(lambda m: m.update(channel="test"))),
                ("another top-level field changed", mutated(lambda m: m.update(firmware_version="9.9.9"))),
            )
            for n, (label, m) in enumerate(bad):
                rc, out = run_assertion(script, three, m, tmp, "bad%d" % n)
                check("fails: %s" % label, rc != 0 and "AssertionError" in out, (rc, out))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
