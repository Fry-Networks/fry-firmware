# Tests for tools/make_manifest.py --include-env: a release overrides ONE env's channel exclusion on
# its command line (the committed tools/ota_channels.json is not edited). Used by release-fw.yml to
# put esp8266 in the prod manifest from 0.4.11. Dependency-free, same style as
# tools/test_make_manifest_envs.py:
#
#   python3 tools/test_make_manifest_include_env.py                   # test the sibling make_manifest.py
#   python3 tools/test_make_manifest_include_env.py <path-to-a-copy>  # test a specific copy (pre-change proof)
#
# Exit 0 = all pass, 1 = a failure.
#   (a) without the flag esp8266 stays out of the prod builds{} (today's manifest)
#   (b) with it the manifest differs from (a) ONLY by builds.esp8266 {url, sha256}; esp32/esp32c3
#       entries byte-identical; no "rollout" key anywhere (neither top-level nor per build)
#   (c) esp32s3 stays excluded when only esp8266 is included
#   (d) bad input is refused by the tool itself (non-zero exit, no manifest written), including an
#       env the channel does not exclude (a typo would otherwise be a silent no-op) and --no-exclusions
#   (e) the shipped client's selection (ota_client.cpp: builds[env].url|sha256) finds esp8266
#   (f) release-fw.yml passes the flag as a committed literal, and its manifest assertion (the python
#       heredoc, extracted and EXECUTED here) passes the good manifest and fails each bad one
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

TOOL = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "make_manifest.py")
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
    """Returns (rc, log, raw manifest bytes or None). Prod channel, committed exclusions."""
    out = os.path.join(tmp, "out-" + tag, "manifest.json")
    cmd = [sys.executable, TOOL, "--version", "0.4.11", "--channel", "prod",
           "--release-base", "https://example.invalid/releases/download/fw-v0.4.11",
           "--build-dir", os.path.join(tmp, "build"), "--out", out, "--no-factory",
           "--dist", os.path.join(tmp, "dist-" + tag),
           "--channels-config", os.path.join(HERE, "ota_channels.json")] + list(extra)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    raw = None
    if os.path.exists(out):
        with open(out, "rb") as f:
            raw = f.read()
    return proc.returncode, proc.stdout + proc.stderr, raw


def refused(rc, log, raw):
    return rc != 0 and raw is None and "unrecognized arguments" not in log and "include-env" in log


def workflow_assertion(wf):
    """The python heredoc of release-fw.yml's manifest step (the one that reads ota/manifest.json),
    dedented, or None."""
    lines = wf.split("\n")
    for i, line in enumerate(lines):
        if line.strip() == "python3 - <<'EOF'":
            j = i + 1
            while j < len(lines) and lines[j].strip() != "EOF":
                j += 1
            body = textwrap.dedent("\n".join(lines[i + 1:j]))
            if 'open("ota/manifest.json")' in body:
                return body
    return None


def run_assertion(script, manifest, tmp, tag):
    """Runs the workflow's assertion in a scratch tree holding ota/manifest.json and the committed
    tools/ota_channels.json, exactly as the release job's working directory does. Returns rc, output."""
    root = os.path.join(tmp, "assert-" + tag)
    os.makedirs(os.path.join(root, "ota"))
    os.makedirs(os.path.join(root, "tools"))
    shutil.copy(os.path.join(HERE, "ota_channels.json"), os.path.join(root, "tools", "ota_channels.json"))
    with open(os.path.join(root, "ota", "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f)
    proc = subprocess.run([sys.executable, "-I", "-c", script], cwd=root, capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def client_select(manifest, own_env):
    build = manifest.get("builds", {}).get(own_env, {})
    return build.get("url", ""), build.get("sha256", "")


def has_rollout(node):
    if isinstance(node, dict):
        return "rollout" in node or any(has_rollout(v) for v in node.values())
    if isinstance(node, list):
        return any(has_rollout(v) for v in node)
    return False


def main():
    tmp = tempfile.mkdtemp(prefix="mm-include-env-")
    try:
        E.build_tree(os.path.join(tmp, "build"), ALL)
        cfg = json.load(open(os.path.join(HERE, "ota_channels.json")))

        print("(a) no flag: the committed prod exclusions apply:")
        rc, log, raw = run(tmp, "base", "--envs", "esp32,esp32c3,esp8266")
        check("exit 0", rc == 0, log)
        base = json.loads(raw) if raw else {}
        check("esp8266 is not in builds{}", sorted(base.get("builds", {})) ==
              sorted({"esp32", "esp32c3", "esp8266"} - set(cfg["channels"]["prod"]["exclude_from_builds"])),
              base.get("builds"))
        check("the exclusion is logged", "esp8266 left out" in log, log)

        print("(b) --include-env esp8266:")
        rc, log, raw = run(tmp, "inc", "--envs", "esp32,esp32c3,esp8266", "--include-env", "esp8266")
        check("exit 0", rc == 0, log)
        inc = json.loads(raw) if raw else {}
        check("builds{} is esp32, esp32c3, esp8266", sorted(inc.get("builds", {})) ==
              ["esp32", "esp32c3", "esp8266"], inc.get("builds"))
        check("the override is logged", "esp8266 kept in builds{}" in log and "left out" not in log, log)
        check("esp8266 entry is url + sha256 only",
              sorted(inc.get("builds", {}).get("esp8266", {})) == ["sha256", "url"], inc.get("builds"))
        check("esp8266 url is the release asset",
              inc.get("builds", {}).get("esp8266", {}).get("url") ==
              "https://example.invalid/releases/download/fw-v0.4.11/firmware-esp8266.bin")
        ib, bb = inc.get("builds", {}), base.get("builds", {})
        check("esp32 / esp32c3 entries identical to the no-flag manifest",
              bool(ib) and all(ib.get(e) == bb.get(e) for e in ("esp32", "esp32c3")))
        check("the only difference from the no-flag manifest is builds.esp8266",
              bool(ib) and {k: v for k, v in inc.items() if k != "builds"} == {k: v for k, v in base.items() if k != "builds"}
              and {k: v for k, v in ib.items() if k != "esp8266"} == bb)
        check("no rollout key anywhere (top-level or per build)", not has_rollout(inc), inc)
        check("the esp8266 image is in dist", os.path.exists(os.path.join(tmp, "dist-inc", "firmware-esp8266.bin")))

        print("(c) esp32s3 stays excluded:")
        rc, log, raw = run(tmp, "all", "--include-env", "esp8266")
        m = json.loads(raw) if raw else {}
        check("exit 0 with all four envs built", rc == 0, log)
        check("builds{} has esp8266 but not esp32s3",
              "esp8266" in m.get("builds", {}) and "esp32s3" not in m.get("builds", {}), sorted(m.get("builds", {})))
        check("esp32s3 left out is logged", "esp32s3 left out" in log, log)
        check("the committed prod config still excludes esp32s3",
              "esp32s3" in cfg["channels"]["prod"]["exclude_from_builds"])

        print("(d) bad input is refused:")
        for label, args in (("unknown env", ["--envs", "esp32,esp8266", "--include-env", "esp9999"]),
                            ("env not among the built --envs", ["--envs", "esp32,esp32c3", "--include-env", "esp8266"]),
                            ("empty value", ["--envs", "esp32,esp8266", "--include-env", ""])):
            rc, log, raw = run(tmp, "bad", *args)
            check("%s -> refused, no manifest" % label, refused(rc, log, raw), (rc, log))
        rc, log, raw = run(tmp, "bad", "--envs", "esp32,esp8266", "--include-env", "esp32")
        check("an env the channel does not exclude -> refused, no manifest", refused(rc, log, raw), (rc, log))
        rc, log, raw = run(tmp, "bad", "--envs", "esp32,esp8266", "--include-env", "esp8266", "--no-exclusions")
        check("--include-env with --no-exclusions -> refused, no manifest", refused(rc, log, raw), (rc, log))
        rc, log, raw = run(tmp, "bad", "--envs", "esp32,esp8266", "--include-env", "esp8266", "--include-env", "esp8266")
        check("repeating the same env is harmless", rc == 0 and "esp8266" in json.loads(raw).get("builds", {}), log)

        good, nofl = inc, base
        print("(e) the shipped client's selection:")
        check("esp8266 picks its own build",
              bool(ib.get("esp8266")) and client_select(inc, "esp8266") == (ib["esp8266"]["url"], ib["esp8266"]["sha256"]))
        check("esp32 / esp32c3 still pick their own builds",
              bool(ib) and all(client_select(inc, e) == (ib[e]["url"], ib[e]["sha256"]) for e in ("esp32", "esp32c3")))
        check("a no-flag manifest still gives esp8266 nothing (NoBuild)",
              client_select(base, "esp8266") == ("", ""))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("(f) release-fw.yml:")
    wf = open(os.path.join(HERE, "..", ".github", "workflows", "release-fw.yml"), encoding="utf-8").read()
    check("esp8266 is released with a committed literal --include-env esp8266",
          re.search(r"--include-env esp8266\s", wf) is not None)
    check("no repo variable or rollout flag feeds the manifest",
          "vars." not in wf and "--rollout" not in wf and "--env-rollout" not in wf)
    check("the assertion keeps the exclusion-aware literal", '{"esp32", "esp32c3", "esp8266"} - excluded' in wf)
    script = workflow_assertion(wf)
    check("the manifest assertion heredoc is found in the workflow", script is not None)
    if script is not None and good:
        tmp2 = tempfile.mkdtemp(prefix="mm-assert-")
        try:
            rc, out = run_assertion(script, good, tmp2, "good")
            check("assertion passes the good manifest (esp8266 included, no rollout)", rc == 0, out)

            def mutated(fn):
                m = json.loads(json.dumps(good))
                fn(m)
                return m

            bad = (
                ("no esp8266 entry (the flag removed)", nofl),
                ("a per-build rollout key", mutated(lambda m: m["builds"]["esp8266"].update(
                    rollout={"bucket_lo": 0, "bucket_hi": 9}))),
                ("a per-build rollout key on esp32", mutated(lambda m: m["builds"]["esp32"].update(
                    rollout={"bucket_lo": 0, "bucket_hi": 9}))),
                ("a top-level rollout key", mutated(lambda m: m.update(rollout={"bucket_lo": 0, "bucket_hi": 9}))),
                ("esp32s3 present", mutated(lambda m: m["builds"].update(esp32s3=dict(m["builds"]["esp32"])))),
                ("a short sha256", mutated(lambda m: m["builds"]["esp8266"].update(sha256="ab"))),
                ("an empty url", mutated(lambda m: m["builds"]["esp8266"].update(url=""))),
                ("channel test", mutated(lambda m: m.update(channel="test"))),
            )
            for n, (label, m) in enumerate(bad):
                rc, out = run_assertion(script, m, tmp2, "bad%d" % n)
                check("assertion fails: %s" % label, rc != 0 and "AssertionError" in out, (rc, out))
        finally:
            shutil.rmtree(tmp2, ignore_errors=True)
    check("the new test runs in the release tooling tests", "tools/test_make_manifest_include_env.py" in wf)

    print("%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
