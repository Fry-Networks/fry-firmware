# esp8266 joins the release build (release-fw.yml) while the prod OTA manifest still leaves it out
# (tools/ota_channels.json). Dependency-free, same style as tools/test_make_manifest_envs.py:
#
#   python3 tools/test_manifest_esp8266_compat.py
#
# Exit 0 = all pass, 1 = a failure.
#   (a) adding esp8266 to --envs leaves the esp32 / esp32c3 entries byte-identical
#   (b) a model of the shipped client's selection picks its own env and ignores extra keys
#   (c) with esp8266 excluded, builds{} is today's set, and the esp8266 image is still copied to dist
#   (d) release-fw.yml builds and attaches esp8266 and derives its assertion from the exclusions
import json
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import test_make_manifest_envs as E  # noqa: E402  (helpers: build_tree, run, FAKE_ESPTOOL)

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


def client_select(manifest, own_env):
    """Model of src/core/ota_client.cpp:503-507: builds[FRY_BUILD_ENV]["url"|"sha256"], missing ->
    "" (decideOtaUpdate then answers NoBuild). Nothing else in the manifest is consulted."""
    build = manifest.get("builds", {}).get(own_env, {})
    return build.get("url", ""), build.get("sha256", "")


def main():
    tmp = tempfile.mkdtemp(prefix="mm-esp8266-")
    try:
        E.build_tree(os.path.join(tmp, "build"), ("esp32", "esp32c3", "esp8266"))
        esptool = os.path.join(tmp, "fake_esptool.py")
        with open(esptool, "w") as f:
            f.write(E.FAKE_ESPTOOL)
        boot_app0 = os.path.join(tmp, "boot_app0.bin")
        with open(boot_app0, "wb") as f:
            f.write(b"\x00" * 32)
        common = ["--esptool", esptool, "--boot-app0", boot_app0, "--no-exclusions"]

        print("(a) esp32 / esp32c3 entries do not change when esp8266 is added:")
        rc, log, base = E.run(tmp, "--envs", "esp32,esp32c3", "--dist", os.path.join(tmp, "d1"), *common)
        check("baseline manifest builds", rc == 0, log)
        rc, log, full = E.run(tmp, "--envs", "esp32,esp32c3,esp8266", "--dist", os.path.join(tmp, "d2"),
                              *common)
        check("manifest with esp8266 builds", rc == 0, log)
        for env in ("esp32", "esp32c3"):
            check("%s entry identical" % env, base["builds"][env] == full["builds"][env],
                  (base["builds"][env], full["builds"][env]))
            check("%s keeps url + sha256 + factory" % env,
                  sorted(full["builds"][env]) == ["factory", "sha256", "url"], sorted(full["builds"][env]))
        check("esp8266 entry is url + sha256 only", sorted(full["builds"]["esp8266"]) == ["sha256", "url"],
              full["builds"].get("esp8266"))
        check("top-level keys unchanged", sorted(full) == sorted(base) ==
              ["builds", "channel", "firmware_version", "olostep_kill"], (sorted(full), sorted(base)))

        print("(b) the shipped client's selection (ota_client.cpp:503-507):")
        for env in ("esp32", "esp32c3", "esp8266"):
            check("%s picks its own build" % env,
                  client_select(full, env) == (full["builds"][env]["url"], full["builds"][env]["sha256"]))
        check("an env with no entry gets nothing (NoBuild)", client_select(base, "esp8266") == ("", ""))
        extra = json.loads(json.dumps(full))
        extra["builds"]["esp8266"]["future_key"] = {"x": 1}
        extra["future_top"] = True
        check("extra keys are ignored by every env",
              all(client_select(extra, e) == client_select(full, e) for e in ("esp32", "esp32c3", "esp8266")))

        print("(c) esp8266 excluded (the committed prod channel):")
        cfg = json.load(open(os.path.join(HERE, "ota_channels.json")))
        dist = os.path.join(tmp, "d3")
        rc, log, prod = E.run(tmp, "--envs", "esp32,esp32c3,esp8266", "--channel", "prod", "--dist", dist,
                              "--esptool", esptool, "--boot-app0", boot_app0)
        check("exit 0", rc == 0, log)
        want = {"esp32", "esp32c3", "esp8266"} - set(cfg["channels"]["prod"]["exclude_from_builds"])
        check("builds{} equals the committed prod set", set(prod["builds"]) == want, (sorted(prod["builds"]), sorted(want)))
        if "esp8266" in cfg["channels"]["prod"]["exclude_from_builds"]:
            check("builds{} equals today's {esp32, esp32c3}", set(prod["builds"]) == {"esp32", "esp32c3"})
            check("the held esp8266 image is still copied to dist",
                  os.path.exists(os.path.join(dist, "firmware-esp8266.bin")))
            check("excluded esp8266 -> the client finds no build", client_select(prod, "esp8266") == ("", ""))
        check("esp32 / esp32c3 entries match the baseline",
              all(prod["builds"][e] == base["builds"][e] for e in ("esp32", "esp32c3")))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("(d) release-fw.yml:")
    wf = open(os.path.join(HERE, "..", ".github", "workflows", "release-fw.yml"), encoding="utf-8").read()
    check("esp8266 is in the build matrix", re.search(r"env: \[esp32, esp32c3, esp8266\]", wf) is not None)
    check("the manifest is made from all three envs", "--envs esp32,esp32c3,esp8266" in wf)
    check("the assertion subtracts the committed exclusions",
          '{"esp32", "esp32c3", "esp8266"} - excluded' in wf)
    check("the esp8266 image is attached to the release", "release/firmware-esp8266.bin" in wf)

    print("%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
