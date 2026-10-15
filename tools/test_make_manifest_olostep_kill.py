# The OTA manifest carries a top-level "olostep_kill": false on every channel (a published
# manifest edited to true switches the opt-in relay off fleet-wide; see src/core/ota_client.cpp).
#
#   python3 -m pytest tools/test_make_manifest_olostep_kill.py -q
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "make_manifest.py")
ENVS = ("esp8266", "esp32", "esp32s3", "esp32c3")


def build(tmp_path, channel, extra=()):
    bd = tmp_path / "build"
    for env in ENVS:
        d = bd / env
        d.mkdir(parents=True, exist_ok=True)
        (d / "firmware.bin").write_bytes(("app-image-for-%s" % env).encode() * 64)
    out = tmp_path / "out" / "manifest.json"
    cmd = [sys.executable, TOOL, "--version", "0.4.0",
           "--release-base", "https://github.com/Fry-Networks/fry-firmware/releases/download/fw-v0.4.0",
           "--build-dir", str(bd), "--out", str(out), "--no-factory", "--channel", channel] + list(extra)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return json.loads(out.read_text(encoding="utf-8"))


@pytest.mark.parametrize("channel", ["prod", "test"])
def test_every_channel_emits_olostep_kill_false(tmp_path, channel):
    m = build(tmp_path, channel)
    assert "olostep_kill" in m
    assert m["olostep_kill"] is False


def test_olostep_kill_is_top_level_not_per_build(tmp_path):
    m = build(tmp_path, "test")
    assert all("olostep_kill" not in b for b in m["builds"].values())


def test_olostep_kill_survives_no_exclusions(tmp_path):
    m = build(tmp_path, "prod", ["--no-exclusions"])
    assert m["olostep_kill"] is False


def test_existing_manifest_keys_unchanged(tmp_path):
    m = build(tmp_path, "prod")
    assert {"firmware_version", "channel", "builds"} <= set(m)
    assert m["firmware_version"] == "0.4.0" and m["channel"] == "prod"
