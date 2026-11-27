# Tests for tools/esp8266_ram_margin.py, the stricter ESP8266 static-RAM guard added by T-ESP.
#
#   python3 -m pytest tools/test_esp8266_ram_margin.py -q
#
# Size outputs are real `xtensa-lx106-elf-size -A firmware.elf` sections: PRE = the esp8266 image before T-ESP (34356 B, which the old
# 34408 B gate passes with 52 B spare) and NOW = the T-ESP image (33596 B). The new guard must pass NOW and FAIL PRE: that is the point,
# a regression back to the old size must not slip under the old budget. Every rule also runs on a mutant so a pass is never vacuous.
import importlib.util
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "esp8266_ram_margin.py")
CFG = os.path.join(HERE, "esp8266_ram_margin.json")
OLD_TOOL = os.path.join(HERE, "check_esp8266_ram_budget.py")


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


m = load(TOOL, "esp8266_ram_margin")
old = load(OLD_TOOL, "check_esp8266_ram_budget")


def size_a(data, rodata, bss):
    return (
        "firmware.elf  :\nsection                 size         addr\n"
        ".data                 %5d   1073643520\n.text                   258   1074790400\n"
        ".irom0.text          500004   1075843088\n.text1                28341   1074790660\n"
        ".rodata               %5d   1073645232\n.bss                  %5d   1073650736\n"
        ".comment                 49            0\nTotal                528343\n" % (data, rodata, bss)
    )


PRE = size_a(1652, 5640, 27064)  # 34356
NOW = size_a(1648, 4892, 27056)  # 33596
cfg = m.load_config(CFG)


def test_config_is_strictly_below_the_old_budget():
    assert cfg["measured_total"] == 33596
    assert cfg["limit"] == cfg["measured_total"] + cfg["headroom"]
    assert cfg["headroom"] <= 128
    assert cfg["limit"] < old.BUDGET_BYTES - 500  # the old gate stays 34408; the new one is far tighter
    assert set(cfg["gated"]) == {"esp8266", "esp8266_test"}


def test_config_matches_the_recorded_sections():
    raw = json.load(open(CFG))
    assert raw["data"] + raw["rodata"] + raw["bss"] == raw["measured_total"]


def test_now_passes():
    code, msg = m.check(NOW, cfg["limit"])
    assert code == 0 and "33596 B used" in msg


def test_pre_t_esp_size_fails_even_though_the_old_gate_passes():
    assert old.check(PRE)[0] == 0  # old gate: 34356 <= 34408
    code, msg = m.check(PRE, cfg["limit"])
    assert code == 1 and "EXCEEDED" in msg


def test_boundary_is_inclusive():
    at = size_a(1648, 4892, 27056 + cfg["headroom"])
    assert m.check(at, cfg["limit"])[0] == 0
    over = size_a(1648, 4892, 27056 + cfg["headroom"] + 1)
    assert m.check(over, cfg["limit"])[0] == 1


def test_missing_section_is_unmeasurable_and_fails():
    code, msg = m.check(".data 10 1\n.bss 20 2\n", cfg["limit"])
    assert code == 1 and "no .rodata" in msg


def test_config_refuses_a_loose_headroom(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"measured_total": 33596, "headroom": 5000, "env_gated": ["esp8266"]}))
    with pytest.raises(m.Unmeasurable):
        m.load_config(str(p))
    p.write_text("not json")
    with pytest.raises(m.Unmeasurable):
        m.load_config(str(p))


class FakeEnv(dict):
    def subst(self, s):
        return {"$PROJECT_DIR": os.path.join(HERE, "..")}.get(s, "")


def test_post_action_gates_only_prod_envs():
    assert m.post_action(FakeEnv(PIOENV="esp8266_lab"), size_text=PRE) == 0  # skipped, not gated
    assert m.post_action(FakeEnv(PIOENV="esp8266"), size_text=NOW) == 0
    assert m.post_action(FakeEnv(PIOENV="esp8266"), size_text=PRE) == 1
    assert m.post_action(FakeEnv(PIOENV="esp8266_test"), size_text=PRE) == 1


def test_cli_exit_codes(tmp_path):
    good, bad = tmp_path / "g.txt", tmp_path / "b.txt"
    good.write_text(NOW)
    bad.write_text(PRE)
    run = lambda *a: subprocess.run([sys.executable, TOOL, *a], capture_output=True, text=True)
    assert run("--size-output", str(good)).returncode == 0
    assert run("--size-output", str(bad)).returncode == 1
    assert run().returncode == 2


def test_platformio_wires_the_guard_and_the_iram_heap_after_the_old_gate():
    ini = open(os.path.join(HERE, "..", "platformio.ini")).read()
    sect = ini.split("[env:esp8266]")[1].split("\n[env:")[0]
    assert "post:tools/esp8266_ram_margin.py" in sect
    assert "post:tools/check_esp8266_ram_budget.py" in sect  # the old gate is still there
    assert "-D PIO_FRAMEWORK_ARDUINO_MMU_CACHE16_IRAM48_SECHEAP_SHARED" in sect
    assert "-DNON32XFER_HANDLER" in sect  # the IRAM heap needs the byte-access handler
