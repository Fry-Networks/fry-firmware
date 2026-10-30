# Tests for tools/check_esp8266_ram_budget.py: the post-link RAM budget of the ESP8266 images (the OTA image download's heap gate).
#
#   python3 -m pytest tools/test_check_esp8266_ram_budget.py -q
#
# The size outputs below are the real `xtensa-lx106-elf-size -A firmware.elf` sections of two builds: main 85825ac (GREEN) and
# fw-v0.4.15 / 46666f1 (the build that missed the OTA download heap gate by 24 B; RED). Every rule is also run on a mutant
# so a pass is never vacuous.
import importlib.util
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "check_esp8266_ram_budget.py")


def load():
    spec = importlib.util.spec_from_file_location("check_esp8266_ram_budget", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ram = load()


def size_a(data, rodata, bss):
    return (
        "firmware.elf  :\n"
        "section                 size         addr\n"
        ".data                 %5d   1073643520\n"
        ".text                   258   1074790400\n"
        ".irom0.text          492952   1075843088\n"
        ".text1                27981   1074790660\n"
        ".rodata               %5d   1073645232\n"
        ".bss                  %5d   1073650736\n"
        ".comment                 49            0\n"
        "Total                528343\n" % (data, rodata, bss)
    )


MAIN = size_a(1652, 5500, 27000)  # 34152 B
V0415 = size_a(1652, 5500, 28072)  # 35224 B


class FakeEnv(dict):
    def __init__(self, pioenv):
        super().__init__(PIOENV=pioenv)

    def subst(self, s):
        return {"$BUILD_DIR/${PROGNAME}.elf": "/nowhere/firmware.elf", "$SIZETOOL": "size"}.get(s, s)


def test_the_budget_is_main_plus_the_stated_margin():
    assert ram.BASELINE_BYTES == 34152
    assert ram.MARGIN_BYTES == 256
    assert ram.BUDGET_BYTES == 34408


def test_ram_is_data_plus_rodata_plus_bss_and_nothing_else():
    assert ram.ram_bytes(MAIN) == 34152  # the figure PlatformIO prints as "RAM: used 34152 bytes"
    assert ram.ram_bytes(V0415) == 35224
    assert ram.ram_sections(MAIN) == {".data": 1652, ".rodata": 5500, ".bss": 27000}
    # Flash sections do not count: a bigger .irom0.text must not move the total.
    assert ram.ram_bytes(MAIN.replace("492952", "999999")) == 34152


def test_main_is_green():
    code, msg = ram.check(MAIN)
    assert code == 0, msg
    assert "34152 B used" in msg and "256 B spare" in msg


def test_the_0415_image_is_red():
    code, msg = ram.check(V0415)
    assert code == 1
    assert "EXCEEDED" in msg and "816 B over" in msg
    assert "35224" in msg


def test_the_boundary_is_exact():
    at = size_a(1652, 5500, 27000 + ram.MARGIN_BYTES)
    over = size_a(1652, 5500, 27000 + ram.MARGIN_BYTES + 1)
    assert ram.check(at)[0] == 0
    assert ram.check(over)[0] == 1


def test_each_ram_section_counts_toward_the_total():
    # A mutant that dropped one section from the sum would let this through.
    pad = ram.MARGIN_BYTES + 1
    assert ram.check(size_a(1652 + pad, 5500, 27000))[0] == 1
    assert ram.check(size_a(1652, 5500 + pad, 27000))[0] == 1
    assert ram.check(size_a(1652, 5500, 27000 + pad))[0] == 1


def test_a_missing_ram_section_fails_closed():
    code, msg = ram.check(MAIN.replace(".bss", ".nobss"))
    assert code == 1 and "no .bss" in msg
    assert ram.check("")[0] == 1


def test_the_budget_argument_is_honoured():
    assert ram.check(MAIN, budget=34151)[0] == 1
    assert ram.check(MAIN, budget=34152)[0] == 0


def test_only_the_prod_images_are_gated():
    assert ram.env_is_gated("esp8266") and ram.env_is_gated("esp8266_test")
    for other in ("esp8266_lab", "esp8266_tlsbench", "esp8266_olostep", "esp32", "esp32c3", "native"):
        assert not ram.env_is_gated(other), other


def test_post_action_fails_the_gated_build_and_skips_the_others(capsys):
    assert ram.post_action(FakeEnv("esp8266"), size_text=MAIN) == 0
    assert ram.post_action(FakeEnv("esp8266_test"), size_text=MAIN) == 0
    assert ram.post_action(FakeEnv("esp8266"), size_text=V0415) == 1
    assert ram.post_action(FakeEnv("esp8266_test"), size_text=V0415) == 1
    # A bench build is far over budget by design (trust anchors): it must be left alone.
    assert ram.post_action(FakeEnv("esp8266_tlsbench"), size_text=V0415) == 0
    assert "skipped for env esp8266_tlsbench" in capsys.readouterr().out


def run_cli(tmp_path, text, *extra):
    f = tmp_path / "size.txt"
    f.write_text(text)
    return subprocess.run([sys.executable, TOOL, "--size-output", str(f), *extra], capture_output=True, text=True)


def test_cli_exit_codes(tmp_path):
    ok = run_cli(tmp_path, MAIN)
    assert ok.returncode == 0 and "34152 B used" in ok.stdout
    bad = run_cli(tmp_path, V0415)
    assert bad.returncode == 1 and "EXCEEDED" in bad.stdout
    assert run_cli(tmp_path, "garbage").returncode == 1
    assert subprocess.run([sys.executable, TOOL], capture_output=True, text=True).returncode == 2


def test_the_platformio_wiring_gates_esp8266_only():
    ini = open(os.path.join(HERE, "..", "platformio.ini")).read()
    sect = ini.split("[env:esp8266]")[1].split("\n[env:")[0]
    assert "post:tools/check_esp8266_ram_budget.py" in sect
    assert ini.count("check_esp8266_ram_budget.py") == 2  # the comment above the setting and the setting itself
    # The olostep envs replace extra_scripts, so they never run it; the bench env inherits it and the script skips it.
    olo = ini.split("[env:esp8266_olostep]")[1].split("\n[env:")[0]
    assert "check_esp8266_ram_budget" not in olo
