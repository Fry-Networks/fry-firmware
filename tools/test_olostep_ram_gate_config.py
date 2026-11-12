# Tests for the calibrated olostep RAM gate (tools/olostep_ram_gate.json read via --config).
#
#   python3 -m pytest tools/test_olostep_ram_gate_config.py -q
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "check_esp8266_olostep_ram.py")
CONFIG = os.path.join(HERE, "olostep_ram_gate.json")

with open(CONFIG) as f:
    CFG = json.load(f)
M = CFG["measured"]


def size_a(sections):
    return (
        "firmware.elf  :\n"
        "section                 size         addr\n"
        ".data                 %5d   1073643520\n"
        ".text                   258   1074790400\n"
        ".rodata               %5d   1073645232\n"
        ".bss                  %5d   1073650736\n"
        "Total                528343\n" % (sections[".data"], sections[".rodata"], sections[".bss"])
    )


def run(tmp_path, prod_sections, olo_sections, *extra):
    p = tmp_path / "prod.txt"
    o = tmp_path / "olo.txt"
    p.write_text(size_a(prod_sections))
    o.write_text(size_a(olo_sections))
    r = subprocess.run([sys.executable, "-I", TOOL, "--prod-size", str(p), "--olostep-size", str(o), *extra],
                       capture_output=True, text=True)
    return r.returncode, r.stdout


def inflated(extra_bytes):
    s = dict(M["olostep_sections"])
    s[".bss"] += extra_bytes
    return s


def test_config_is_consistent():
    assert type(CFG["max_delta"]) is int
    assert sum(M["prod_sections"].values()) == M["prod_total"]
    assert sum(M["olostep_sections"].values()) == M["olostep_total"]
    assert CFG["max_delta"] == M["olostep_total"] - M["prod_budget"] + CFG["margin"]


def test_measured_build_passes_with_config(tmp_path):
    code, out = run(tmp_path, M["prod_sections"], M["olostep_sections"], "--config", CONFIG)
    assert code == 0, out
    assert "%d B spare" % CFG["margin"] in out


def test_at_exact_limit_passes(tmp_path):
    code, out = run(tmp_path, M["prod_sections"], inflated(CFG["margin"]), "--config", CONFIG)
    assert code == 0 and "0 B spare" in out, out


def test_over_budget_fails_with_config(tmp_path):
    code, out = run(tmp_path, M["prod_sections"], inflated(CFG["margin"] + 1), "--config", CONFIG)
    assert code == 1 and "EXCEEDED by 1 B" in out, out


def test_large_inflation_fails(tmp_path):
    code, out = run(tmp_path, M["prod_sections"], inflated(4096), "--config", CONFIG)
    assert code == 1 and "EXCEEDED" in out, out


def test_max_delta_overrides_config(tmp_path):
    code, _ = run(tmp_path, M["prod_sections"], M["olostep_sections"], "--config", CONFIG, "--max-delta", "0")
    assert code == 1


def test_without_config_still_uncalibrated(tmp_path):
    code, out = run(tmp_path, M["prod_sections"], M["olostep_sections"])
    assert code == 3 and "UNCALIBRATED" in out


def test_bad_config_is_usage_error(tmp_path):
    for body in ("not json", "{}", '{"max_delta": "5"}', '{"max_delta": true}', '{"max_delta": -1}'):
        c = tmp_path / "c.json"
        c.write_text(body)
        code, out = run(tmp_path, M["prod_sections"], M["olostep_sections"], "--config", str(c))
        assert code == 2 and "bad --config" in out, (body, out)
    code, _ = run(tmp_path, M["prod_sections"], M["olostep_sections"], "--config", str(tmp_path / "missing.json"))
    assert code == 2
