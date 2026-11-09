# Tests for tools/check_esp8266_olostep_ram.py (manual / pre-release gate; not collected by CI).
#
#   python3 -m pytest tools/test_check_esp8266_olostep_ram.py -q
import importlib.util
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "check_esp8266_olostep_ram.py")

spec = importlib.util.spec_from_file_location("check_esp8266_olostep_ram", TOOL)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def size_a(data, rodata, bss):
    return (
        "firmware.elf  :\n"
        "section                 size         addr\n"
        ".data                 %5d   1073643520\n"
        ".text                   258   1074790400\n"
        ".irom0.text          492952   1075843088\n"
        ".rodata               %5d   1073645232\n"
        ".bss                  %5d   1073650736\n"
        ".comment                 49            0\n"
        "Total                528343\n" % (data, rodata, bss)
    )


PROD = size_a(1652, 5500, 27000)  # 34152 B
OLO_OK = size_a(1700, 6000, 27500)  # 35200 B
NO_BSS = "firmware.elf  :\n.data 1652 1\n.rodata 5500 2\n"


def run(tmp_path, prod_text, olo_text, *extra):
    p = tmp_path / "prod.txt"
    o = tmp_path / "olo.txt"
    if prod_text is not None:
        p.write_text(prod_text)
    if olo_text is not None:
        o.write_text(olo_text)
    r = subprocess.run([sys.executable, "-I", TOOL, "--prod-size", str(p), "--olostep-size", str(o), *extra],
                       capture_output=True, text=True)
    return r.returncode, r.stdout


def test_pass_within_cap(tmp_path):
    code, out = run(tmp_path, PROD, OLO_OK, "--max-delta", "1000")  # limit 35408 >= 35200
    assert code == 0, out
    assert "208 B spare" in out


def test_pass_at_exact_limit(tmp_path):
    assert run(tmp_path, PROD, OLO_OK, "--max-delta", "792")[0] == 0  # 34408 + 792 == 35200


def test_over_budget_fails(tmp_path):
    code, out = run(tmp_path, PROD, OLO_OK, "--max-delta", "791")  # one byte over
    assert code == 1 and "EXCEEDED by 1 B" in out


def test_unmeasurable_fails(tmp_path):
    assert run(tmp_path, PROD, NO_BSS, "--max-delta", "1000")[0] == 1
    assert run(tmp_path, NO_BSS, OLO_OK, "--max-delta", "1000")[0] == 1
    assert run(tmp_path, PROD, "garbage\n", "--max-delta", "1000")[0] == 1


def test_missing_file_fails(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    assert run(a, PROD, None, "--max-delta", "1000")[0] == 1
    assert run(b, None, OLO_OK, "--max-delta", "1000")[0] == 1


def test_unset_delta_is_uncalibrated(tmp_path):
    assert gate.OLOSTEP_MAX_DELTA is None
    code, out = run(tmp_path, PROD, OLO_OK)
    assert code == 3 and "UNCALIBRATED" in out


def test_verdict_pure():
    assert gate.verdict(34152, 34408, 0)[0] is True
    assert gate.verdict(34152, 34409, 0)[0] is False
