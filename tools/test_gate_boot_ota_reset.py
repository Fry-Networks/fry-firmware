# End-to-end tests for tools/gate_boot.py: a `rst cause:2` that follows `ota: applied` is an EXPECTED
# software restart, every other reset/crash signature still FAILs. Dependency-free except pyserial
# (already required by gate_boot). Same style as tools/test_redact.py:
#
#   python3 tools/test_gate_boot_ota_reset.py                   # test the sibling gate_boot.py
#   python3 tools/test_gate_boot_ota_reset.py <path-to-a-copy>  # test a specific copy (needs _serialutil.py + redact.py beside it)
#
# Exit 0 = all pass, 1 = a failure. Each case runs the REAL CLI as a subprocess against a pty that a
# feeder thread writes the fixture lines to. No serial device is touched.
#
# TEST-SIDE SHIM (lives only in this file): a pty has no modem-control lines, so pyserial's DTR/RTS
# set raises OSError(ENOTTY). The subprocess launcher below ONLY swallows that OSError from
# serial.serialposix.Serial._update_dtr_state/_update_rts_state, then runs gate_boot.py unmodified via
# runpy. It changes nothing else; production code is untouched.
#
# Fixture lines are transcribed from real ESP8266 captures (timestamps stripped); MACs are synthetic and
# banner keys are masked (FEM-<U+2026>ABCD). No raw key or token appears here.
import os
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "gate_boot.py")
SECONDS = 3

LAUNCHER = r"""
import runpy, sys
import serial.serialposix as sp
def _wrap(orig):
    def f(self, *a, **k):
        try:
            return orig(self, *a, **k)
        except OSError:
            pass
    return f
sp.Serial._update_dtr_state = _wrap(sp.Serial._update_dtr_state)
sp.Serial._update_rts_state = _wrap(sp.Serial._update_rts_state)
tool = sys.argv[1]
sys.argv = [tool] + sys.argv[2:]
runpy.run_path(tool, run_name="__main__")
"""

OTA = "ota: applied 0.4.23 sha=ok"
RST2 = " ets Jan  8 2013,rst cause:2, boot mode:(3,6)"
RST3 = " ets Jan  8 2013,rst cause:3, boot mode:(3,6)"
BANNER = "FRY boot v0.4.23 chip=ESP8266 mac=AA:BB:CC:00:11:22 minerkey=FEM-…ABCD"
RAWKEYBANNER = "FRY boot v0.4.23 chip=ESP8266 mac=AA:BB:CC:00:11:22 minerkey=FEM-" + "Q" * 12
INFO = "[gate_boot] expected post-OTA reset (rst cause:2 after ota: applied)"
PASS = "[gate_boot] PASS minerkey=FEM-…ABCD"
NOBANNER = "[gate_boot] FAIL: no boot banner in %ds" % SECONDS
CRASHP = "[gate_boot] FAIL crash marker: "
SOFTWDT = "Soft WDT reset"
EXC4 = "Exception (4)"
CRASH_INFO = "[crash] reason=3 exccause=4 epc1=0x4000dcf0 epc2=0x00000000 epc3=0x00000000 excvaddr=0x00000000 depc=0x00000000"

FAILURES = []


def check(name, cond, detail=""):
    if cond:
        print("PASS %s" % name)
    else:
        FAILURES.append(name)
        print("FAIL %s %s" % (name, detail))


def run_cli(lines):
    """Feed lines through a pty to the real CLI; return (exit code, stdout lines)."""
    master, slave = os.openpty()
    port = os.ttyname(slave)
    proc = subprocess.Popen([sys.executable, "-c", LAUNCHER, TOOL, "--port", port, "--seconds", str(SECONDS)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8")

    def feed():
        time.sleep(0.6)  # let the child open the port
        try:
            for ln in lines:
                if proc.poll() is not None:
                    return
                os.write(master, (ln + "\r\n").encode("utf-8"))
                time.sleep(0.05)
        except OSError:
            pass

    t = threading.Thread(target=feed, daemon=True)
    t.start()
    try:
        out, _ = proc.communicate(timeout=25)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
        out += "\n<TIMEOUT>"
    t.join(timeout=5)
    os.close(master)
    os.close(slave)
    return proc.returncode, [l for l in out.splitlines() if l.startswith("[gate_boot]") or l == "<TIMEOUT>"]


def verdict(out):
    """The final [gate_boot] PASS/FAIL line."""
    v = [l for l in out if l.startswith("[gate_boot] PASS") or l.startswith("[gate_boot] FAIL")]
    return v[-1] if v else ""


def case(name, lines, rc, vprefix, info_count=None):
    code, out = run_cli(lines)
    v = verdict(out)
    ok = code == rc and v.startswith(vprefix) and (info_count is None or out.count(INFO) == info_count)
    check(name, ok, "rc=%s verdict=%r info=%d out=%r" % (code, v, out.count(INFO), out))


def test_all():
    case("A ota->rst2->new banner: PASS + info line", ["boot", BANNER, "ota: downloading 500/511 KB", OTA, "", RST2, "boot2", BANNER],
         0, PASS, 1)
    case("B ota->rst2->no banner: FAIL", [BANNER, OTA, "", RST2, "ets_task()"], 1, NOBANNER, 1)
    case("C soft wdt + exception(4): FAIL", ["boot", SOFTWDT, EXC4, CRASH_INFO, BANNER], 1, CRASHP + SOFTWDT, 0)
    case("D rst2 then rst3 no ota: FAIL", ["ota: sha256 mismatch - rejected", "[r1f] download rejected, restarting", "rst cause:2", "rst cause:3"],
         1, CRASHP + "rst cause:2", 0)
    case("E ota->exception(4)->rst2: FAIL", [OTA, EXC4, CRASH_INFO, RST2, BANNER], 1, CRASHP + EXC4, 0)
    case("F ota->rst2->banner->second rst2: FAIL", [OTA, RST2, BANNER, RST2, BANNER], 1, CRASHP + " ets Jan  8 2013,rst cause:2", 1)
    case("G plain banner no reset: PASS", ["boot", BANNER], 0, PASS, 0)
    case("H ota->rst2->raw-key banner: FAIL key check", [OTA, RST2, RAWKEYBANNER], 1, "[gate_boot] FAIL: raw miner key in banner", 1)
    # Negative cases (round 1): the OTA arming line is anchored, the reset must be exactly cause:2, and the
    # expectation never survives a second reset or a co-located crash marker.
    case("I echo 'expect ota: applied'->rst2->banner: FAIL", ["[note] expect ota: applied", RST2, BANNER],
         1, CRASHP + " ets Jan  8 2013,rst cause:2", 0)
    case("J ota->one line rst2 + Panic: FAIL", [OTA, "Panic ets Jan  8 2013,rst cause:2, boot mode:(3,6)", BANNER],
         1, CRASHP + "Panic", 0)
    case("K two ota->rst2->banner->rst2: FAIL", [OTA, OTA, RST2, BANNER, RST2, BANNER],
         1, CRASHP + " ets Jan  8 2013,rst cause:2", 1)
    case("L banner->rst2 no ota: FAIL", [BANNER, RST2, BANNER], 1, CRASHP + " ets Jan  8 2013,rst cause:2", 0)
    case("M ota->rst cause:20: FAIL", [OTA, " ets Jan  8 2013,rst cause:20, boot mode:(3,6)", BANNER],
         1, CRASHP + " ets Jan  8 2013,rst cause:20", 0)
    case("N 'ota: applied 0.4.23' (no sha=ok)->rst2->banner: FAIL", ["ota: applied 0.4.23", RST2, BANNER],
         1, CRASHP + " ets Jan  8 2013,rst cause:2", 0)


test_all()
if FAILURES:
    print("FAILED: %s" % ", ".join(FAILURES))
    sys.exit(1)
print("ALL PASS")
