# Boot gate: reset the board and assert the boot banner appears with a well-formed miner key
# and no crash marker within the window.
#   py -3 tools/gate_boot.py [--port COMx] [--seconds 20] [--out FILE]
# Exit 0 = PASS, 1 = FAIL.
import sys, os, re, time, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _serialutil as su

BANNER_RE = re.compile(r"FRY boot v\S+ chip=\S+ mac=[0-9A-Fa-f:]+ minerkey=(\S+)")
MINERKEY_RE = re.compile(r"^IOT-[0-9A-F]{32}$")
CRASH_MARKERS = ("Exception (", "Fatal exception", "wdt reset", "Soft WDT", "abort()",
                  "rst cause:2", "rst cause:3", "Guru Meditation Error", "Panic", "CORRUPT HEAP")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default=None)
    ap.add_argument("--seconds", type=int, default=20)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    out_fh = open(a.out, "w", encoding="utf-8") if a.out else None
    ser = su.open_with_retry(a.port, 115200, do_reset=True)
    start = time.time()
    buf = b""
    banner_ok = False
    miner_key = None
    try:
        while time.time() - start < a.seconds:
            chunk = ser.read(256)
            if not chunk:
                continue
            buf += chunk
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                ms = int((time.time() - start) * 1000)
                text = raw.decode("utf-8", "replace").rstrip("\r")
                if out_fh:
                    out_fh.write("[%7dms] %s\n" % (ms, text)); out_fh.flush()
                if any(m in text for m in CRASH_MARKERS):
                    print("[gate_boot] FAIL crash marker: %s" % text, flush=True)
                    sys.exit(1)
                m = BANNER_RE.search(text)
                if m:
                    banner_ok = True
                    miner_key = m.group(1)
                    print("[gate_boot] banner: %s" % text, flush=True)

        if not banner_ok:
            print("[gate_boot] FAIL: no boot banner in %ds" % a.seconds, flush=True)
            sys.exit(1)
        if not miner_key or not MINERKEY_RE.match(miner_key):
            print("[gate_boot] FAIL: miner key '%s' does not match ^IOT-[0-9A-F]{32}$" % miner_key,
                  flush=True)
            sys.exit(1)
        print("[gate_boot] PASS minerkey=%s" % miner_key, flush=True)
        sys.exit(0)
    finally:
        ser.close()
        if out_fh:
            out_fh.close()


if __name__ == "__main__":
    main()
