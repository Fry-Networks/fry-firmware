# Heap regression gate (retargeted from the sensmos-firmware reference harness for
# fry-firmware's actual [health] line, PROTOCOL.md section 9:
#   [health] up=<s> heap=<free> blk=<maxblock> rssi=<dbm> vpn=<up|down> relayed=<bytes> temp=<c|na>
# unlike the sensmos reference this is raw byte counts, not "heap <N>k").
#   py -3 tools/gate_heap.py [--port COMx] [--seconds 90] [--floor 8000] [--out FILE]
# PASS iff at least one [health] line appears (steady state reached) and no heap= sample ever
# drops below --floor, with no crash marker. Exit 0 = PASS, 1 = FAIL.
#
# FLOOR: 8000 bytes is a conservative placeholder — well below HEAP_GATE_TLS (15000, the point
# at which this firmware itself refuses a TLS handshake) so it should only trip on a genuine
# leak/fragmentation regression, not a normal operational dip. RECALIBRATE against real captured
# runs the same way the sensmos reference documents (max(min_observed - headroom, absolute_floor))
# once this firmware has an on-hardware soak history; this default has not been hardware-measured.
import sys, os, time, re, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _serialutil as su

CRASH = ("Exception (", "Fatal exception", "wdt reset", "Soft WDT", "abort()",
         "rst cause:2", "rst cause:3", "Guru Meditation Error", "Panic", "CORRUPT HEAP")
HEALTH_RE = re.compile(r"\[health\].*\bheap=(\d+)\b")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default=None)
    ap.add_argument("--seconds", type=int, default=90)
    ap.add_argument("--floor", type=int, default=8000)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    out = open(a.out, "w", encoding="utf-8") if a.out else None
    ser = su.open_with_retry(a.port, 115200, do_reset=True)
    start = time.time(); buf = b""
    saw_health = False
    min_heap = None
    try:
        while time.time() - start < a.seconds:
            chunk = ser.read(256)
            if not chunk:
                continue
            buf += chunk
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                t = raw.decode("utf-8", "replace").rstrip("\r")
                if out:
                    out.write(t + "\n"); out.flush()
                if any(c in t for c in CRASH):
                    print("[gate_heap] FAIL crash: %s" % t)
                    sys.exit(1)
                m = HEALTH_RE.search(t)
                if m:
                    saw_health = True
                    h = int(m.group(1))
                    if min_heap is None or h < min_heap:
                        min_heap = h
        if not saw_health:
            print("[gate_heap] FAIL: no [health] line seen in %ds (never reached steady state)" % a.seconds)
            sys.exit(1)
        if min_heap < a.floor:
            print("[gate_heap] FAIL: min heap %d < floor %d" % (min_heap, a.floor))
            sys.exit(1)
        print("[gate_heap] PASS: min_heap=%d floor=%d no crash in %ds" % (min_heap, a.floor, a.seconds))
        sys.exit(0)
    finally:
        ser.close()
        if out:
            out.close()


if __name__ == "__main__":
    main()
