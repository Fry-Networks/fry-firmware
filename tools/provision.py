# Serial provisioning + command helper (PROTOCOL.md section 8).
#   py -3 tools/provision.py --port COMx set-wifi [--no-reset] [--wait 75]
#   py -3 tools/provision.py --port COMx cmd --json "{...}"
# set-wifi reads FRY_SSID, FRY_PSK and FRY_WALLET from the environment and sends set_wifi AND
# THEN set_wallet (never echoes a secret — prints a character count instead). Resets the board
# (unless --no-reset), waits for "[serial] ready", sends each command, captures the reply for
# --wait seconds. Bounded; never loops forever. --port is optional — omit it to auto-resolve by
# USB VID:PID (see _serialutil.py).
import sys, os, time, json, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _serialutil as su

READY = "[serial] ready"


def wait_for_ready(ser, timeout=25):
    start = time.time(); buf = b""
    while time.time() - start < timeout:
        chunk = ser.read(256)
        if chunk:
            buf += chunk
            txt = buf.decode("utf-8", "replace")
            for ln in txt.splitlines():
                print("  " + ln.rstrip(), flush=True)
            if READY in txt:
                return True
            buf = buf[-256:]
    return False


def redact(obj):
    safe = dict(obj)
    for key in ("password", "addr", "psk", "priv"):
        if key in safe and safe[key]:
            safe[key] = "<%d chars>" % len(safe[key])
    return safe


def send_and_capture(ser, obj, wait):
    line = json.dumps(obj, separators=(",", ":"))
    print("[prov] send: %s" % json.dumps(redact(obj), separators=(",", ":")), flush=True)
    ser.write((line + "\n").encode("utf-8")); ser.flush()
    start = time.time(); buf = b""; out = []
    while time.time() - start < wait:
        chunk = ser.read(256)
        if chunk:
            buf += chunk
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                t = raw.decode("utf-8", "replace").rstrip("\r")
                print("  " + t, flush=True); out.append(t)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default=None, help="explicit COM port; omit to auto-resolve by VID:PID")
    sub = ap.add_subparsers(dest="mode", required=True)

    sw = sub.add_parser("set-wifi")
    sw.add_argument("--wait", type=int, default=75)
    sw.add_argument("--no-reset", action="store_true")

    cm = sub.add_parser("cmd")
    cm.add_argument("--json", required=True)
    cm.add_argument("--wait", type=int, default=5)
    cm.add_argument("--no-reset", action="store_true")

    a = ap.parse_args()
    do_reset = not a.no_reset
    ser = su.open_with_retry(a.port, 115200, do_reset=do_reset)
    try:
        if do_reset:
            if not wait_for_ready(ser):
                print("[prov] WARNING: no [serial] ready banner seen; sending anyway", flush=True)

        if a.mode == "set-wifi":
            ssid = os.environ.get("FRY_SSID", "")
            psk = os.environ.get("FRY_PSK", "")
            wallet = os.environ.get("FRY_WALLET", "")
            if not ssid or not wallet:
                print("[prov] ERROR: FRY_SSID and FRY_WALLET must be set in the environment", flush=True)
                sys.exit(2)
            out1 = send_and_capture(ser, {"cmd": "set_wifi", "ssid": ssid, "password": psk}, a.wait)
            out2 = send_and_capture(ser, {"cmd": "set_wallet", "addr": wallet}, a.wait)
            out = out1 + out2
        else:
            obj = json.loads(a.json)
            out = send_and_capture(ser, obj, a.wait)

        ok = any('"status":"ok"' in l for l in out)
        print("[prov] result: %s" % ("OK" if ok else "see-output-above"), flush=True)
    finally:
        ser.close()


if __name__ == "__main__":
    main()
