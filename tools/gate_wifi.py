# WiFi regression gate (retargeted from the sensmos-firmware reference harness for fry-firmware's
# actual log line: "wifi connected ip=<ip> rssi=<dbm>", PROTOCOL.md section 9).
#   py -3 tools/gate_wifi.py [--port COMx] [--subnet 192.168.0.0/20] [--seconds 90] [--out FILE]
# Resets the board (credentials must already be provisioned — run provision.py first), captures
# up to --seconds, PASS iff a station IP is reported that is non-zero, not in the device's own
# 192.168.4.0/24 softAP range, and inside --subnet, with no crash marker and no reboot after
# success inside the window. Exit 0 = PASS, 1 = FAIL. Assertions are never loosened to pass.
import sys, os, time, re, argparse, ipaddress
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _serialutil as su

IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
SOFTAP_NET = ipaddress.ip_network("192.168.4.0/24")

CRASH_MARKERS = ("Exception (", "Fatal exception", "wdt reset", "Soft WDT", "abort()",
                  "rst cause:2", "rst cause:3", "Guru Meditation Error", "Panic", "CORRUPT HEAP")
BOOT_MARKERS = ("FRY boot v",)


def extract_success_ip(line):
    if "wifi connected ip=" in line:
        m = IP_RE.search(line.split("ip=", 1)[1])
        return m.group(1) if m else None
    return None


def valid_station_ip(ipstr, subnet):
    try:
        ip = ipaddress.ip_address(ipstr)
    except ValueError:
        return False, "unparseable"
    if str(ip) == "0.0.0.0":
        return False, "zero"
    if ip in SOFTAP_NET:
        return False, "in-softAP-range-192.168.4.x"
    if ip not in subnet:
        return False, "outside-subnet-%s" % subnet
    return True, "ok"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default=None)
    ap.add_argument("--subnet", default="192.168.0.0/20")
    ap.add_argument("--seconds", type=int, default=90)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    subnet = ipaddress.ip_network(a.subnet, strict=False)
    print("[gate_wifi] subnet=%s window=%ds" % (subnet, a.seconds), flush=True)

    out_fh = open(a.out, "w", encoding="utf-8") if a.out else None
    ser = su.open_with_retry(a.port, 115200, do_reset=True)
    start = time.time()
    buf = b""
    passed_ip = None
    pass_time = None
    try:
        while time.time() - start < a.seconds:
            if passed_ip and (time.time() - pass_time) > 3.0:
                break  # confirmed + 3s clean tail (no crash/reboot) -> PASS; stop early
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
                    print("[gate_wifi] FAIL (crash): %s" % text, flush=True)
                    sys.exit(1)
                if passed_ip and any(m in text for m in BOOT_MARKERS):
                    print("[gate_wifi] FAIL (reboot after success): %s" % text, flush=True)
                    sys.exit(1)
                ipstr = extract_success_ip(text)
                if ipstr and not passed_ip:
                    ok, why = valid_station_ip(ipstr, subnet)
                    if ok:
                        passed_ip = ipstr
                        pass_time = time.time()
                        print("[gate_wifi] success line: %s" % text, flush=True)
                        print("[gate_wifi] station IP %s valid in %s" % (ipstr, subnet), flush=True)
                    else:
                        print("[gate_wifi] candidate ip %s rejected (%s): %s" % (ipstr, why, text), flush=True)
        if passed_ip:
            print("[gate_wifi] PASS ip=%s" % passed_ip, flush=True)
            sys.exit(0)
        print("[gate_wifi] FAIL: no valid station IP in %ds window" % a.seconds, flush=True)
        sys.exit(1)
    finally:
        ser.close()
        if out_fh:
            out_fh.close()


if __name__ == "__main__":
    main()
