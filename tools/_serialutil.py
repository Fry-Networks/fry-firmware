# Shared serial helpers for the fry-firmware host tools (PROTOCOL.md section 8).
# Port resolution: an explicit --port always wins; when omitted, resolve by USB VID:PID —
# never hardcode a COM number, since a board can re-enumerate after a reset/reflash.
# Known bench boards: 10c4:ea60 (Silicon Labs CP210x) = ESP8266, 1a86:55d4 (CH34x) = ESP32,
# 303a:1001 (Espressif native USB) = native-USB ESP32-S3/C3.
import sys, time
import serial
import serial.tools.list_ports as lp

BOARD_VID_PIDS = (
    (0x10C4, 0xEA60, "esp8266"),
    (0x1A86, 0x55D4, "esp32"),
    (0x303A, 0x1001, "esp32s3/esp32c3 (native USB)"),
)


def resolve_port(explicit_port=None, verbose=True):
    if explicit_port:
        return explicit_port
    cands = []
    for p in lp.comports():
        for vid, pid, label in BOARD_VID_PIDS:
            if p.vid == vid and p.pid == pid:
                cands.append((p, label))
    if not cands:
        raise RuntimeError(
            "no known bench-board VID:PID found; ports=" +
            ", ".join(p.device for p in lp.comports()))
    port, label = cands[0]
    if verbose:
        print("[port] resolved %s (%s; %d candidate(s))" % (port.device, label, len(cands)))
    return port.device


def open_no_reset(port, baud):
    # Configure DTR/RTS de-asserted BEFORE open so opening the port does not pulse a reset.
    ser = serial.Serial()
    ser.port = port
    ser.baudrate = baud
    ser.timeout = 0.2
    ser.dtr = False
    ser.rts = False
    ser.open()
    # Some Windows USB-serial drivers only honor the state after open — re-assert.
    try:
        ser.dtr = False
        ser.rts = False
    except Exception:
        pass
    return ser


def pulse_reset(ser):
    # Run-mode reset (NOT flash/bootloader): EN low while GPIO0/IO0 stays high.
    # DTR=False -> boot pin high; RTS=True -> EN low (reset held); RTS=False -> boot.
    ser.dtr = False
    ser.rts = True
    time.sleep(0.1)
    ser.rts = False


def open_with_retry(explicit_port, baud, do_reset, retries=6, verbose=True):
    # Bounded self-heal on a transient exclusive-open race or a port that is momentarily busy.
    # Escalating backoff; re-resolve every attempt in case the COM number moved.
    attempt = 0
    last = None
    while attempt <= retries:
        try:
            port = resolve_port(explicit_port, verbose=verbose)
            ser = open_no_reset(port, baud)
            if do_reset:
                pulse_reset(ser)
            return ser
        except Exception as e:
            last = e
            wait = min(1.0 + attempt * 1.0, 5.0)
            if verbose:
                print("[port] open attempt %d failed: %s (retry in %.0fs)" % (attempt + 1, e, wait))
            time.sleep(wait)
            attempt += 1
    raise RuntimeError("could not open serial after %d attempts: %s" % (retries + 1, last))
