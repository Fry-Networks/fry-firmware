# Shared serial-log redaction filter for the host tools (oneshot esp7, C3).
#
# Why this exists: a board's USB serial log is the only diagnostic channel, and it was carrying
# values that must not reach a file, a paste buffer or a report - the miner key (the boot banner
# and, until this change, the Improv 0xF1 "#key=" URL payload), the Wi-Fi SSID the owner typed
# (the lab `set_wifi` command), and the ESP8266 setup-AP code (a WPA2 passphrase). The firmware
# now masks all three at the source (key_policy.h's maskMinerKeyLast4 / maskSecretLast4), but the
# host side must not depend on that: an older image, a lab build, or a future line can still print
# one, so every byte a tool writes to disk goes through this filter first.
#
# The 0xF1 "#key=" fragment is a FUNCTIONAL payload (the app reads it to finish web setup), so the
# firmware keeps sending it; only the captured copy is masked here.
#
# Dependency-free, byte-in/str-out, no I/O of its own:
#   from redact import Redactor
#   r = Redactor()
#   safe = r.line(raw_text)          # never raises; r.hits counts what it caught
#
# Deliberately NOT redacted: the firmware's own "FEM-<ellipsis><last4>" form (it is already a
# mask, and its tail is what the boot gate checks) and "FEM-PENDING" (a state, not a key).
import os
import re

# A value kept in the log as "<redacted len=N>": the length is diagnostic, the bytes are not.
def _mask(match, group):
    value = match.group(group)
    return "<redacted len=%d>" % len(value)


# Order matters: the URL fragment first, so "#key=FEM-..." is masked as a whole and the miner-key
# rule below never sees it half-eaten.
#   name, pattern, replacement function
_RULES = [
    ("url_key", re.compile(r"(#key=)([A-Za-z0-9_-]{6,})"),
     lambda m: m.group(1) + "<redacted len=%d>" % len(m.group(2))),
    ("miner_key", re.compile(r"\b(?:FEM|IOT)-[A-Za-z0-9]{8,}"),
     lambda m: m.group(0)[:4] + "<redacted len=%d>" % len(m.group(0))),
    ("ssid", re.compile(r"\bssid=('[^']*'|[^\s,;]+)"),
     lambda m: "ssid=" + _mask(m, 1)),
    ("setup_code", re.compile(r"\bsetup-code=(\S+)"),
     lambda m: "setup-code=" + _mask(m, 1)),
    # The firmware already prints "<N chars>" for passwords; anything else is a real value.
    ("password", re.compile(r"\bpassword=(?!<)(\S+)"),
     lambda m: "password=" + _mask(m, 1)),
    ("bearer", re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/-]{8,}=*)"),
     lambda m: "Bearer <redacted>"),
    # WireGuard material, whichever command printed it.
    ("wg_field", re.compile(r"\b(priv|psk|peer_pub|private_key|preshared_key)=(\"[^\"]*\"|\S+)"),
     lambda m: m.group(1) + "=<redacted>"),
]


class Redactor(object):
    """Per-capture filter. hits[name] counts how many values of that kind were masked."""

    def __init__(self):
        self.hits = {}

    def line(self, text):
        if not text:
            return text
        out = text
        for name, pattern, repl in _RULES:
            out, n = pattern.subn(repl, out)
            if n:
                self.hits[name] = self.hits.get(name, 0) + n
        return out

    def total_hits(self):
        return sum(self.hits.values())


def redact_text(text):
    """Convenience for one-shot use: (redacted, hits dict)."""
    r = Redactor()
    out = r.line(text)
    return out, r.hits


class RawPathRefused(Exception):
    """--raw-to pointed outside <run>/secret. Never carries the path's contents."""


def resolve_raw_path(raw_to, run_dir=None):
    """Return the absolute path a raw (unredacted) capture may be written to.

    It MUST resolve inside <run>/secret. run_dir is the oneshot RUN directory: the --run-dir
    argument or $RUN. Refusing everything else is the whole point - an unredacted serial log is a
    secret-bearing artefact, and those live in exactly one directory that is already treated as
    such by the run (mode 0700, never committed, never pasted)."""
    if not raw_to:
        raise RawPathRefused("empty path")
    run_dir = run_dir or os.environ.get("RUN")
    if not run_dir:
        raise RawPathRefused("no run directory (pass --run-dir or set $RUN)")
    secret = os.path.realpath(os.path.join(run_dir, "secret"))
    target = os.path.realpath(raw_to)
    if target != secret and not target.startswith(secret + os.sep):
        raise RawPathRefused("outside <run>/secret")
    return target
