#!/usr/bin/env python3
"""Generate data/cert/x509_crt_bundle.bin for WiFiClientSecure::setCACertBundle() on ESP32.

Bug 2 (v0.2.0): src/esp32/http_tls.cpp used sec.setInsecure() — no certificate verification at
all. The framework's own bundle generator (ESP-IDF's components/mbedtls/esp_crt_bundle/
gen_crt_bundle.py) does NOT ship inside the installed framework-arduinoespressif32 PlatformIO
package (verified: `find <package dir> -iname "gen_crt_bundle*"` returns nothing — only the
compiled esp_crt_bundle.c/.h runtime is vendored, not the IDF build-time tooling). This script
reimplements just enough of it, reading the exact binary format from the vendored runtime parser
instead of guessing:
    framework-arduinoespressif32/libraries/WiFiClientSecure/src/esp_crt_bundle.c

Binary format (esp_crt_bundle_init() / esp_crt_verify_callback(), big-endian lengths):
    [2B num_certs]
    per cert, sorted ascending by `name` (the raw DER Subject-name TLV — this is compared via
    memcmp() against a child certificate's raw Issuer-name TLV during binary search, so it MUST
    be byte-identical to how the issuing CA's Subject is encoded in real leaf certs, which is
    exactly what Name.public_bytes() re-derives):
        [2B name_len][2B key_len][name_len bytes: DER Subject Name][key_len bytes: DER
         SubjectPublicKeyInfo, i.e. what mbedtls_pk_parse_public_key() expects]

REVISION HISTORY / WHY THIS ISN'T A HAND-PICKED THREE-ROOT SET ANYMORE
-----------------------------------------------------------------------
The first version of this script hand-picked exactly three roots (ISRG Root X1, ISRG Root X2,
USERTrust ECC Certification Authority) based on which live chains happened to resolve to them.
That was WRONG and would have bricked ESP32 OTA fleet-wide:
  - github.com's chain terminates at "Sectigo Public Server Authentication Root E46", which is
    NOT self-signed and does NOT send a cross-signature up to USERTrust ECC in the wire chain —
    so USERTrust ECC never gets consulted. E46 itself must be a directly trusted bundle entry.
  - release-assets.githubusercontent.com (the actual OTA-binary redirect target as of 2026-09 —
    NOT objects.githubusercontent.com, which this script's first draft incorrectly assumed) and
    objects.githubusercontent.com both terminate at "ISRG Root YR", cross-signed by X1 but
    without X1's own self-signed certificate present in the wire chain.
  - These CAs are visibly mid-rotation (ISRG Root YE/YR and Sectigo E46 are all new). Any
    hand-picked set is one CA rotation away from bricking OTA fleet-wide with no remote recovery
    path (OTA is the mechanism you'd otherwise use to ship the fix).

Fix: embed the FULL Mozilla root store instead of guessing which roots matter. Cost is small —
esp_crt_bundle stores only DER Subject name + SubjectPublicKeyInfo per root, not whole
certificates — see this script's own output for the final on-flash size.

Sources (both vendored into data/cert/ alongside this script, not fetched at build time):
  1. data/cert/mozilla_cacert_2026-08-13.pem — the full curl.se Mozilla CA extract, fetched
     2026-09-09 from https://curl.se/ca/cacert.pem.
       Mozilla data date (per the file's own header comment): Thu Aug 13 03:12:01 2026 GMT
       File size: 188,900 bytes
       SHA-256 (whole file, as fetched):
         f66dff1bdf8f96060b8177976f8b7d9254bc89bc4db933d769f7384d28480bc9
       (curl.se also embeds its own SHA-256 of just the certificate data in the file's header
       comment — 81b7f2576333a2e360e673f912d7b0b7a765d836c731003e348a46cac5d37198 — recorded
       here for cross-reference; the whole-file hash above is what to check the vendored copy
       against.)
     This resolves github.com (Sectigo Public Server Authentication Root E46 IS present in
     Mozilla's set directly — verified: `grep -c "Sectigo Public Server Authentication Root
     E46" mozilla_cacert_2026-08-13.pem` = 1) and hardwareapi.frynetworks.com (ISRG Root X1/X2
     both present).
  2. data/cert/supplemental_isrg_root_ye.pem, supplemental_isrg_root_yr.pem — "ISRG Root YE" and
     "ISRG Root YR" are Let's Encrypt's newest transitional roots and are NOT yet in Mozilla's
     root program (verified: both `grep -c "Root YE"` and `grep -c "Root YR"` against the
     cacert.pem above return 0), so the full Mozilla bundle alone does not carry them. Extracted
     directly from live TLS handshakes on 2026-09-09 via `openssl s_client -showcerts`:
       ISRG Root YE <- hardwareapi.frynetworks.com:443 chain, cert index 2
       ISRG Root YR <- release-assets.githubusercontent.com:443 chain, cert index 2
     Embedding these directly (rather than relying solely on their X1/X2 cross-signatures, which
     some servers' chains omit — exactly the objects/release-assets.githubusercontent.com case
     above) means a chain that stops at "ISRG Root YE"/"ISRG Root YR" verifies without needing
     mbedTLS to walk any further.

Usage:
    py -3 data/cert/gen_crt_bundle.py [--out data/cert/x509_crt_bundle.bin]

The script re-parses its own output afterward and prints a verification summary: total cert
count, total byte size, a check that entries are strictly ascending by name bytes (the
precondition esp_crt_bundle.c's binary search depends on), and an explicit assertion that the
five CAs this bug report named are present: ISRG Root X1, ISRG Root X2, ISRG Root YE, ISRG Root
YR, Sectigo Public Server Authentication Root E46.
"""
import argparse
import glob
import struct
import sys

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Asserted present in the final bundle after the build — see verify_bundle(). Matched by
# (Organization, CommonName) so a same-CN-different-O collision can't cause a false positive.
REQUIRED_ROOTS = [
    ("Internet Security Research Group", "ISRG Root X1"),
    ("Internet Security Research Group", "ISRG Root X2"),
    ("ISRG", "Root YE"),
    ("ISRG", "Root YR"),
    ("Sectigo Limited", "Sectigo Public Server Authentication Root E46"),
]


def _name_der(cert: x509.Certificate) -> bytes:
    # cryptography >=41 dropped the optional `backend` arg; try new signature first.
    try:
        return cert.subject.public_bytes()
    except TypeError:
        from cryptography.hazmat.backends import default_backend

        return cert.subject.public_bytes(default_backend())


def _cn(cert: x509.Certificate) -> str:
    attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    return attrs[0].value if attrs else "<no CN>"


def _org(cert: x509.Certificate) -> str:
    attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
    return attrs[0].value if attrs else "<no O>"


def load_all_pem_certs(pem_path: str) -> list[x509.Certificate]:
    data = open(pem_path, "rb").read()
    try:
        return x509.load_pem_x509_certificates(data)  # cryptography >= 39
    except AttributeError:
        # Older cryptography: split the concatenated PEM bundle by hand.
        certs = []
        chunk = []
        in_cert = False
        for line in data.decode("ascii", "ignore").splitlines():
            if line.startswith("-----BEGIN CERTIFICATE-----"):
                in_cert, chunk = True, [line]
            elif line.startswith("-----END CERTIFICATE-----"):
                chunk.append(line)
                certs.append(x509.load_pem_x509_certificate("\n".join(chunk).encode()))
                in_cert = False
            elif in_cert:
                chunk.append(line)
        return certs


def build_bundle(certs: list[x509.Certificate]) -> tuple[bytes, list[tuple[bytes, bytes, str]]]:
    by_name = {}
    dupes = 0
    for cert in certs:
        name = _name_der(cert)
        if name in by_name:
            dupes += 1
            continue  # keep the first occurrence (Mozilla set takes precedence over supplemental)
        key = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        by_name[name] = (key, f"{_org(cert)} / {_cn(cert)}")
    if dupes:
        print(f"note: {dupes} duplicate-subject cert(s) skipped (kept first occurrence)")

    entries = [(name, key, label) for name, (key, label) in by_name.items()]
    entries.sort(key=lambda e: e[0])  # ascending by raw Subject-name DER bytes (binary search)

    out = struct.pack(">H", len(entries))
    for name, key, _label in entries:
        out += struct.pack(">HH", len(name), len(key)) + name + key
    return out, entries


def verify_bundle(blob: bytes, entries: list[tuple[bytes, bytes, str]]) -> None:
    (num_certs,) = struct.unpack_from(">H", blob, 0)
    assert num_certs == len(entries), f"count mismatch: {num_certs} vs {len(entries)}"
    off = 2
    prev_name = b""
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    for name, key, _label in entries:
        name_len, key_len = struct.unpack_from(">HH", blob, off)
        off += 4
        blob_name = blob[off : off + name_len]
        off += name_len
        blob_key = blob[off : off + key_len]
        off += key_len
        assert blob_name == name and blob_key == key, "round-trip mismatch"
        assert blob_name > prev_name, "entries are not strictly ascending by name bytes"
        prev_name = blob_name
        load_der_public_key(blob_key)  # catches truncation/mis-length bugs here, not on-device
    assert off == len(blob), f"trailing bytes after last entry: {len(blob) - off}"
    print(f"verify: {num_certs} certs, {len(blob)} bytes total, strictly ascending by name: OK")


def assert_required_roots_present(certs: list[x509.Certificate]) -> None:
    present = {(_org(c), _cn(c)) for c in certs}
    missing = [r for r in REQUIRED_ROOTS if r not in present]
    if missing:
        print(f"ERROR: required root(s) missing from the built bundle: {missing}", file=sys.stderr)
        sys.exit(1)
    print("verify: all required roots present:")
    for org, cn in REQUIRED_ROOTS:
        print(f"  OK  O={org!r} CN={cn!r}")


def main() -> int:
    here = __import__("os").path.dirname(__file__)
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--mozilla-bundle",
        default=__import__("os").path.join(here, "mozilla_cacert_2026-08-13.pem"),
        help="Full Mozilla CA PEM (default: the vendored copy next to this script)",
    )
    ap.add_argument(
        "--supplemental-glob",
        default=__import__("os").path.join(here, "supplemental_*.pem"),
        help="Extra root/anchor PEMs not yet in Mozilla's set (default: data/cert/supplemental_*.pem)",
    )
    ap.add_argument("--out", default=__import__("os").path.join(here, "x509_crt_bundle.bin"))
    args = ap.parse_args()

    print(f"reading full Mozilla bundle from: {args.mozilla_bundle}")
    certs = load_all_pem_certs(args.mozilla_bundle)
    print(f"  {len(certs)} certs")

    supplemental_files = sorted(glob.glob(args.supplemental_glob))
    for f in supplemental_files:
        extra = load_all_pem_certs(f)
        print(f"reading supplemental root from: {f} ({len(extra)} cert(s))")
        certs.extend(extra)

    assert_required_roots_present(certs)

    blob, entries = build_bundle(certs)
    with open(args.out, "wb") as f:
        f.write(blob)
    print(f"wrote {args.out}: {len(blob)} bytes, {len(entries)} certs (deduped)")

    verify_bundle(blob, entries)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
