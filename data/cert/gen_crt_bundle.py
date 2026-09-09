#!/usr/bin/env python3
"""Generate data/cert/x509_crt_bundle.bin for WiFiClientSecure::setCACertBundle() on ESP32.

Bug 2 (v0.2.0): src/esp32/http_tls.cpp used sec.setInsecure() — no certificate verification at
all. The framework's own bundle generator (ESP-IDF's components/mbedtls/esp_crt_bundle/
gen_crt_bundle.py) does NOT ship inside the installed
framework-arduinoespressif32 PlatformIO package (verified: `find <package dir> -iname
"gen_crt_bundle*"` returns nothing — only the compiled esp_crt_bundle.c/.h runtime are vendored,
not the IDF build-time tooling). This script reimplements just enough of it, reading the exact
binary format from the vendored runtime parser instead of guessing:
    framework-arduinoespressif32/libraries/WiFiClientSecure/src/esp_crt_bundle.c

Binary format (esp_crt_bundle_init() / esp_crt_verify_callback(), big-endian lengths):
    [2B num_certs]
    per cert, sorted ascending by `name` (the raw DER Subject-name TLV — this is compared via
    memcmp() against a child certificate's raw Issuer-name TLV during binary search, so it MUST
    be byte-identical to how the issuing CA's Subject is encoded in real leaf certs, which is
    exactly what Name.public_bytes() re-derives):
        [2B name_len][2B key_len][name_len bytes: DER Subject Name][key_len bytes: DER
         SubjectPublicKeyInfo, i.e. what mbedtls_pk_parse_public_key() expects]

Root selection — verified live against both hostnames this firmware's HTTPS client touches
(openssl s_client -connect <host>:443, run 2026-09-08; see PROTOCOL.md T5/T7 for why these two
are the only HTTPS destinations: hardwareapi for registration/leases, GitHub for OTA):
    hardwareapi.frynetworks.com -> leaf -> Let's Encrypt YE1 -> ISRG Root YE -> ISRG Root X2
                                    -> ISRG Root X1 (self-signed, sent by the server itself)
    github.com                  -> leaf -> Sectigo Public Server Authentication CA DV E36
                                    -> Sectigo Public Server Authentication Root E46
                                    -> USERTrust ECC Certification Authority
    objects.githubusercontent.com (OTA asset download) -> leaf -> Let's Encrypt YR1
                                    -> ISRG Root YR -> ISRG Root X1
Every path terminates at one of exactly three roots, so the bundle embeds precisely those three:
    "ISRG Root X1"                       (covers hardwareapi + both github hosts)
    "ISRG Root X2"                       (Let's Encrypt's short-lived intermediate roots chain
                                           through X2 before reaching X1 on some paths; embedding
                                           it directly means a chain that stops at X2 still
                                           verifies even if a future server omits the X1 cross-
                                           cert)
    "USERTrust ECC Certification Authority"  (github.com's Sectigo chain's actual trust anchor —
                                           "Sectigo Public Server Authentication Root E46" is
                                           NOT self-signed, it is cross-signed BY this root)

Source of the three root certificates: the local `certifi` package (certifi.where()), which is
byte-for-byte Mozilla's CA bundle — the same root program every major TLS client (including
ESP-IDF's own default bundle) draws from. No network fetch needed; if certifi is not installed,
pass --bundle pointing at any PEM file containing these three certs (e.g. curl's
curl-ca-bundle.crt or /etc/ssl/certs/ca-certificates.crt).

Usage:
    py -3 data/cert/gen_crt_bundle.py [--bundle PATH_TO_PEM] [--out data/cert/x509_crt_bundle.bin]

The script re-parses its own output afterward and prints a verification summary (count, per-CA
subject CN + byte sizes, and a check that entries are strictly ascending by name bytes — the
precondition esp_crt_bundle.c's binary search depends on).
"""
import argparse
import struct
import sys

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Exactly the roots identified above. Matched by subject CN via cryptography's NameOID so a stray
# "Subject Alternative CN" or reordered RDN in the PEM comment can't cause a silent mismatch.
REQUIRED_ROOT_CNS = [
    "ISRG Root X1",
    "ISRG Root X2",
    "USERTrust ECC Certification Authority",
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


def load_candidates(pem_path: str) -> list[x509.Certificate]:
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


def build_bundle(certs: list[x509.Certificate]) -> bytes:
    entries = []
    for cert in certs:
        name = _name_der(cert)
        key = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        entries.append((name, key, _cn(cert)))
    entries.sort(key=lambda e: e[0])  # ascending by raw Subject-name DER bytes (binary search)

    out = struct.pack(">H", len(entries))
    for name, key, _cn_ in entries:
        out += struct.pack(">HH", len(name), len(key)) + name + key
    return out, entries


def verify_bundle(blob: bytes, expected_cns: list[str]) -> None:
    (num_certs,) = struct.unpack_from(">H", blob, 0)
    assert num_certs == len(expected_cns), f"count mismatch: {num_certs} vs {len(expected_cns)}"
    off = 2
    prev_name = b""
    seen_cns = []
    for _ in range(num_certs):
        name_len, key_len = struct.unpack_from(">HH", blob, off)
        off += 4
        name = blob[off : off + name_len]
        off += name_len
        key = blob[off : off + key_len]
        off += key_len
        assert name > prev_name, "entries are not strictly ascending by name bytes"
        prev_name = name
        # Re-parse the embedded key so a truncation/mis-length bug is caught here, not on-device.
        from cryptography.hazmat.primitives.serialization import load_der_public_key

        load_der_public_key(key)
        seen_cns.append((name_len, key_len))
    assert off == len(blob), f"trailing bytes after last entry: {len(blob) - off}"
    print(f"verify: {num_certs} certs, {len(blob)} bytes total, strictly ascending by name: OK")
    for i, (nl, kl) in enumerate(seen_cns):
        print(f"  [{i}] name={nl}B key={kl}B")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", default=None, help="PEM file to source roots from (default: certifi.where())")
    ap.add_argument("--out", default="data/cert/x509_crt_bundle.bin")
    args = ap.parse_args()

    bundle_path = args.bundle
    if not bundle_path:
        import certifi

        bundle_path = certifi.where()
    print(f"reading candidate roots from: {bundle_path}")

    candidates = load_candidates(bundle_path)
    by_cn = {}
    for c in candidates:
        by_cn.setdefault(_cn(c), c)

    missing = [cn for cn in REQUIRED_ROOT_CNS if cn not in by_cn]
    if missing:
        print(f"ERROR: required root(s) not found in {bundle_path}: {missing}", file=sys.stderr)
        return 1

    selected = [by_cn[cn] for cn in REQUIRED_ROOT_CNS]
    blob, entries = build_bundle(selected)

    with open(args.out, "wb") as f:
        f.write(blob)
    print(f"wrote {args.out}: {len(blob)} bytes, {len(entries)} certs")
    for name, key, cn in sorted(entries, key=lambda e: e[0]):
        print(f"  CN={cn!r} name={len(name)}B key={len(key)}B")

    verify_bundle(blob, [e[2] for e in entries])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
