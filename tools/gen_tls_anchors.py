#!/usr/bin/env python3
"""Generates the ESP8266 trust anchors as flash-resident data from data/cert/*.pem.

Each root is picked by the SHA-256 of its DER (pinned below), so a renamed or substituted certificate is refused,
not silently loaded. Only ROOTS are emitted, never a leaf or an intermediate. Output is deterministic.

A BearSSL trust anchor is the subject name (the whole DER Name, tag and length included) plus the public key (RSA n without
its leading zero and e, or the EC point q). This script derives both from the certificate itself and writes:

  lib/fry_core/tls_anchor_bytes.h             the raw bytes, plain C++ (native tests read it)
  src/esp8266/tls_anchors.h                   br_x509_trust_anchor arrays + X509List-layout mirrors, const, in flash
  test/test_tls_anchors_flash/der_fixture.h   the roots' full DER, so a native test re-derives the same bytes in C++

  tools/gen_tls_anchors.py            write the three files
  tools/gen_tls_anchors.py --check    exit 1 if any file on disk differs from what this would write
  tools/gen_tls_anchors.py --wrong DIR  write tls_anchor_bytes.h and tls_anchors.h for the WRONG-anchor test image (Amazon
                                      Root CA 1 in every set) into DIR; scratch builds only, never into the tree
"""
import base64
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_BYTES = ROOT / "lib" / "fry_core" / "tls_anchor_bytes.h"
OUT_DEV = ROOT / "src" / "esp8266" / "tls_anchors.h"
OUT_FIX = ROOT / "test" / "test_tls_anchors_flash" / "der_fixture.h"
CERT = ROOT / "data" / "cert"

# (C identifier stem, label, source pem, sha256 of DER, DER length)
YE = ("Ye", "ISRG Root YE", "supplemental_isrg_root_ye.pem", "0fc0901cca2bae9e9fdbb02d50d02f1094f7b36672086991b9e897626dc485f0", 682)
E46 = ("E46", "Sectigo Public Server Authentication Root E46", "mozilla_cacert_2026-08-13.pem",
       "c90f26f0fb1b4018b22227519b5ca2b53e2ca5b3be5cf18efe1bef47380c5383", 574)
YR = ("Yr", "ISRG Root YR", "supplemental_isrg_root_yr.pem", "072639d0b140d5bffae16ad9c3f6cc6086040621f51ee61a6d46a8915c07cf76", 1528)
ROOTS = (YE, E46, YR)
# One root per set: the active set is switched between redirect hops (lib/fry_core/tls_trust.h).
SETS = (("Hwapi", "HWAPI: hardwareapi.frynetworks.com", (YE,)),
        ("GithubCom", "GITHUB_COM: github.com", (E46,)),
        ("GithubAssets", "GITHUB_ASSETS: *.githubusercontent.com", (YR,)))

BLOCK = re.compile(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.S)
OID_RSA = bytes.fromhex("2a864886f70d010101")
OID_EC = bytes.fromhex("2a8648ce3d0201")
OID_P384 = bytes.fromhex("2b81040022")
BR_EC_SECP384R1 = 24  # bearssl_ec.h


def der_for(entry, fname=None):
    stem, label, src, want, length = entry
    text = (CERT / (fname or src)).read_text()
    for m in BLOCK.finditer(text):
        der = base64.b64decode("".join(m.group(1).split()))
        if hashlib.sha256(der).hexdigest() == want:
            if len(der) != length:
                sys.exit("%s: unexpected DER length %d" % (label, len(der)))
            return der
    sys.exit("%s: not found in %s by fingerprint" % (label, src))


def tlv(buf, pos):
    """Returns (tag, header_len, content_len) of the element at pos."""
    tag = buf[pos]
    b = buf[pos + 1]
    if b < 0x80:
        return tag, 2, b
    n = b & 0x7F
    return tag, 2 + n, int.from_bytes(buf[pos + 2:pos + 2 + n], "big")


def children(buf, pos):
    tag, hl, cl = tlv(buf, pos)
    p, end, out = pos + hl, pos + hl + cl, []
    while p < end:
        t, h, c = tlv(buf, p)
        out.append((t, p, h, c))
        p += h + c
    return out


def anchor_of(der):
    """(dn bytes, key dict) of the certificate's subject: what BearSSL's certificate_to_trust_anchor keeps."""
    tbs = children(der, 0)[0]  # the certificate SEQUENCE's first child is the TBSCertificate
    items = children(der, tbs[1])
    i = 1 if items[0][0] == 0xA0 else 0  # explicit [0] version
    # serial, sigalg, issuer, validity, subject, spki
    subj, spki = items[i + 4], items[i + 5]
    dn = bytes(der[subj[1]:subj[1] + subj[2] + subj[3]])
    alg, bits = children(der, spki[1])
    oid = children(der, alg[1])
    oid_val = bytes(der[oid[0][1] + oid[0][2]:oid[0][1] + oid[0][2] + oid[0][3]])
    bitstr = bytes(der[bits[1] + bits[2]:bits[1] + bits[2] + bits[3]])
    if bitstr[0] != 0:
        sys.exit("unexpected BIT STRING padding")
    bitstr = bitstr[1:]
    if oid_val == OID_EC:
        curve = bytes(der[oid[1][1] + oid[1][2]:oid[1][1] + oid[1][2] + oid[1][3]])
        if curve != OID_P384:
            sys.exit("unsupported EC curve")
        return dn, {"type": "ec", "curve": BR_EC_SECP384R1, "q": bitstr}
    if oid_val == OID_RSA:
        n, e = children(bitstr, 0)
        nb = bytes(bitstr[n[1] + n[2]:n[1] + n[2] + n[3]]).lstrip(b"\x00")
        eb = bytes(bitstr[e[1] + e[2]:e[1] + e[2] + e[3]]).lstrip(b"\x00")
        return dn, {"type": "rsa", "n": nb, "e": eb}
    sys.exit("unsupported key algorithm")


def carr(name, data, qual):
    rows = []
    for i in range(0, len(data), 16):
        rows.append("  " + ", ".join("0x%02x" % b for b in data[i:i + 16]) + ",")
    return "%s const unsigned char %s[%d] %s = {\n%s\n};" % (qual, name, len(data), "FRY_ANCHOR_ROM" if qual == "static" else "", "\n".join(rows))


def render_bytes(der_of):
    out = ["#pragma once",
           "// GENERATED by tools/gen_tls_anchors.py from data/cert/*.pem; never hand-edited (tools/gen_tls_anchors.py --check).",
           "// The trust-anchor bytes BearSSL needs for each root: the subject Name as DER (tag and length included) and the",
           "// public key. Public root certificates only: no key material. On the device these live in flash (FRY_ANCHOR_ROM).",
           "#if defined(ARDUINO)", "#include <pgmspace.h>", "#define FRY_ANCHOR_ROM PROGMEM", "#else",
           "#define FRY_ANCHOR_ROM", "#endif", "", "namespace fry {", ""]
    for r in ROOTS:
        dn, key = anchor_of(der_of[r[0]])
        out.append("// %s (%d DER bytes, sha256 %s)" % (r[1], r[4], r[3][:16]))
        out.append(carr("kAnchor%sDn" % r[0], dn, "static"))
        if key["type"] == "ec":
            out.append(carr("kAnchor%sQ" % r[0], key["q"], "static"))
            out.append("static const int kAnchor%sCurve = %d;  // BR_EC_secp384r1" % (r[0], key["curve"]))
        else:
            out.append(carr("kAnchor%sN" % r[0], key["n"], "static"))
            out.append(carr("kAnchor%sE" % r[0], key["e"], "static"))
        out.append("")
    out.append("}  // namespace fry")
    out.append("")
    return "\n".join(out)


def render_dev(der_of):
    out = ["#pragma once",
           "// GENERATED by tools/gen_tls_anchors.py from data/cert/*.pem; never hand-edited (tools/gen_tls_anchors.py --check).",
           "// ESP8266 trust anchors as const data in flash: br_x509_trust_anchor arrays plus a mirror of BearSSL::X509List's layout",
           "// ({count, certificate array, trust-anchor array}) for each set. WiFiClientSecure only ever calls getCount() and",
           "// getTrustAnchors() on the list it is given (WiFiClientSecureBearSSL.cpp), so the mirror is handed to setTrustAnchors",
           "// in its place and no heap list exists. BearSSL reads these with byte loads: the esp8266 envs build with",
           "// -DNON32XFER_HANDLER (platformio.ini), which makes a byte load from flash succeed instead of fault.",
           "#include <Arduino.h>",
           "#include <BearSSLHelpers.h>",
           "#include <cstddef>",
           "#include \"tls_anchor_bytes.h\"",
           "#include \"tls_trust.h\"", "",
           "namespace fry {", "",
           "// Same layout as BearSSL::X509List: count, certificate array, trust-anchor array.",
           "struct X509ListMirror {", "  size_t count;", "  const br_x509_certificate* cert;", "  const br_x509_trust_anchor* ta;", "};",
           "static_assert(sizeof(BearSSL::X509List) == sizeof(X509ListMirror), \"X509List layout changed: update fry::X509ListMirror\");",
           "static_assert(sizeof(X509ListMirror) == sizeof(size_t) + 2 * sizeof(void*), \"X509ListMirror padding\");",
           "static_assert(offsetof(X509ListMirror, count) == 0 && offsetof(X509ListMirror, cert) == sizeof(size_t) &&",
           "                  offsetof(X509ListMirror, ta) == sizeof(size_t) + sizeof(void*),",
           "              \"X509ListMirror offsets: the framework's list is {_count, _cert, _ta} in that order\");", ""]
    keys = {}
    for r in ROOTS:
        keys[r[0]] = anchor_of(der_of[r[0]])[1]
    for name, comment, entries in SETS:
        out.append("// %s" % comment)
        out.append("static const br_x509_trust_anchor kTa%s[%d] FRY_ANCHOR_ROM = {" % (name, len(entries)))
        for e in entries:
            k = keys[e[0]]
            if k["type"] == "ec":
                pk = "{BR_KEYTYPE_EC, {.ec = {kAnchor%sCurve, const_cast<unsigned char*>(kAnchor%sQ), sizeof(kAnchor%sQ)}}}" % (e[0], e[0], e[0])
            else:
                pk = ("{BR_KEYTYPE_RSA, {.rsa = {const_cast<unsigned char*>(kAnchor%sN), sizeof(kAnchor%sN), "
                      "const_cast<unsigned char*>(kAnchor%sE), sizeof(kAnchor%sE)}}}") % (e[0], e[0], e[0], e[0])
            out.append("  {{const_cast<unsigned char*>(kAnchor%sDn), sizeof(kAnchor%sDn)}, BR_X509_TA_CA, %s}," % (e[0], e[0], pk))
        out.append("};")
        out.append("static const X509ListMirror kList%s FRY_ANCHOR_ROM = {%d, nullptr, kTa%s};" % (name, len(entries), name))
        out.append("")
    out.append("// The list for a set, or nullptr for TrustSet::None. Reads the flash mirror through the framework's own class.")
    out.append("inline const BearSSL::X509List* anchorListFor(TrustSet set) {")
    out.append("  switch (set) {")
    for (name, comment, entries) in SETS:
        out.append("    case TrustSet::%s: return reinterpret_cast<const BearSSL::X509List*>(&kList%s);" % (name, name))
    out.append("    default: return nullptr;")
    out.append("  }")
    out.append("}")
    out.append("")
    out.append("}  // namespace fry")
    out.append("")
    return "\n".join(out)


def render_fixture(der_of):
    out = ["#pragma once",
           "// GENERATED by tools/gen_tls_anchors.py; never hand-edited. The roots' full DER, for the native test that re-derives",
           "// each trust anchor's name and key in C++ and checks them against lib/fry_core/tls_anchor_bytes.h.",
           "namespace fry_test {", ""]
    for r in ROOTS:
        out.append("static const unsigned char kDer%s[%d] = {" % (r[0], len(der_of[r[0]])))
        d = der_of[r[0]]
        for i in range(0, len(d), 16):
            out.append("  " + ", ".join("0x%02x" % b for b in d[i:i + 16]) + ",")
        out.append("};")
    out += ["", "}  // namespace fry_test", ""]
    return "\n".join(out)


def load():
    return {r[0]: der_for(r) for r in ROOTS}


if __name__ == "__main__":
    der_of = load()
    if "--wrong" in sys.argv:
        # Amazon Root CA 1 (from the Mozilla bundle, pinned by fingerprint) in place of every root.
        amz = ("Amz", "Amazon Root CA 1", "mozilla_cacert_2026-08-13.pem",
               "8ecde6884f3d87b1125ba31ac3fcb13d7016de7f57cc904fe1cb97c6ae98196e", None)
        text = (CERT / amz[2]).read_text()
        found = None
        for m in BLOCK.finditer(text):
            der = base64.b64decode("".join(m.group(1).split()))
            if hashlib.sha256(der).hexdigest() == amz[3]:
                found = der
        if not found:
            sys.exit("Amazon Root CA 1 not found")
        for r in ROOTS:
            der_of[r[0]] = found
        outdir = Path(sys.argv[sys.argv.index("--wrong") + 1])
        (outdir / "tls_anchor_bytes.h").write_text(render_bytes(der_of))
        (outdir / "tls_anchors.h").write_text(render_dev(der_of))
        sys.exit(0)
    files = ((OUT_BYTES, render_bytes(der_of)), (OUT_DEV, render_dev(der_of)), (OUT_FIX, render_fixture(der_of)))
    if "--check" in sys.argv:
        sys.exit(0 if all(p.exists() and p.read_text() == t for p, t in files) else 1)
    for p, t in files:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(t)
