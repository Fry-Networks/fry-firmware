#!/usr/bin/env python3
"""Fails if a PROD firmware image carries the test OTA channel (round 2 F12).

A *_test build compiles in the ota-test prerelease manifest URL; a prod build must not. The
prebuild guard (tools/fry_prebuild.py) only sees build flags, which a source-level #define,
build_src_flags or -include could slip past. This checks the bytes that actually ship.

    python3 tools/check_prod_channel.py IMAGE [IMAGE ...]              # prod: marker must be absent
    python3 tools/check_prod_channel.py --expect-test IMAGE [IMAGE ...]  # positive control: present

Exit codes: 0 as expected, 1 violation, 2 a missing or unreadable image.
"""
import argparse
import sys

MARKER = b"releases/download/ota-test/"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("images", nargs="+")
    ap.add_argument("--expect-test", action="store_true",
                    help="positive control: every image MUST carry the test-channel marker")
    a = ap.parse_args()

    bad = 0
    for path in a.images:
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            print("check_prod_channel: cannot read %s (%s)" % (path, e.strerror))
            return 2
        present = MARKER in data
        if a.expect_test and not present:
            print("check_prod_channel: CONTROL FAILED - %s has no test-channel marker" % path)
            bad += 1
        elif not a.expect_test and present:
            print("check_prod_channel: FAIL - %s is a prod image carrying the ota-test manifest URL" % path)
            bad += 1
        else:
            print("check_prod_channel: OK - %s %s the test-channel marker"
                  % (path, "carries" if present else "does not carry"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
