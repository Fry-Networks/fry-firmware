#!/usr/bin/env bash
# Proves the two .inc files in this directory are byte-for-byte the manifest-selection code that
# shipped in v0.3.1 and in 0.3.3 (d7a2433). Needs the full git history (tags), so it is run by hand
# or from a full clone, not from a shallow CI checkout.
#   bash test/test_legacy_manifest_select/verify_excerpts.sh
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
here=test/test_legacy_manifest_select
check() {  # rev first-line last-line inc
  local want got
  want=$(git show "$1:src/core/ota_client.cpp" | sed -n "$2,$3p" | sha256sum | cut -d' ' -f1)
  got=$(sha256sum "$here/$4" | cut -d' ' -f1)
  if [ "$want" = "$got" ]; then
    echo "OK   $4 == $1:src/core/ota_client.cpp lines $2-$3 ($got)"
  else
    echo "FAIL $4 ($got) != $1:src/core/ota_client.cpp lines $2-$3 ($want)"
    return 1
  fi
}
check v0.3.1 273 289 legacy_v031_select.inc
check d7a2433 292 308 legacy_v033_select.inc
# The isNewerVersion the excerpts call must be the one that shipped: 0.4.0 only appends to semver.
if git diff v0.3.1 HEAD -- lib/fry_core/semver.cpp lib/fry_core/semver.h | grep -q '^-[^-]'; then
  echo "FAIL lib/fry_core/semver.* removed or changed lines since v0.3.1"
  exit 1
fi
echo "OK   lib/fry_core/semver.* only gained lines since v0.3.1"
