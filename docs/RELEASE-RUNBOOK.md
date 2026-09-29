# Firmware release runbook (fw-v0.4.x, kill switch, A3 revert, flasher move)

Operator procedure for firmware 0.4.0 and later. Everything a field board does with a release
follows from one fact: **every board reads `releases/latest`** — v0.3.x boards with no channel or
strike memory, 0.4.x boards with `channel`, SemVer precedence and strikes (PROTOCOL.md sections 6,
11.5, 11.8). "Latest" is therefore the only lever, and each step below ends by proving where
`releases/latest` points.

Conventions: `REPO=Fry-Networks/fry-firmware`; commands need `gh` (2.20+, `--latest` support) and
`curl`; a repository tag ruleset must restrict `v*` tags (the legacy build.yml path, prove it with a
decoy tag before the first release) — **never tag `v*`**,
firmware releases are `fw-v<X.Y.Z>` only. Work in a scratch directory for downloads.

```sh
REPO=Fry-Networks/fry-firmware
LATEST_URL=https://github.com/$REPO/releases/latest/download/manifest.json
latest_tag() { gh api "repos/$REPO/releases/latest" --jq .tag_name; }
latest_manifest_sha() { curl -sL "$LATEST_URL" | sha256sum | cut -d' ' -f1; }
# the FIRST redirect (no -L): it must point under releases/download/<tag>/ of the release you expect
latest_manifest_location() { curl -sI "$LATEST_URL" | grep -i '^location:' | head -1; }
```

## 1. Publish fw-v0.4.x (draft → canary → publish with --latest)

1. **Version.** `platformio.ini` `-DFRY_FIRMWARE_VERSION='"X.Y.Z"'` — plain `X.Y.Z`, no prerelease
   tag on anything a 0.3.x board may take (0.3.3's `compareSemver` ignores prerelease tags, so
   `0.4.1-rc.1` would compare *not newer* than `0.4.1`). The release job refuses a tag whose version
   does not match this line. Commit on a branch GitHub Pages does not serve (the flasher moves
   separately, section 5).
2. **Tag → draft.** `git tag fw-vX.Y.Z <commit> && git push origin fw-vX.Y.Z`. `release-fw.yml`
   builds esp32 and esp32c3 token-free (`check_no_token`, `check_prod_channel` + its `esp32_test`
   control), runs the native and tool tests, checks the flasher and creates a **DRAFT** release
   with `firmware-esp32.bin`, `firmware-esp32c3.bin`, the two `-factory.bin` images and
   `manifest.json` (`builds` = esp32, esp32c3 only; `channel: prod`). A draft never resolves at
   `releases/latest`, so nothing has shipped yet. ESP32-S3 and ESP8266 are held: not built, not
   attached, not in the manifest (`tools/ota_channels.json`).
3. **Canary.** From the tag (`--ref` takes a branch or tag, not a SHA; the dispatch only works once
   test-channel.yml is on the default branch): `gh workflow run test-channel.yml --repo $REPO --ref fw-vX.Y.Z -f fault=0`
   (the `ota-test` prerelease must exist and stay a prerelease; the job refuses if
   `releases/latest` is `ota-test`). Bench boards run the `*_test` images and read only `ota-test`.
   Run the canary journeys (a fresh flash, an OTA from 0.3.x, a rollback with `fault=1`/`2`/`3`).
   Preconditions before the next step: hardwareapi healthy (a transport-level outage rolls every
   pending board back after 20 min of Wi-Fi and 0.3.x re-downloads), the ops tripwire owner
   warned, and the kill switch of section 2 rehearsed once on a fork.
4. **Publish.** `gh release edit fw-vX.Y.Z --repo $REPO --draft=false --latest`. `--latest` is
   not optional: GitHub otherwise picks "latest" by the tagged commit's date, which is exactly the
   ambiguity the kill switch must never depend on.
5. **Verify (paste the output into the release notes / run log):**
   ```sh
   latest_tag                       # must print fw-vX.Y.Z
   latest_manifest_location         # must point under releases/download/fw-vX.Y.Z/
   gh release download fw-vX.Y.Z --repo $REPO -p manifest.json -O fw-manifest.json
   sha256sum fw-manifest.json; latest_manifest_sha   # the two sha256 must be equal
   python3 -c "import json; m=json.load(open('fw-manifest.json')); assert m['channel']=='prod' and sorted(m['builds'])==['esp32','esp32c3'] and m['firmware_version']=='X.Y.Z', m; print('manifest ok', m['firmware_version'], sorted(m['builds']))"
   ```
   Then the 6-h watch: per-`install_id` version flips 0.3.x ↔ X.Y.Z (a board cycling every ~6 h or
   faster is looping, section 2), asset downloads against fleet size, PoC 401 rate for the new
   `software_version`.

## 2. Kill switch (fw-hold): stop every board from installing anything

`tools/fw-hold/manifest.json` is exactly `{"firmware_version":"0.0.0","channel":"prod","builds":{}}`
(sha256 `01f0bd98846e33c25d15d739215e385dccd7ba70df5bbdcdc690044b0099bedc`). Published as the
manifest of a **normal, non-prerelease release that is latest**, it stops every client:
v0.3.1/0.3.3 get no URL on any chip, 0.4.x see nothing newer (`test/test_fw_hold` proves both on
the file's exact bytes). It only brakes the loop if it *is* latest — hence `--latest`; a hold on a
tag whose commit is older than fw-v0.4.0's, or a prerelease, changes nothing while the operator
believes the loop is stopped.

**When:** boards ping-pong between 0.3.x and 0.4.x (rollback → re-download; from a crash-at-boot
that is a 1–2 min cycle with a slot erase each time), a hardwareapi outage is rolling the fleet
back, or anything else that needs "nobody installs anything now".

Rehearsed live on Fry-Networks/fry-firmware (2026-09-29 02:18Z): with `--latest`, the API's
`releases/latest` became the hold **immediately**, and `latest/download/manifest.json` served the
hold's bytes (sha `01f0bd98…`) at once — even with `--target` pointing at an *older* commit, so
the commit date does not matter when `--latest` is given. A hold therefore reaches boards within
about 1–2 min (a board's next check).

```sh
HOLD=fw-hold-$(date -u +%Y%m%dT%H%M%SZ)
# --target: any commit, an older one is fine (the rehearsal used one); --latest is what makes it latest.
gh release create "$HOLD" tools/fw-hold/manifest.json --repo $REPO --target <any commit> --latest \
  --title fw-hold \
  --notes "Kill switch: an empty manifest so no board updates. See docs/RELEASE-RUNBOOK.md section 2."
# verify - all three must hold before you tell anyone the loop is stopped
latest_tag                          # == $HOLD (immediate)
latest_manifest_location            # under releases/download/$HOLD/
latest_manifest_sha                 # == 01f0bd98846e33c25d15d739215e385dccd7ba70df5bbdcdc690044b0099bedc (immediate)
```
`fw-hold-*` matches no workflow trigger (build.yml `v*`, release-fw.yml `fw-v*`), so nothing
builds or publishes on its own. Do **not** use `--prerelease` (a prerelease is never latest). Do
**not** delete or un-publish fw-v0.4.0 instead: latest would fall back to the v0.3.1 release,
whose manifest lists esp32s3 and esp8266 and whose images mint IOT- keys.

Effect on boards: a 0.3.x board stops at its next check (about 30 s after the reboot that follows
a rollback, otherwise within 6 h); a 0.4.x board sees `not_newer`. Strikes: `0.0.0` is "a
different latest", so 0.4.x boards **clear** the strikes they held (section 4).

### Lifting the hold — publish the fix first, delete the hold last, then wait ~2 min

Deleting the hold while it is latest makes latest fall back to fw-v0.4.0 and the loop resumes.
Rehearsed: `gh release delete … --cleanup-tag` flipped the API's latest back **at once**, but the
`latest/download/…` **redirect stayed cached on the deleted release for ~70 s**, so boards that
checked in that window got a 404 = no update (harmless). Allow ~2 min before counting boards.

```sh
# 1. the fix, per section 1, made latest explicitly - and proven before the hold is touched
gh release edit fw-vX.Y.Z --repo $REPO --draft=false --latest
latest_tag                          # == fw-vX.Y.Z, NOT the hold
latest_manifest_sha                 # == sha256sum of the fw-vX.Y.Z manifest.json asset
# 2. only then the hold (housekeeping: it is no longer latest)
gh release delete "$HOLD" --repo $REPO --cleanup-tag -y
latest_tag                          # still fw-vX.Y.Z (immediate)
sleep 120; latest_manifest_location # under releases/download/fw-vX.Y.Z/ once the ~70 s redirect cache has expired
latest_manifest_sha                 # == the fw-vX.Y.Z manifest sha; a 404 inside the first ~70 s is the cache, retry
```

## 3. A3 revert (branch `iv1/fw-revert-a3`, version 0.4.90) and the ≥ 0.4.91 rule

A3 is 0.3.3 source with the fw-v* release tooling, `confirmGood` on any HTTP answer, rollback
evidence for 0.4.x (`fry_ota/rbk`), version **0.4.90** — plain X.Y.Z so that both parsers rank it
above every 0.4.x shipped so far. It is published exactly like section 1 (tag `fw-v0.4.90` on that
branch; the manifest is esp32 + esp32c3 only; canary on `ota-test` is impossible for 0.3.3 source,
so canary by USB on bench boards).

Consequences to plan for:
- **Every later version must be ≥ 0.4.91** (or 0.5.0): anything below 0.4.90 is "not newer" to a
  board on A3 and never installs.
- 0.3.x boards on ESP32/C3 that never took 0.4.0 also take 0.4.90 (token-free 0.3.3 semantics:
  telemetry `/measurements` stops, PoC and lease keep working on device tokens).
- 0.4.90 is a *different latest* for 0.4.x boards, so their strikes reset (section 4).

## 4. Strike notes (0.4.x boards only)

- A 0.4.x board records one strike per rollback from a version (`fry_ota/badver` + `badn`): the
  version is skipped on the first check after the rollback boot, retried at the next 6-h check,
  and skipped for good at **3** strikes — a bad version costs each board at most 3 downloads,
  ≥ 6 h apart, then silence until a *different* version is published.
- **Any different `firmware_version` clears the strikes** — a hold (`0.0.0`), A3 (`0.4.90`) or a
  fix. A version re-published under the *same* number after a hold therefore gets **3 fresh
  attempts** per board; publish the fix under a new number.
- A restart that is not a failure (restart-to-apply, USB re-key) sets `fry_ota/planrst` and is
  not a strike.
- 0.3.x boards keep no strikes: a rolled-back 0.3.x board re-downloads at its first tick after the
  rollback boot and every 6 h after — only the hold (section 2) stops that.
- Field-readable state: `ota` in 0A / 0xF1 / `/status` is `pending`, `valid` or `rolled_back`;
  `rolled_back` stays for the life of an image after any rollback (the other slot is still marked
  invalid), it is not a fault by itself.

## 5. Flasher move (after the canary): local gate before pushing the commit

The Pages flasher (`docs/flash/`) stays at 0.3.3 until the canary passed; then ESP32 and ESP32-C3
move to 0.4.x while ESP32-S3 and ESP8266 keep their 0.3.3 parts under `docs/flash/fw/hold/`
(`manifest-hold.json`, second button). No workflow gates that commit (`release-fw.yml`'s
`flasher-assets` job only runs on the *next* `fw-v*` tag), so gate it locally and paste the output
into the commit message.

1. Take the **published** `firmware-<env>.bin` assets (`gh release download fw-vX.Y.Z --repo $REPO -p 'firmware-*.bin'`)
   and confirm each sha256 equals the `builds.<env>.sha256` in the release's `manifest.json` — the asset
   plus the manifest is what boards install, so that is the comparison. Build the tagged commit locally
   (`pio run -e esp32 -e esp32c3`, token unset) only for the `bootloader.bin` / `partitions.bin` parts the
   flasher needs. Same-machine rebuilds were byte-identical in the release evidence, but a CI build may
   differ from a local one, so do not gate on a local `firmware.bin` matching the asset.
2. Lay them out as the release job does (the published asset as `manifest_input/<env>/firmware.bin`, the local `bootloader.bin`,
   `partitions.bin`) and write the flasher manifests, carrying the held chips over unchanged:
   ```sh
   python3 tools/make_manifest.py --version X.Y.Z --channel prod --envs esp32,esp32c3 \
     --release-base "https://github.com/$REPO/releases/download/fw-vX.Y.Z" \
     --build-dir manifest_input --out docs/flash/fw/manifest.json --dist docs/flash/fw \
     --ewt-out docs/flash/manifest.json --ewt-merge docs/flash/manifest-hold.json
   ```
3. **Gate** (all must pass; the second block is the same assertion `release-fw.yml` runs):
   ```sh
   python3 tools/check_flasher_assets.py --expect-version X.Y.Z
   python3 - <<'EOF'
   import hashlib, json, os
   main = json.load(open("docs/flash/manifest.json"))
   hold = json.load(open("docs/flash/manifest-hold.json"))
   held = {b["chipFamily"]: b["parts"] for b in hold["builds"]}
   assert sorted(held) == ["ESP32-S3", "ESP8266"], sorted(held)
   for b in main["builds"]:
       if b["chipFamily"] in held:
           assert b["parts"] == held[b["chipFamily"]], b["chipFamily"]
   for parts in held.values():
       for p in parts:
           assert p["path"].startswith("fw/hold/"), p["path"]
           data = open(os.path.join("docs/flash", p["path"]), "rb").read()
           assert hashlib.sha256(data).hexdigest() == p["sha256"], p["path"]
   fw = json.load(open("docs/flash/fw/manifest.json"))
   assert sorted(fw["builds"]) == ["esp32", "esp32c3"], sorted(fw["builds"])
   print("held:", sorted(held), "at", hold["version"], "- served:", main["version"], "- fw/ builds:", sorted(fw["builds"]))
   EOF
   ```
   Expected: `check_flasher_assets: OK - flasher serves X.Y.Z, ...` and
   `held: ['ESP32-S3', 'ESP8266'] at 0.3.3 - served: X.Y.Z - fw/ builds: ['esp32', 'esp32c3']`.
4. Known cosmetic residual: the ESP Web Tools manifest `version` becomes X.Y.Z for all chips, so an
   S3 already on 0.3.3 is offered "Update" and re-flashes its 0.3.3 parts. Say so in the guide.
