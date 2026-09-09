# docs/flash/fw/

This directory is intentionally empty in source control (aside from this file and
`.gitkeep`). `../index.html` fetches `fw/manifest.json` and the firmware binaries it
references as same-origin, relative paths — GitHub's release-asset host does not send
`Access-Control-Allow-Origin`, so a browser can never fetch `github.com/.../releases/...`
directly (verified: `TypeError: Failed to fetch` from a real cross-origin `fetch()`,
confirmed independently from two different test origins). Serving these files from the
flasher page's own origin sidesteps CORS instead of trying to work around it.

The release pipeline is expected to populate this directory at release time with:

- `manifest.json` — same shape as the existing `ota/manifest.json` (see
  `tools/make_manifest.py`), with each `builds[board].url` / `builds[board].factory.url`
  either a path relative to this directory (e.g. `firmware-esp32-factory.bin`) or a full
  absolute URL. `index.html` resolves either form against its own location.
- The firmware binaries those `url` / `factory.url` fields point to.

Do not hand-commit firmware binaries or a manifest.json here — that's the release
process's job. For local testing, drop a temporary `manifest.json` (and matching
binaries) in this directory, serve `docs/` over a local HTTP server (not `file://`,
since `crypto.subtle` requires a secure context and Web Serial requires a real
origin), exercise the page, then remove the temporary files before committing.
