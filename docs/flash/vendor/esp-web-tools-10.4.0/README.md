# esp-web-tools 10.4.0 (vendored)

`../../index.html` loads its flashing code from this directory, not from a CDN. A page that
writes firmware to a board must not fetch the code that does the writing from a third party at
flash time: a compromised or hijacked CDN entry would own every board flashed through the page,
and pinning a version does not help if the host serving it changes what that version returns.
These files are therefore served from the same origin as the page, and their hashes are committed.

## Provenance

- Package: `esp-web-tools@10.4.0`, Apache-2.0 (see `LICENSE`, copied from the tarball).
- Upstream: `git+https://github.com/esphome/esp-web-tools.git` (`npm view esp-web-tools@10.4.0
  repository.url`).
- Tarball: `https://registry.npmjs.org/esp-web-tools/-/esp-web-tools-10.4.0.tgz`, fetched with
  `npm pack esp-web-tools@10.4.0`.
- The tarball's sha512 was checked against the registry's own `dist.integrity` before anything was
  copied out of it, and the two matched:

      $ openssl dgst -sha512 -binary esp-web-tools-10.4.0.tgz | openssl base64 -A
      3pwkeFFm5Fj7UQo8SJNYK5RXrtNCpq6X9QoI6bMT4GBZWgrJqjn0YvM9ihG74BtMoSFYXfmDtkehuxe50PTMPQ==
      $ npm view esp-web-tools@10.4.0 dist.integrity
      sha512-3pwkeFFm5Fj7UQo8SJNYK5RXrtNCpq6X9QoI6bMT4GBZWgrJqjn0YvM9ihG74BtMoSFYXfmDtkehuxe50PTMPQ==

- Copied: every file from `package/dist/web/` (26 JavaScript files — the browser build, whose
  dynamic imports are all relative and stay inside this directory) plus `package/LICENSE`.
  Nothing was edited. `SHA256SUMS.txt` covers all 27 files; verify with
  `sha256sum -c SHA256SUMS.txt` run from this directory.

## Updating

1. `npm pack esp-web-tools@<version>` and compare the tarball's sha512 with
   `npm view esp-web-tools@<version> dist.integrity`; confirm `repository.url` is still
   `esphome/esp-web-tools`. Stop if either disagrees.
2. Copy `package/dist/web/*` and `package/LICENSE` into a NEW
   `docs/flash/vendor/esp-web-tools-<version>/`, regenerate `SHA256SUMS.txt`, and point the
   `<script type="module" src=...>` in `../../index.html` at it. Version the directory rather
   than overwriting it, so a bad update is a one-line revert.
3. The manifest contract this page depends on is small and stable, but re-check it against the
   new bundle: `parts[].path` is resolved with `new URL(path, manifestUrl)`, `parts[].offset` is
   used verbatim, images are written with `flashMode/flashFreq/flashSize: "keep"` (so a part's
   own header reaches the chip unmodified), and the Improv device-info firmware NAME is compared
   to `manifest.name` with `===`.
