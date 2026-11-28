// node --test test/flash/chipfamily.test.mjs
// Set CHIPFAMILY_IMPL=<path to an alternative module> to run the same table against another
// implementation (used to prove the pre-fix normalizer fails it).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const implPath = process.env.CHIPFAMILY_IMPL
  ? path.resolve(process.env.CHIPFAMILY_IMPL)
  : path.resolve(here, "../../docs/flash/chipfamily.js");
const impl = await import(pathToFileURL(implPath).href);
const { boardForChipDescription, BOARD_LABELS, mismatchMessage } = impl;

// Every string esptool-js 0.6.1 can return from getChipDescription() (lib/targets/*.js), with
// the "(revision vX.Y)" suffix main() appends, plus the python-esptool spelling with a -V3 tag.
const TABLE = [
  ["ESP8266EX", "esp8266"],
  ["ESP8285", "esp8266"],
  ["ESP8266", "esp8266"],
  ["ESP32 (revision v1.0)", "esp32"],
  ["ESP32-D0WD (revision v1.0)", "esp32"],
  ["ESP32-D0WDQ6 (revision v1.0)", "esp32"],
  ["ESP32-D0WDQ6-V3 (revision v3.0)", "esp32"],
  ["ESP32-D2WD (revision v1.0)", "esp32"],
  ["ESP32-PICO-D4 (revision v1.0)", "esp32"],
  ["ESP32-PICO-V3 (revision v3.0)", "esp32"],
  ["ESP32-PICO-V3-02 (revision v3.0)", "esp32"],
  ["ESP32-S0WD (revision v1.0)", "esp32"],
  ["ESP32-S0WDQ6 (revision v1.0)", "esp32"],
  ["ESP32-U4WDH (revision v3.1)", "esp32"],
  ["Unknown ESP32 (revision v0.0)", "esp32"],
  ["ESP32-S3 (QFN56) (revision v0.2)", "esp32s3"],
  ["ESP32-S3-PICO-1 (LGA56) (revision v0.1)", "esp32s3"],
  ["unknown ESP32-S3 (revision v0.0)", "esp32s3"],
  ["ESP32-S3", "esp32s3"],
  ["ESP32-C3 (QFN32) (revision v0.4)", "esp32c3"],
  ["ESP32-C3 AZ (QFN32) (revision v0.4)", "esp32c3"],
  ["ESP8685 (QFN28) (revision v0.4)", "esp32c3"],
  ["ESP8686 (QFN24) (revision v0.4)", "esp32c3"],
  ["Unknown ESP32-C3 (revision v0.0)", "esp32c3"],
  ["ESP32-C3", "esp32c3"],
  ["ESP32-S2 (revision v1.0)", null],
  ["ESP32-S2FH4 (revision v1.0)", null],
  ["ESP32-S2FNR2 (revision v1.0)", null],
  ["unknown ESP32-S2 (revision v0.0)", null],
  ["ESP32-C2 (revision v1.0)", null],
  ["ESP32-C5 (revision v1.0)", null],
  ["ESP32-C6 (revision v0.1)", null],
  ["ESP32-C61 (revision v0.1)", null],
  ["ESP32-H2 (revision v0.1)", null],
  ["ESP32-P4 (revision v0.1)", null],
  ["Unknown ESP32-P4 (revision v0.0)", null],
  ["", null],
  [undefined, null],
  [null, null],
  ["Banana", null],
];

for (const [description, expected] of TABLE) {
  test(`${JSON.stringify(description)} -> ${JSON.stringify(expected)}`, () => {
    assert.equal(boardForChipDescription(description), expected);
  });
}

// Autodetect design (a453380): index.html has no hand-picked Board menu any more. ESP Web Tools
// reads the manifest and picks the build from the chip it detects, so these checks pin that
// design instead of a menu.
import { createHash } from "node:crypto";
const flashDir = path.resolve(here, "../../docs/flash");
const indexHtml = readFileSync(path.join(flashDir, "index.html"), "utf8");
const manifest = JSON.parse(readFileSync(path.join(flashDir, "manifest.json"), "utf8"));
const hold = JSON.parse(readFileSync(path.join(flashDir, "manifest-hold.json"), "utf8"));
const sha256 = (rel) => createHash("sha256").update(readFileSync(path.join(flashDir, rel))).digest("hex");

test("the page has no hand-picked Board menu (autodetect only)", () => {
  assert.ok(!/<select[\s>]/i.test(indexHtml), "a <select> menu is back");
  assert.ok(!/<option[\s>]/i.test(indexHtml), "an <option> menu entry is back");
});

test("the page installs from manifest.json and from manifest-hold.json, self-hosted", () => {
  const manifests = [...indexHtml.matchAll(/<esp-web-install-button[^>]*manifest="([^"]+)"/g)].map((m) => m[1]);
  assert.ok(manifests.includes("manifest.json"), manifests.join());
  assert.ok(manifests.includes("manifest-hold.json"), manifests.join());
  assert.ok(/<script type="module" src="vendor\/esp-web-tools-[0-9.]+\/install-button\.js">/.test(indexHtml));
  assert.ok(!/<script[^>]+src="https?:/i.test(indexHtml), "flashing code must not come from a CDN");
});

test("every board label is a chipFamily the manifest builds, and vice versa", () => {
  const families = manifest.builds.map((b) => b.chipFamily).sort();
  assert.deepEqual(families, Object.values(BOARD_LABELS).sort());
});

test("every manifest build chipFamily is reached by the autodetect mapping", () => {
  const reached = new Set(TABLE.map(([d]) => boardForChipDescription(d)).filter(Boolean));
  for (const build of manifest.builds) {
    const key = Object.entries(BOARD_LABELS).find(([, label]) => label === build.chipFamily)?.[0];
    assert.ok(key, `no board key for chipFamily ${build.chipFamily}`);
    assert.ok(reached.has(key), `autodetect never yields ${key} for ${build.chipFamily}`);
  }
  for (const key of Object.keys(BOARD_LABELS)) {
    assert.ok(reached.has(key), `${key} unreachable from any chip description`);
  }
});

test("ESP8266 is served by manifest-hold.json with intact, checksummed parts", () => {
  assert.equal(hold.builds.length, 1);
  const [build] = hold.builds;
  assert.equal(build.chipFamily, BOARD_LABELS.esp8266);
  assert.ok(build.parts.length >= 1);
  for (const part of build.parts) {
    assert.match(part.path, /^fw\/hold\/[^/]+\.bin$/);
    assert.ok(Number.isInteger(part.offset) && part.offset >= 0);
    assert.equal(sha256(part.path), part.sha256, `sha256 mismatch for ${part.path}`);
  }
  const main = manifest.builds.find((b) => b.chipFamily === "ESP8266");
  assert.deepEqual(main.parts.map((p) => [p.path, p.offset, p.sha256]),
    build.parts.map((p) => [p.path, p.offset, p.sha256]),
    "manifest.json must list the same ESP8266 parts as the hold manifest");
});

test("the mismatch message tells the user to pick a label that exists in the menu", () => {
  const msg = mismatchMessage("ESP32-S3 (QFN56) (revision v0.2)", "esp32s3", "esp32");
  assert.ok(msg.includes(`"${BOARD_LABELS.esp32s3}"`), msg);
  assert.ok(msg.includes(`"${BOARD_LABELS.esp32}"`), msg);
  assert.ok(!/re-select ESP32-S3 \(QFN56\)/.test(msg), msg);
});
