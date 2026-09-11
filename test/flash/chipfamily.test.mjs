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

test("every board label is an option the real Board menu offers", () => {
  const html = readFileSync(path.resolve(here, "../../docs/flash/index.html"), "utf8");
  const optionLabels = [...html.matchAll(/<option value="([^"]+)"[^>]*>([^<]+)<\/option>/g)].map((m) => [m[1], m[2]]);
  for (const [key, label] of Object.entries(BOARD_LABELS)) {
    assert.ok(optionLabels.some(([v, l]) => v === key && l === label), `menu lacks ${key}=${label}`);
  }
});

test("the mismatch message tells the user to pick a label that exists in the menu", () => {
  const msg = mismatchMessage("ESP32-S3 (QFN56) (revision v0.2)", "esp32s3", "esp32");
  assert.ok(msg.includes(`"${BOARD_LABELS.esp32s3}"`), msg);
  assert.ok(msg.includes(`"${BOARD_LABELS.esp32}"`), msg);
  assert.ok(!/re-select ESP32-S3 \(QFN56\)/.test(msg), msg);
});
