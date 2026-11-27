// node --test test/flash/boards_docs.test.mjs
// The flasher page documents the non-browser board families (Pico W / Pico 2 W via UF2,
// BK7231N via ltchiptool) without shipping binaries or touching the live manifests.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const flashDir = path.resolve(here, "../../docs/flash");
const html = readFileSync(path.join(flashDir, "index.html"), "utf8");
const readme = readFileSync(path.join(flashDir, "README.md"), "utf8");
const section = (id) => {
  const m = new RegExp(`<h3 id="${id}">[\\s\\S]*?(?=<h3 |</section>)`).exec(html);
  assert.ok(m, `section ${id} missing`);
  return m[0];
};

test("Pico W / Pico 2 W section gives UF2 drag-and-drop steps", () => {
  const s = section("board-pico");
  for (const needle of ["Pico W", "Pico 2 W", "RP2040", "RP2350", "BOOTSEL", "RPI-RP2", ".uf2", "drag"]) {
    assert.ok(s.toLowerCase().includes(needle.toLowerCase()), `missing ${needle}`);
  }
  assert.ok(!/ltchiptool/.test(s));
});

test("BK7231N section gives ltchiptool steps", () => {
  const s = section("board-bk7231n");
  for (const needle of ["BK7231N", "pip install ltchiptool", "ltchiptool flash write", "TX1", "RX1", "3.3 V"]) {
    assert.ok(s.includes(needle), `missing ${needle}`);
  }
});

test("README repeats both procedures", () => {
  for (const needle of ["Pico 2 W", "BOOTSEL", ".uf2", "BK7231N", "ltchiptool flash write"]) {
    assert.ok(readme.includes(needle), `README missing ${needle}`);
  }
});

test("the new sections add no menu, no ESP Web Tools button and no binary links", () => {
  const sec = /<section id="otherBoards">[\s\S]*?<\/section>/.exec(html)?.[0];
  assert.ok(sec);
  assert.ok(!/<esp-web-install-button|<select|<option/i.test(sec));
  assert.ok(!/href="[^"]*\.(uf2|bin|elf)"/i.test(sec), "no binary downloads from this page");
});

test("no board binaries or manifest entries were added for the new families", () => {
  const manifest = JSON.parse(readFileSync(path.join(flashDir, "manifest.json"), "utf8"));
  const hold = JSON.parse(readFileSync(path.join(flashDir, "manifest-hold.json"), "utf8"));
  assert.deepEqual(manifest.builds.map((b) => b.chipFamily).sort(), ["ESP32", "ESP32-C3", "ESP32-S3", "ESP8266"]);
  assert.deepEqual(hold.builds.map((b) => b.chipFamily), ["ESP8266"]);
  const walk = (d) => readdirSync(d, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]);
  const bad = walk(path.join(flashDir, "fw")).filter((f) => /\.uf2$|pico|bk7231|rp2/i.test(path.basename(f)));
  assert.deepEqual(bad, []);
});
