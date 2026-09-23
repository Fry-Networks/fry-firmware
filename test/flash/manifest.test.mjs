// node --test test/flash/manifest.test.mjs
//
// Shape checks for docs/flash/manifest.json, the ESP Web Tools manifest the browser flasher reads.
// tools/check_flasher_assets.py already proves the bytes and the offsets are right at release
// time; this proves the JSON itself is the shape ESP Web Tools accepts, on every PR rather than
// only on a tag. A manifest that parses but is subtly wrong (a missing chipFamily, an absolute
// part path, an offset inside NVS) fails at flash time, on a stranger's board.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const flashDir = path.resolve(here, "../../docs/flash");
const manifest = JSON.parse(readFileSync(path.join(flashDir, "manifest.json"), "utf8"));

// The device reports this string over Improv Serial; ESP Web Tools compares it to manifest.name
// with ===. Read out of the firmware source so the two cannot drift apart unnoticed.
const glue = readFileSync(
  path.resolve(here, "../../src/core/improv_serial_glue.cpp"), "utf8");
const improvName = /kImprovFirmwareName\[\]\s*=\s*"([^"]*)"/.exec(glue)?.[1];

const EXPECTED_FAMILIES = ["ESP8266", "ESP32", "ESP32-S3", "ESP32-C3"];
// bootloader, partition table, otadata, app — ESP32 puts its bootloader at 0x1000, the
// newer parts at 0x0.
const ESP32_OFFSETS = { ESP32: [0x1000, 0x8000, 0xe000, 0x10000] };
const RISCV_OFFSETS = [0x0, 0x8000, 0xe000, 0x10000];

test("name matches the firmware's Improv name exactly", () => {
  assert.equal(improvName, "Fry Firmware");
  assert.equal(manifest.name, improvName);
});

test("version is a plain semver with no v prefix", () => {
  assert.match(manifest.version, /^\d+\.\d+\.\d+$/);
});

test("a new install prompts to erase, and improv wait time is a sane number of seconds", () => {
  assert.equal(manifest.new_install_prompt_erase, true);
  assert.equal(typeof manifest.new_install_improv_wait_time, "number");
  assert.ok(Number.isInteger(manifest.new_install_improv_wait_time));
  assert.ok(manifest.new_install_improv_wait_time > 0);
  assert.ok(manifest.new_install_improv_wait_time <= 120);
});

test("one build per supported chip family, no duplicates", () => {
  assert.ok(Array.isArray(manifest.builds));
  const families = manifest.builds.map((b) => b.chipFamily);
  assert.deepEqual([...families].sort(), [...EXPECTED_FAMILIES].sort());
  assert.equal(new Set(families).size, families.length);
});

test("every part has a relative path, an integer offset and a sha256", () => {
  for (const build of manifest.builds) {
    assert.ok(build.parts.length >= 1, `${build.chipFamily} has no parts`);
    for (const part of build.parts) {
      assert.equal(typeof part.path, "string");
      // Resolved with new URL(path, manifestUrl): a leading slash or a scheme would send the
      // browser somewhere other than this repo's own directory.
      assert.ok(!part.path.startsWith("/"), `${part.path} must be relative`);
      assert.ok(!/^[a-z]+:/i.test(part.path), `${part.path} must not be an absolute URL`);
      assert.ok(!part.path.includes(".."), `${part.path} must not escape the flash directory`);
      assert.ok(Number.isInteger(part.offset) && part.offset >= 0);
      assert.match(part.sha256, /^[0-9a-f]{64}$/);
    }
  }
});

test("every part file exists and is non-empty", () => {
  for (const build of manifest.builds) {
    for (const part of build.parts) {
      const abs = path.join(flashDir, part.path);
      assert.ok(statSync(abs).size > 0, `${part.path} is empty`);
    }
  }
});

test("parts are ordered by offset and never overlap", () => {
  for (const build of manifest.builds) {
    let end = -1;
    for (const part of build.parts) {
      assert.ok(part.offset > end,
        `${build.chipFamily}: ${part.path} at 0x${part.offset.toString(16)} overlaps the part before it`);
      end = part.offset + statSync(path.join(flashDir, part.path)).size - 1;
    }
  }
});

test("ESP8266 ships one whole-flash image at offset 0", () => {
  const build = manifest.builds.find((b) => b.chipFamily === "ESP8266");
  assert.equal(build.parts.length, 1);
  assert.equal(build.parts[0].offset, 0);
});

test("each ESP32-family build lists four parts at the documented offsets", () => {
  for (const build of manifest.builds.filter((b) => b.chipFamily !== "ESP8266")) {
    const want = ESP32_OFFSETS[build.chipFamily] || RISCV_OFFSETS;
    assert.deepEqual(build.parts.map((p) => p.offset), want, build.chipFamily);
  }
});

test("nothing is written into the NVS window, where the miner key lives", () => {
  // 0x9000-0xe000 in every ESP32 layout here. A merged factory image pads this gap with 0xFF,
  // which is exactly why the web manifest lists parts instead.
  const NVS_START = 0x9000;
  const NVS_END = 0xe000;
  for (const build of manifest.builds.filter((b) => b.chipFamily !== "ESP8266")) {
    for (const part of build.parts) {
      const size = statSync(path.join(flashDir, part.path)).size;
      assert.ok(part.offset >= NVS_END || part.offset + size <= NVS_START,
        `${build.chipFamily}: ${part.path} overlaps NVS`);
    }
  }
});
