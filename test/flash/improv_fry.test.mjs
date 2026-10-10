// node --test test/flash/improv_fry.test.mjs
//
// Fry vendor Improv commands 0xF0 FrySetMinerKey / 0xF1 FryGetStatus (PROTOCOL.md section 11.4).
// The golden vectors live in ONE place, test/test_improv_vendor/test_main.cpp, where the firmware's
// own encoder is checked against them. This file reads the same arrays back out of that source and
// checks them against an independent JavaScript encoder written from the protocol text, and
// against the hex listed in PROTOCOL.md. The browser setup page and the Android app speak this
// wire format too, so a vector that drifts from any of the three is a broken client somewhere.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const cppSource = readFileSync(
  path.resolve(here, "../test_improv_vendor/test_main.cpp"), "utf8");
const protocol = readFileSync(path.resolve(here, "../../PROTOCOL.md"), "utf8");

function goldens() {
  const out = new Map();
  const re = /const uint8_t (kFry\w+)\[\] = \{([^}]*)\};/g;
  for (const m of cppSource.matchAll(re)) {
    out.set(m[1], Uint8Array.from(m[2].split(",").map((b) => Number.parseInt(b.trim(), 16))));
  }
  return out;
}

// ---- independent encoder (improv-wifi.com/serial + PROTOCOL.md section 11.4) --------------------
function packet(type, payload) {
  const head = [..."IMPROV"].map((c) => c.charCodeAt(0));
  const bytes = [...head, 0x01, type, payload.length, ...payload];
  const sum = bytes.reduce((a, b) => a + b, 0) & 0xff;
  return Uint8Array.from([...bytes, sum]);
}

function rpcRequest(command, data) {
  return packet(0x03, [command, data.length, ...data]);
}

function rpcResult(command, strings) {
  const data = [];
  for (const s of strings) {
    const enc = [...new TextEncoder().encode(s)];
    data.push(enc.length, ...enc);
  }
  return packet(0x04, [command, data.length, ...data]);
}

const KEY = "FEM-TESTKEY0000000000000000000000001"; // synthetic
const MASKED = "FEM-TE…";

const expected = {
  kFryReqSetKey: rpcRequest(0xf0, [KEY.length, ...new TextEncoder().encode(KEY)]),
  kFryReqGetStatus: rpcRequest(0xf1, []),
  kFrySetKeyOk: rpcResult(0xf0, ["ok", MASKED]),
  kFrySetKeyBadKey: rpcResult(0xf0, ["err", "7", "bad_key"]),
  kFrySetKeyLocked: rpcResult(0xf0, ["err", "8", "key_locked"]),
  kFryStatusConnected: rpcResult(0xf1,
    ["1", "3", "0", "0", "1", MASKED, "0.4.0", "202", "12", "valid", ""]),
  kFryStatusKeyRequired: rpcResult(0xf1,
    ["1", "4", "4", "6", "0", "", "0.4.0", "0", "-1", "pending", "ABCD2345"]),
};

const hex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, "0")).join("");

test("every golden vector in the C++ suite is found", () => {
  const g = goldens();
  assert.deepEqual([...g.keys()].sort(), Object.keys(expected).sort());
});

for (const [name, bytes] of Object.entries(expected)) {
  test(`${name}: the C++ golden equals the independent JS encoding`, () => {
    assert.equal(hex(goldens().get(name)), hex(bytes));
  });

  test(`${name}: PROTOCOL.md lists the same bytes`, () => {
    const line = new RegExp(`^\\s*${name}\\s+([0-9a-f]+)\\s*$`, "m").exec(protocol);
    assert.ok(line, `PROTOCOL.md has no "${name} <hex>" line`);
    assert.equal(line[1], hex(bytes));
  });
}

test("the masked key is six characters and a UTF-8 ellipsis, never the key", () => {
  const ok = goldens().get("kFrySetKeyOk");
  assert.ok(!hex(ok).includes(hex(new TextEncoder().encode(KEY))));
  assert.ok(hex(ok).includes("46454d2d5445e280a6"));
});

test("0x42 is still not a vendor command", () => {
  for (const [name, bytes] of goldens()) {
    if (name.startsWith("kFryReq")) assert.notEqual(bytes[9], 0x42);
  }
});

// ---- the shared fixture (round 2): test/fixtures/improv_fry_vectors.json ------------------------
// The single source the dashboard vendors byte-identical and the native suite test_improv_fixture
// reads. Every vector there must equal the C++ golden, the independent JS encoding above, and
// PROTOCOL.md - and must say how it was built (its strings / request data), not just its bytes.
const fixture = JSON.parse(readFileSync(
  path.resolve(here, "../fixtures/improv_fry_vectors.json"), "utf8"));

test("the fixture carries exactly the seven vectors", () => {
  assert.equal(fixture.schema, 1);
  assert.deepEqual(fixture.vectors.map((v) => v.name).sort(), Object.keys(expected).sort());
});

for (const v of fixture.vectors) {
  test(`${v.name}: fixture hex = C++ golden = JS encoding`, () => {
    assert.equal(v.hex, hex(expected[v.name]));
    assert.equal(v.hex, hex(goldens().get(v.name)));
  });

  test(`${v.name}: the fixture's own inputs rebuild its bytes`, () => {
    const rebuilt = v.kind === "rpc_request"
      ? rpcRequest(v.command, [...Buffer.from(v.data_hex, "hex")])
      : rpcResult(v.command, v.strings);
    assert.equal(hex(rebuilt), v.hex);
  });
}

test("the fixture file is ASCII-only, so vendored copies stay byte-identical", () => {
  const raw = readFileSync(path.resolve(here, "../fixtures/improv_fry_vectors.json"));
  assert.ok([...raw].every((b) => b < 0x80));
});
