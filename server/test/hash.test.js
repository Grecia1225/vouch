const test = require("node:test");
const assert = require("node:assert");
const { sha256Hex, isSha256Hex } = require("../src/services/hash");

test("sha256Hex matches the known digest of 'abc'", () => {
  assert.strictEqual(sha256Hex(Buffer.from("abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});

test("a one-character change produces a completely different hash", () => {
  const a = sha256Hex(Buffer.from("Pay Rs 1000"));
  const b = sha256Hex(Buffer.from("Pay Rs 9000"));
  assert.notStrictEqual(a, b);
});

test("isSha256Hex validates format", () => {
  assert.ok(isSha256Hex("a".repeat(64)));
  assert.ok(!isSha256Hex("xyz"));
  assert.ok(!isSha256Hex("a".repeat(63)));
});
