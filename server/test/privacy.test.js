const test = require("node:test");
const assert = require("node:assert");
const p = require("../src/services/privacy");

const doc = { filename: "contract.pdf", hash: "a".repeat(64), txHash: "0x" + "b".repeat(64), blockNumber: 77, notarizedAt: "2026-01-01T00:00:00Z", version: 2, uploaderRef: "SECRET-REF", owner: "user-1", metadata: { author: "x" }, capture: { location: { latitude: 1, longitude: 2 } } };

test("share tokens are unguessable and well-formed", () => {
  const a = p.newShareToken(), b = p.newShareToken();
  assert.notStrictEqual(a, b);
  assert.strictEqual(a.length, 24); // 144 bits, base64url
  assert.ok(p.isToken(a));
  assert.ok(!p.isToken("short") && !p.isToken("../etc/passwd") && !p.isToken(undefined) && !p.isToken("a".repeat(100)));
});

test("share links can expire or be revoked", () => {
  const now = Date.parse("2026-06-01T00:00:00Z");
  assert.ok(p.isShareActive({ token: "x".repeat(24) }, now));
  assert.ok(p.isShareActive({ token: "x".repeat(24), expiresAt: "2026-07-01T00:00:00Z" }, now));
  assert.ok(!p.isShareActive({ token: "x".repeat(24), expiresAt: "2026-05-01T00:00:00Z" }, now));
  assert.ok(!p.isShareActive({ token: "x".repeat(24), revoked: true }, now));
  assert.ok(!p.isShareActive(undefined, now) && !p.isShareActive({}, now));
});

test("public view reveals only what the owner chose", () => {
  const basic = p.publicView(doc, { level: "basic" }, "amoy");
  assert.deepStrictEqual(Object.keys(basic).sort(), ["level", "network", "registeredAt", "status", "version"]);
  const named = p.publicView(doc, { level: "name" }, "amoy");
  assert.strictEqual(named.filename, "contract.pdf");
  assert.ok(!("sha256" in named) && !("txHash" in named));
  const tech = p.publicView(doc, { level: "technical" }, "amoy");
  assert.strictEqual(tech.sha256, doc.hash);
  // at EVERY level these never appear
  for (const level of p.LEVELS) {
    const json = JSON.stringify(p.publicView(doc, { level }, "amoy"));
    for (const secret of ["SECRET-REF", "user-1", "author", "latitude"]) assert.ok(!json.includes(secret), `${level} leaked ${secret}`);
  }
  assert.strictEqual(p.publicView(doc, undefined, "amoy").level, "basic"); // unknown level falls back to the strictest
});

test("on-chain uploader references are unlinkable across documents but stable per document", () => {
  const a1 = p.uploaderRef("secret", "user-1", "hash-A"), a2 = p.uploaderRef("secret", "user-1", "hash-A");
  const b = p.uploaderRef("secret", "user-1", "hash-B"), other = p.uploaderRef("secret", "user-2", "hash-A");
  assert.strictEqual(a1, a2);
  assert.notStrictEqual(a1, b); // same user, different document: cannot be linked by reading the chain
  assert.notStrictEqual(a1, other);
  assert.ok(!a1.includes("user-1") && a1.length === 32 && /^[a-f0-9]+$/.test(a1));
  assert.notStrictEqual(p.uploaderRef("different-secret", "user-1", "hash-A"), a1); // needs the server secret to reproduce
});

test("match results never contain a hash", () => {
  const lineage = [{ hash: doc.hash, version: 2, isLatest: true }, { hash: "c".repeat(64), version: 1, isLatest: false }];
  assert.deepStrictEqual(p.classifyMatch(doc.hash, doc, lineage), { status: "AUTHENTIC" });
  const old = p.classifyMatch("c".repeat(64), doc, lineage);
  assert.strictEqual(old.status, "OTHER_VERSION");
  assert.strictEqual(old.version, 1);
  assert.strictEqual(p.classifyMatch("d".repeat(64), doc, lineage).status, "NO_MATCH");
  for (const r of [p.classifyMatch(doc.hash, doc, lineage), old, p.classifyMatch("d".repeat(64), doc, lineage)])
    assert.ok(!JSON.stringify(r).match(/[a-f0-9]{32}/), "no hash-like value in a public match result");
});
