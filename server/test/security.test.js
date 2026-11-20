const test = require("node:test");
const assert = require("node:assert");
const { AuditChain, MemoryStore, eventHash, ZERO } = require("../src/services/audit");
const lockout = require("../src/services/lockout");

async function build(n = 5) {
  const store = new MemoryStore();
  const chain = new AuditChain(store);
  for (let i = 0; i < n; i++) await chain.log(i % 2 ? "login" : "notarize", `user-${i}`, { n: i, b: 2, a: 1 });
  return { store, chain };
}

test("audit chain links events and verifies", async () => {
  const { store, chain } = await build();
  assert.strictEqual(store.events[0].prevHash, ZERO);
  assert.strictEqual(store.events[1].prevHash, store.events[0].hash);
  const r = await chain.verify();
  assert.ok(r.ok);
  assert.strictEqual(r.count, 5);
  assert.strictEqual(r.headHash, store.events[4].hash);
});

test("audit chain detects an edited event", async () => {
  const { store, chain } = await build();
  store.events[2].detail = { n: 999 };
  const r = await chain.verify();
  assert.ok(!r.ok);
  assert.strictEqual(r.brokenAt, 3);
  assert.match(r.reason, /edited/);
});

test("audit chain detects a deleted event", async () => {
  const { store, chain } = await build();
  store.events.splice(1, 1);
  const r = await chain.verify();
  assert.ok(!r.ok);
  assert.match(r.reason, /deleted|gap/i);
});

test("audit chain detects a rewritten history even if one hash is recomputed", async () => {
  const { store, chain } = await build();
  store.events[1].action = "nothing happened";
  store.events[1].hash = eventHash(store.events[1]); // attacker fixes this event's own hash...
  const r = await chain.verify();
  assert.ok(!r.ok); // ...but the next event still points at the old hash
  assert.strictEqual(r.brokenAt, 3);
});

test("concurrent logging keeps a valid chain", async () => {
  const chain = new AuditChain(new MemoryStore());
  await Promise.all(Array.from({ length: 25 }, (_, i) => chain.log("notarize", `u${i}`, { i })));
  const r = await chain.verify();
  assert.ok(r.ok);
  assert.strictEqual(r.count, 25);
});

test("lockout triggers after 5 failures, then expires", () => {
  let user = { failedLogins: 0, lockedUntil: null };
  const t0 = 1_000_000;
  for (let i = 1; i <= 4; i++) {
    const u = lockout.afterFailure(user, t0);
    assert.ok(!u.locked);
    user = { ...user, failedLogins: u.failedLogins };
  }
  const fifth = lockout.afterFailure(user, t0);
  assert.ok(fifth.locked);
  const locked = { failedLogins: 0, lockedUntil: fifth.lockedUntil };
  assert.ok(lockout.isLocked(locked, t0 + 60_000));
  assert.ok(!lockout.isLocked(locked, t0 + lockout.LOCK_MS + 1));
  assert.deepStrictEqual(lockout.afterSuccess(), { failedLogins: 0, lockedUntil: null });
});
