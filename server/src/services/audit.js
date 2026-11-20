/**
 * Tamper-evident audit log: every event embeds the hash of the previous one (a hash chain),
 * so editing, deleting or reordering any past event breaks every later hash.
 * The head hash can additionally be anchored on the blockchain (see scripts/verify-audit.js --anchor).
 */
const crypto = require("crypto");

const ZERO = "0".repeat(64);
const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");

function stable(v) {
  if (Array.isArray(v)) return "[" + v.map(stable).join(",") + "]";
  if (v && typeof v === "object") return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + stable(v[k])).join(",") + "}";
  return JSON.stringify(v === undefined ? null : v);
}
const eventHash = (e) => sha256(stable([e.seq, e.at, e.actor || null, e.action, e.detail || {}, e.prevHash]));

class MemoryStore {
  constructor() { this.events = []; }
  async last() { return this.events[this.events.length - 1] || null; }
  async append(ev) { this.events.push(ev); }
  async *all() { for (const e of this.events) yield e; }
}

class AuditChain {
  constructor(store) { this.store = store; this.queue = Promise.resolve(); }

  /** Appends an event. Calls are serialised so sequence numbers and hashes stay consistent. */
  log(action, actor, detail = {}) {
    const run = async () => {
      const last = await this.store.last();
      const ev = { seq: last ? last.seq + 1 : 1, at: new Date().toISOString(), actor: actor ? String(actor) : null, action, detail, prevHash: last ? last.hash : ZERO };
      ev.hash = eventHash(ev);
      await this.store.append(ev);
      return ev;
    };
    const p = this.queue.then(run, run);
    this.queue = p.catch(() => {});
    return p;
  }

  /** Recomputes the whole chain. Returns {ok, count, headHash} or {ok:false, brokenAt, reason}. */
  async verify() {
    let prev = ZERO, expected = 1, count = 0;
    for await (const ev of this.store.all()) {
      if (ev.seq !== expected) return { ok: false, count, brokenAt: expected, reason: `Sequence gap: expected event ${expected}, found ${ev.seq} (event deleted or reordered)` };
      if (ev.prevHash !== prev) return { ok: false, count, brokenAt: ev.seq, reason: "Link to the previous event does not match" };
      if (eventHash(ev) !== ev.hash) return { ok: false, count, brokenAt: ev.seq, reason: "Event content does not match its hash (edited)" };
      prev = ev.hash; expected++; count++;
    }
    return { ok: true, count, headHash: prev };
  }
}

let shared;
/** Lazily creates the MongoDB-backed log used by the running server. */
function getAudit() {
  if (!shared) shared = new AuditChain(require("./auditStore"));
  return shared;
}
/** Fire-and-forget helper: auditing must never break a user request. */
const audit = (action, actor, detail) => getAudit().log(action, actor, detail).catch((e) => console.error("audit failed:", e.message));

module.exports = { AuditChain, MemoryStore, eventHash, stable, getAudit, audit, ZERO };
