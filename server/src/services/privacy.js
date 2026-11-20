/**
 * What a THIRD PARTY may see. Principle: show the minimum needed to answer "is this document registered
 * and does my copy match?", and reveal more only when the owner chooses a higher share level.
 */
const crypto = require("crypto");

const LEVELS = ["basic", "name", "technical"];
const levelIndex = (l) => Math.max(0, LEVELS.indexOf(l));

/** 144 random bits, URL-safe: an unguessable capability token. */
const newShareToken = () => crypto.randomBytes(18).toString("base64url");
const isToken = (t) => typeof t === "string" && /^[A-Za-z0-9_-]{16,64}$/.test(t);

function isShareActive(share, now = Date.now()) {
  return !!(share && share.token && !share.revoked && (!share.expiresAt || new Date(share.expiresAt).getTime() > now));
}

/**
 * The only function that builds a public response about a document.
 * basic:     registered + date + network + version
 * name:      + file name (the owner decided to reveal it)
 * technical: + SHA-256, transaction, block (the owner decided to reveal it)
 * NEVER included at any level: uploader reference, owner identity, metadata, capture location, hidden-content findings.
 */
function publicView(doc, share, network) {
  const lvl = levelIndex(share && share.level);
  const out = { status: "REGISTERED", registeredAt: doc.notarizedAt, network: network || "unknown", version: doc.version || 1, level: LEVELS[lvl] };
  if (lvl >= 1) out.filename = doc.filename;
  if (lvl >= 2) { out.sha256 = doc.hash; out.txHash = doc.txHash; out.blockNumber = doc.blockNumber; }
  return out;
}

/**
 * Pseudonymous on-chain reference. Different for every document, so a user's records cannot be linked
 * together by reading the public chain, yet the server (which knows the secret) can still prove ownership.
 */
const uploaderRef = (secret, userId, hash) =>
  crypto.createHmac("sha256", secret).update(`vouch-ref-v1:${userId}:${hash}`).digest("hex").slice(0, 32);

/** Compares a viewer's file hash with the document and its versions. Never returns any hash. */
function classifyMatch(computedHash, doc, lineage = []) {
  if (computedHash === doc.hash) return { status: "AUTHENTIC" };
  const other = lineage.find((v) => v.hash === computedHash);
  if (other) return { status: "OTHER_VERSION", version: other.version, registeredVersion: doc.version || 1, isLatest: !!other.isLatest };
  return { status: "NO_MATCH" };
}

module.exports = { LEVELS, newShareToken, isToken, isShareActive, publicView, uploaderRef, classifyMatch };
