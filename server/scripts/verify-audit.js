/**
 * Verifies the audit log's hash chain. With --anchor, also records the head hash on the blockchain
 * so even someone with full database access cannot rewrite history without detection.
 *   node scripts/verify-audit.js [--anchor]
 */
const mongoose = require("mongoose");
const cfg = require("../src/config");
const { AuditChain } = require("../src/services/audit");
const store = require("../src/services/auditStore");

(async () => {
  await mongoose.connect(cfg.mongoUri);
  const res = await new AuditChain(store).verify();
  if (!res.ok) {
    console.error(`AUDIT LOG BROKEN at event ${res.brokenAt}: ${res.reason}`);
    process.exit(1);
  }
  console.log(`Audit log OK: ${res.count} events, head ${res.headHash}`);
  if (process.argv.includes("--anchor") && res.count) {
    const chain = require("../src/services/blockchain");
    if ((await chain.lookup(res.headHash)).exists) console.log("Head hash is already anchored on-chain.");
    else { const tx = await chain.notarize(res.headHash, "audit-log-head"); console.log(`Anchored head hash on-chain. tx ${tx.txHash}`); }
  }
  await mongoose.disconnect();
})().catch((e) => { console.error(e.message); process.exit(2); });
