const router = require("express").Router();
const multer = require("multer");
const Document = require("../models/Document");
const { sha256Hex, isSha256Hex } = require("../services/hash");
const chain = require("../services/blockchain");
const { collectInputs } = require("../services/inputs");
const { maxFileBytes } = require("../config");

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: maxFileBytes, files: 10 } });

// Public metadata only: never expose filename or owner details
async function publicMeta(hash) {
  const d = await Document.findOne({ hash }).select("txHash blockNumber -_id");
  return d ? { txHash: d.txHash, blockNumber: d.blockNumber } : {};
}

async function verifyOne(item, expected) {
  if (item.error) return { name: item.name, status: "ERROR", error: item.error };
  const hash = sha256Hex(item.buffer);
  const rec = await chain.lookup(hash);
  if (rec.exists) return { name: item.name, status: "AUTHENTIC", hash, record: rec, ...(await publicMeta(hash)) };
  if (isSha256Hex(expected)) {
    const exp = expected.toLowerCase();
    const expRec = await chain.lookup(exp);
    if (expRec.exists) return { name: item.name, status: "TAMPERED", hash, expectedHash: exp, record: expRec, ...(await publicMeta(exp)) };
  }
  return { name: item.name, status: "NOT_FOUND", hash };
}

// Verify one or many items (files, camera captures, voice, links).
// `expectedHash` (from a certificate QR) is only used when exactly one item is sent.
router.post("/", upload.array("files", 10), async (req, res, next) => {
  try {
    const items = await collectInputs(req);
    if (!items.length) return res.status(400).json({ error: "Add at least one file, capture or link to verify" });
    const expected = items.length === 1 ? (req.body.expectedHash || "") : "";
    const results = [];
    for (const item of items) results.push(await verifyOne(item, expected));
    res.json({ results });
  } catch (e) { next(e); }
});

// Version history of a document, read from the contract (newest first)
router.get("/:hash/history", async (req, res, next) => {
  try {
    const hash = req.params.hash.toLowerCase();
    if (!isSha256Hex(hash)) return res.status(400).json({ error: "Invalid hash" });
    res.json({ hash, versions: await chain.history(hash) });
  } catch (e) { next(e); }
});

// Look up a record by hash (used when someone scans the certificate QR)
router.get("/:hash", async (req, res, next) => {
  try {
    const hash = req.params.hash.toLowerCase();
    if (!isSha256Hex(hash)) return res.status(400).json({ error: "Invalid hash" });
    const rec = await chain.lookup(hash);
    res.json(rec.exists ? { found: true, hash, record: rec, ...(await publicMeta(hash)) } : { found: false, hash });
  } catch (e) { next(e); }
});

module.exports = router;
