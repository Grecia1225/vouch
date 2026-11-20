const router = require("express").Router();
const multer = require("multer");
const Document = require("../models/Document");
const chain = require("../services/blockchain");
const { sha256Hex } = require("../services/hash");
const { collectInputs } = require("../services/inputs");
const { isToken, isShareActive, publicView, classifyMatch } = require("../services/privacy");
const { maxFileBytes, network } = require("../config");

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: maxFileBytes, files: 5 } });
const NOT_VALID = { error: "This link is not valid or has expired" }; // same answer for unknown, revoked and expired

async function findByToken(token) {
  if (!isToken(token)) return null;
  const doc = await Document.findOne({ "share.token": token }).select("filename hash version previousHash txHash blockNumber notarizedAt share");
  return doc && isShareActive(doc.share) ? doc : null;
}

// All versions of the same document that Vouch knows about (walks previous links both ways)
async function lineage(doc) {
  const out = [{ hash: doc.hash, version: doc.version || 1 }];
  let cur = doc;
  for (let i = 0; i < 25 && cur.previousHash; i++) {
    cur = await Document.findOne({ hash: cur.previousHash }).select("hash version previousHash");
    if (!cur) break;
    out.push({ hash: cur.hash, version: cur.version || 1 });
  }
  cur = doc;
  for (let i = 0; i < 25; i++) {
    const next = await Document.findOne({ previousHash: cur.hash }).select("hash version");
    if (!next) break;
    out.push({ hash: next.hash, version: next.version || 1 });
    cur = next;
  }
  const latest = Math.max(...out.map((v) => v.version));
  return out.map((v) => ({ ...v, isLatest: v.version === latest }));
}

// Minimal public view for whoever holds the link
router.get("/:token", async (req, res, next) => {
  try {
    const doc = await findByToken(req.params.token);
    if (!doc) return res.status(404).json(NOT_VALID);
    res.json(publicView(doc, doc.share, network));
  } catch (e) { next(e); }
});

// "Does my copy match?" The answer never contains a hash.
router.post("/:token/check", upload.array("files", 5), async (req, res, next) => {
  try {
    const doc = await findByToken(req.params.token);
    if (!doc) return res.status(404).json(NOT_VALID);
    const items = await collectInputs(req);
    if (!items.length) return res.status(400).json({ error: "Add a file, capture or link to check" });
    const onChain = (await chain.lookup(doc.hash)).exists;
    const versions = await lineage(doc);
    const results = items.map((it) => {
      if (it.error) return { name: it.name, status: "ERROR", error: it.error };
      const m = classifyMatch(sha256Hex(it.buffer), doc, versions);
      return { name: it.name, ...(m.status === "AUTHENTIC" && !onChain ? { status: "RECORD_UNAVAILABLE" } : m) };
    });
    res.json({ registeredAt: doc.notarizedAt, results });
  } catch (e) { next(e); }
});

module.exports = router;
