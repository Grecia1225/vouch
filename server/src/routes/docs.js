const router = require("express").Router();
const multer = require("multer");
const auth = require("../middleware/auth");
const Document = require("../models/Document");
const User = require("../models/User");
const { getBucket } = require("../db");
const { sha256Hex } = require("../services/hash");
const chain = require("../services/blockchain");
const { buildCertificate } = require("../services/certificate");
const { analyseFile, sanitizeForStorage } = require("../services/metadata");
const { collectInputs } = require("../services/inputs");
const { audit } = require("../services/audit");
const privacy = require("../services/privacy");
const { maxFileBytes, clientUrl, refSecret, network } = require("../config");

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: maxFileBytes, files: 10 } });

function saveToGridFS(item) {
  return new Promise((resolve, reject) => {
    const stream = getBucket().openUploadStream(item.name, { contentType: item.mimeType });
    stream.on("error", reject);
    stream.on("finish", () => resolve(stream.id));
    stream.end(item.buffer);
  });
}

// Notarize ONE item: hash -> snapshot metadata -> store file -> anchor hash on chain -> save record
async function notarizeOne(item, userId, link = {}) {
  if (item.error) return { name: item.name, status: "error", error: item.error };
  let fileId;
  try {
    const hash = sha256Hex(item.buffer);
    if ((await chain.lookup(hash)).exists)
      return { name: item.name, status: "exists", hash, error: "This exact file is already notarized" };

    let metadata;
    try { metadata = sanitizeForStorage(await analyseFile(item.buffer, item.name, { context: item.context })); } catch (_) { /* best effort */ }

    fileId = await saveToGridFS(item);
    const tx = await chain.notarize(hash, privacy.uploaderRef(refSecret, userId, hash), link.previousHash);
    const doc = await Document.create({
      owner: userId, filename: item.name, mimeType: item.mimeType, size: item.buffer.length, hash, fileId,
      txHash: tx.txHash, blockNumber: tx.blockNumber, notarizedAt: new Date(tx.timestamp * 1000),
      metadata, capture: item.context,
      share: { token: privacy.newShareToken(), level: "basic" },
      ...(link.previousHash ? { previousHash: link.previousHash, version: link.version } : {}),
    });
    audit(link.previousHash ? "version" : "notarize", userId, { hash, txHash: tx.txHash, ...(link.previousHash ? { previousHash: link.previousHash } : {}) });
    return { name: item.name, status: "ok", doc };
  } catch (e) {
    if (fileId) getBucket().delete(fileId).catch(() => {}); // roll back orphaned file
    return { name: item.name, status: "error", error: e.message };
  }
}

// Batch notarize: files + camera/voice captures + links. Sequential, because one relayer wallet
// must send transactions in nonce order.
router.post("/notarize", auth, upload.array("files", 10), async (req, res, next) => {
  try {
    const items = await collectInputs(req);
    if (!items.length) return res.status(400).json({ error: "Add at least one file, capture or link" });
    const results = [];
    for (const item of items) results.push(await notarizeOne(item, req.user.id));
    res.status(results.some((r) => r.status === "ok") ? 201 : 200).json({ results });
  } catch (e) { next(e); }
});

// New version of one of your documents: the contract links it to the previous hash.
router.post("/:id/version", auth, upload.array("files", 1), async (req, res, next) => {
  try {
    const prev = await Document.findOne({ _id: req.params.id, owner: req.user.id });
    if (!prev) return res.status(404).json({ error: "Document not found" });
    const items = await collectInputs(req);
    if (items.length !== 1) return res.status(400).json({ error: "Add exactly one file for the new version" });
    const result = await notarizeOne(items[0], req.user.id, { previousHash: prev.hash, version: (prev.version || 1) + 1 });
    res.status(result.status === "ok" ? 201 : 200).json({ results: [result] });
  } catch (e) { next(e); }
});

router.get("/", auth, async (req, res, next) => {
  try {
    res.json(await Document.find({ owner: req.user.id }).sort({ createdAt: -1 }));
  } catch (e) { next(e); }
});

async function ownedDoc(req, res) {
  const doc = await Document.findOne({ _id: req.params.id, owner: req.user.id });
  if (!doc) res.status(404).json({ error: "Document not found" });
  return doc;
}

router.get("/:id/metadata", auth, async (req, res, next) => {
  try {
    const doc = await ownedDoc(req, res);
    if (!doc) return;
    res.json(doc.metadata || null);
  } catch (e) { next(e); }
});

// Owner controls what a third party sees through the share link (and can revoke it any time)
router.post("/:id/share", auth, async (req, res, next) => {
  try {
    const doc = await ownedDoc(req, res);
    if (!doc) return;
    const { level, expiresInDays, regenerate } = req.body || {};
    if (level !== undefined && !privacy.LEVELS.includes(level)) return res.status(400).json({ error: "Unknown share level" });
    const days = Number(expiresInDays) || 0;
    if (days < 0 || days > 3650) return res.status(400).json({ error: "Expiry must be 0 (never) to 3650 days" });
    const share = (doc.share && doc.share.toObject ? doc.share.toObject() : doc.share) || {};
    if (!share.token || share.revoked || regenerate) { share.token = privacy.newShareToken(); share.revoked = false; }
    if (level) share.level = level;
    share.expiresAt = days ? new Date(Date.now() + days * 86400000) : null;
    doc.share = share;
    await doc.save();
    audit("share", req.user.id, { docId: String(doc._id), level: share.level, expiresInDays: days });
    res.json({ token: share.token, level: share.level, expiresAt: share.expiresAt, url: `${clientUrl}/v/${share.token}` });
  } catch (e) { next(e); }
});

router.delete("/:id/share", auth, async (req, res, next) => {
  try {
    const doc = await ownedDoc(req, res);
    if (!doc) return;
    if (doc.share) { doc.share.revoked = true; await doc.save(); }
    audit("share_revoked", req.user.id, { docId: String(doc._id) });
    res.json({ revoked: true });
  } catch (e) { next(e); }
});

router.get("/:id/download", auth, async (req, res, next) => {
  try {
    const doc = await ownedDoc(req, res);
    if (!doc) return;
    audit("download", req.user.id, { docId: String(doc._id) });
    res.set({
      "Content-Type": doc.mimeType || "application/octet-stream",
      "Content-Disposition": `attachment; filename="${encodeURIComponent(doc.filename)}"`,
    });
    getBucket().openDownloadStream(doc.fileId).on("error", next).pipe(res);
  } catch (e) { next(e); }
});

router.get("/:id/certificate", auth, async (req, res, next) => {
  try {
    const doc = await ownedDoc(req, res);
    if (!doc) return;
    // Legacy records get a share token on first use. The QR carries this token, never the hash.
    if (!doc.share || !doc.share.token) { doc.share = { token: privacy.newShareToken(), level: "basic" }; await doc.save(); }
    const user = await User.findById(req.user.id);
    const variant = req.query.variant === "public" ? "public" : "owner";
    const verifyUrl = `${clientUrl}/v/${doc.share.token}`;
    const pdf = await buildCertificate({ doc, userName: user.name, verifyUrl, variant, level: doc.share.level, network });
    res.set({ "Content-Type": "application/pdf", "Content-Disposition": `inline; filename="vouch-certificate-${variant}-${String(doc._id).slice(-6)}.pdf"` });
    res.send(pdf);
  } catch (e) { next(e); }
});

module.exports = router;
