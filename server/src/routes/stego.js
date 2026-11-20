const router = require("express").Router();
const multer = require("multer");
const auth = require("../middleware/auth");
const { detectType, textForScan } = require("../services/metadata");
const { extractCandidate } = require("../services/stego");
const { collectInputs } = require("../services/inputs");
const { audit } = require("../services/audit");
const { maxFileBytes } = require("../config");

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: maxFileBytes, files: 1 } });

// Lets a logged-in analyst download a hidden payload that the analyser found.
// The bytes are sent as an opaque attachment with a harmless extension: never rendered, never executed.
router.post("/extract", auth, upload.array("files", 1), async (req, res, next) => {
  try {
    const [item] = await collectInputs(req);
    if (!item || item.error) return res.status(400).json({ error: item ? item.error : "Add the file to extract from" });
    const id = String(req.body.candidateId || "").slice(0, 80);
    const { type, entries } = detectType(item.buffer);
    const out = extractCandidate(item.buffer, type, id, textForScan(item.buffer, type, entries));
    if (!out) return res.status(404).json({ error: "That hidden item was not found in this file" });
    audit("extract_hidden", req.user.id, { candidate: id, bytes: out.buffer.length });
    res.set({
      "Content-Type": "application/octet-stream",
      "Content-Disposition": `attachment; filename="${out.filename}"`,
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": "sandbox",
    });
    res.send(out.buffer);
  } catch (e) { next(e); }
});

module.exports = router;
