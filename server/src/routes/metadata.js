const router = require("express").Router();
const multer = require("multer");
const { analyseFile } = require("../services/metadata");
const { collectInputs } = require("../services/inputs");
const { maxFileBytes } = require("../config");

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: maxFileBytes, files: 10 } });

// Public, stateless: items are analysed in memory and never stored
router.post("/analyze", upload.array("files", 10), async (req, res, next) => {
  try {
    const items = await collectInputs(req);
    if (!items.length) return res.status(400).json({ error: "Add at least one file, capture or link to analyse" });
    let lastModified = [];
    try { lastModified = JSON.parse(req.body.lastModifieds || "[]"); } catch (_) { /* ignore */ }
    const results = [];
    for (let i = 0; i < items.length; i++) {
      const it = items[i];
      if (it.error) { results.push({ name: it.name, error: it.error }); continue; }
      const lm = Number(lastModified[i]);
      results.push({ name: it.name, report: await analyseFile(it.buffer, it.name, { context: it.context, clientLastModified: it.context.source === "file" && lm > 0 ? lm : undefined }) });
    }
    res.json({ results });
  } catch (e) { next(e); }
});

module.exports = router;
