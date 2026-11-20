/** Normalises every way data can arrive (uploaded files, camera, voice, links) into one list. */
const { fetchRemote } = require("./remoteFile");

const MAX_ITEMS = 10;
const SOURCES = ["file", "camera", "voice", "url", "scan"];

const parseArray = (s) => { try { const a = JSON.parse(s); return Array.isArray(a) ? a : []; } catch { return []; } };
const num = (v) => (v === null || v === "" || v === undefined ? NaN : Number(v));

/** Only known, validated keys survive. Location is self-reported by the browser. */
function cleanContext(c, fallbackSource = "file") {
  c = c && typeof c === "object" ? c : {};
  const out = { source: SOURCES.includes(c.source) ? c.source : fallbackSource };
  if (c.capturedAt && !isNaN(Date.parse(c.capturedAt))) out.capturedAt = new Date(c.capturedAt).toISOString();
  const l = c.location;
  if (l && Math.abs(num(l.latitude)) <= 90 && Math.abs(num(l.longitude)) <= 180) {
    out.location = { latitude: +num(l.latitude).toFixed(6), longitude: +num(l.longitude).toFixed(6) };
    if (Number.isFinite(num(l.accuracy))) out.location.accuracyMeters = Math.round(num(l.accuracy));
    out.location.reportedBy = "browser (unverified)";
  }
  if (Number.isFinite(num(c.durationSec))) out.durationSec = Math.round(num(c.durationSec));
  if (typeof c.sourceUrl === "string") out.sourceUrl = c.sourceUrl.slice(0, 500);
  return out;
}

async function collectInputs(req) {
  const files = req.files || [];
  const contexts = parseArray(req.body && req.body.contexts);
  const urls = parseArray(req.body && req.body.urls).filter((u) => typeof u === "string" && u.trim()).slice(0, 5);

  const items = files.map((f, i) => ({
    name: f.originalname, buffer: f.buffer, mimeType: f.mimetype, context: cleanContext(contexts[i], "file"),
  }));
  for (const u of urls) {
    const context = { source: "url", sourceUrl: u.slice(0, 500) };
    try {
      const r = await fetchRemote(u.trim());
      items.push({ name: r.filename, buffer: r.buffer, mimeType: r.mimeType, context });
    } catch (e) {
      items.push({ name: u.slice(0, 80), error: e.message, context });
    }
  }
  return items.slice(0, MAX_ITEMS);
}

module.exports = { collectInputs, cleanContext, MAX_ITEMS };
