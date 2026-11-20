/**
 * OPTIONAL external tools for wider coverage: ExifTool (any file family) and c2patool (Content Credentials).
 * Disabled unless ENABLE_EXIFTOOL=true / EXIFTOOL_PATH / C2PATOOL_PATH are set. Safety: no shell, fixed arguments,
 * private temp file with a random name (deleted afterwards), 10 s timeout, 2 MB output cap, minimal environment.
 * Production advice: run this service in a container with no network and a read-only filesystem.
 */
const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const exiftoolEnabled = () => process.env.ENABLE_EXIFTOOL === "true" || !!process.env.EXIFTOOL_PATH;
const c2paEnabled = () => !!process.env.C2PATOOL_PATH;

async function withTempFile(buf, fn) {
  const p = path.join(os.tmpdir(), "vouch-" + crypto.randomBytes(12).toString("hex"));
  await fs.promises.writeFile(p, buf, { mode: 0o600 });
  try { return await fn(p); } finally { fs.promises.unlink(p).catch(() => {}); }
}

function run(cmd, args, { timeoutMs = 10000, maxBytes = 2 * 1024 * 1024 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { shell: false, stdio: ["ignore", "pipe", "ignore"], env: { PATH: process.env.PATH || "", LANG: "C" } });
    let out = Buffer.alloc(0), killed = false;
    const timer = setTimeout(() => { killed = true; child.kill("SIGKILL"); }, timeoutMs);
    child.stdout.on("data", (c) => { out = Buffer.concat([out, c]); if (out.length > maxBytes) { killed = true; child.kill("SIGKILL"); } });
    child.on("error", (e) => { clearTimeout(timer); reject(e); });
    child.on("close", (code) => { clearTimeout(timer); killed ? reject(new Error("Tool timed out or produced too much output")) : resolve({ code, stdout: out.toString("utf8") }); });
  });
}

async function exiftool(buf) {
  const cmd = process.env.EXIFTOOL_PATH || "exiftool";
  return withTempFile(buf, async (p) => {
    const { stdout } = await run(cmd, ["-json", "-G1", "-n", "-m", "-api", "largefilesupport=1", "--", p]);
    const obj = (JSON.parse(stdout)[0]) || {};
    const out = {};
    for (const [k, v] of Object.entries(obj)) {
      if (k === "SourceFile" || k.startsWith("System:") || k.startsWith("ExifTool:")) continue; // these describe our temp file, not the upload
      if (Object.keys(out).length >= 400) break;
      out[k] = typeof v === "string" ? v.slice(0, 200) : v;
    }
    return out;
  });
}

async function c2patool(buf) {
  return withTempFile(buf, async (p) => {
    const { stdout } = await run(process.env.C2PATOOL_PATH, [p], { timeoutMs: 15000 });
    try { const j = JSON.parse(stdout); return { activeManifest: j.active_manifest, validationStatus: j.validation_status, manifests: Object.keys(j.manifests || {}).length }; }
    catch { return { raw: stdout.slice(0, 2000) }; }
  });
}

/** Runs whichever tools are enabled. Failures are reported, never thrown. */
async function runExternal(buf, { c2paPresent }) {
  const extended = {};
  if (exiftoolEnabled()) { try { extended.exiftool = await exiftool(buf); } catch (e) { extended.exiftoolError = e.message; } }
  if (c2paEnabled() && c2paPresent) { try { extended.c2pa = await c2patool(buf); } catch (e) { extended.c2paError = e.message; } }
  return Object.keys(extended).length ? extended : undefined;
}

module.exports = { runExternal, exiftoolEnabled, c2paEnabled };
