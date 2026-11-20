/**
 * Vouch Metadata Analyser
 * Reads embedded metadata from PDFs, Office files (docx/xlsx/pptx) and images,
 * then applies simple consistency checks. Findings are INDICATORS, not proof:
 * metadata can be edited or stripped.
 */
const zlib = require("zlib");
const crypto = require("crypto");
const path = require("path");

const { analyseHidden } = require("./stego");
const X = require("./extractors");
const { runExternal } = require("./externalTools");

let exifr = null;
try { exifr = require("exifr"); } catch (_) { /* optional: images fall back to basic info */ }

// ---------------------------------------------------------------- helpers
const toIso = (v) => {
  if (!v) return undefined;
  const d = v instanceof Date ? v : new Date(v);
  return isNaN(d) ? undefined : d.toISOString();
};
const decodeXml = (s) =>
  s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&");
const humanDelta = (ms) => {
  const m = Math.abs(ms) / 60000;
  if (m < 90) return `${Math.round(m)} minutes`;
  if (m < 48 * 60) return `${Math.round(m / 60)} hours`;
  return `${Math.round(m / 1440)} days`;
};
const clean = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && v !== null && v !== ""));

// ---------------------------------------------------------------- type sniffing (magic bytes)
function sniffType(buf) {
  const starts = (hex, off = 0) => buf.subarray(off, off + hex.length / 2).toString("hex") === hex;
  if (starts("25504446")) return { kind: "pdf", mime: "application/pdf", exts: ["pdf"], label: "PDF document" };
  if (starts("ffd8ff")) return { kind: "image", mime: "image/jpeg", exts: ["jpg", "jpeg", "jpe"], label: "JPEG image" };
  if (starts("89504e470d0a1a0a")) return { kind: "image", mime: "image/png", exts: ["png"], label: "PNG image" };
  if (starts("47494638")) return { kind: "image", mime: "image/gif", exts: ["gif"], label: "GIF image" };
  if (starts("49492a00") || starts("4d4d002a")) return { kind: "image", mime: "image/tiff", exts: ["tif", "tiff"], label: "TIFF image" };
  if (starts("52494646") && buf.subarray(8, 12).toString("latin1") === "WEBP")
    return { kind: "image", mime: "image/webp", exts: ["webp"], label: "WebP image" };
  if (starts("504b0304")) return { kind: "zip", mime: "application/zip", exts: ["zip"], label: "ZIP archive" };
  if (buf.subarray(4, 8).toString("latin1") === "ftyp") {
    const brand = buf.subarray(8, 12).toString("latin1");
    if (/^(heic|heix|hevc|mif1|msf1)/.test(brand)) return { kind: "image", mime: "image/heic", exts: ["heic", "heif"], label: "HEIC image" };
    return { kind: "media", mime: "video/mp4", exts: ["mp4", "m4v", "mov", "m4a"], label: "MP4/MOV/M4A media" };
  }
  if (starts("1a45dfa3")) return { kind: "media", mime: "video/webm", exts: ["webm", "weba", "mkv"], label: "WebM media (audio/video)" };
  if (starts("4f676753")) return { kind: "media", mime: "audio/ogg", exts: ["ogg", "oga", "ogv", "opus"], label: "Ogg media" };
  if (starts("52494646") && buf.subarray(8, 12).toString("latin1") === "WAVE") return { kind: "media", mime: "audio/wav", exts: ["wav"], label: "WAV audio" };
  if (starts("494433") || starts("fffb") || starts("fff3") || starts("fff2")) return { kind: "media", mime: "audio/mpeg", exts: ["mp3"], label: "MP3 audio" };
  if (starts("664c6143")) return { kind: "media", mime: "audio/flac", exts: ["flac"], label: "FLAC audio" };
  if (buf.subarray(0, 15).toString("latin1") === "SQLite format 3") return { kind: "database", mime: "application/vnd.sqlite3", exts: ["sqlite", "sqlite3", "db", "db3"], label: "SQLite database" };
  if (starts("4d5a") && buf.length >= 0x40 && buf.readUInt32LE(0x3c) + 4 <= buf.length && buf.toString("latin1", buf.readUInt32LE(0x3c), buf.readUInt32LE(0x3c) + 4) === "PE\0\0")
    return { kind: "executable", mime: "application/vnd.microsoft.portable-executable", exts: ["exe", "dll", "sys", "scr", "ocx", "cpl"], label: "Windows executable (PE)" };
  if (starts("7f454c46")) return { kind: "executable", mime: "application/x-elf", exts: ["", "elf", "so", "o", "bin", "out", "ko"], label: "ELF binary" };
  if (["feedface", "feedfacf", "cefaedfe", "cffaedfe", "cafebabe"].some((m) => starts(m))) return { kind: "executable", mime: "application/x-mach-binary", exts: ["", "dylib", "o", "bin", "class"], label: "Mach-O binary or Java class" };
  if (starts("00010000") || starts("4f54544f") || starts("74727565") || starts("774f4646") || starts("774f4632") || starts("74746366"))
    return { kind: "font", mime: "font/sfnt", exts: ["ttf", "otf", "woff", "woff2", "ttc"], label: "Font file" };
  if (starts("526172211a07")) return { kind: "archive", mime: "application/vnd.rar", exts: ["rar"], label: "RAR archive" };
  if (starts("377abcaf271c")) return { kind: "archive", mime: "application/x-7z-compressed", exts: ["7z"], label: "7-Zip archive" };
  if (starts("1f8b")) return { kind: "archive", mime: "application/gzip", exts: ["gz", "tgz"], label: "gzip data" };
  if (starts("fd377a585a00")) return { kind: "archive", mime: "application/x-xz", exts: ["xz"], label: "xz data" };
  if (buf.subarray(257, 262).toString("latin1") === "ustar") return { kind: "archive", mime: "application/x-tar", exts: ["tar"], label: "TAR archive" };
  if (starts("424d")) return { kind: "image", mime: "image/bmp", exts: ["bmp"], label: "BMP image" };
  if (!buf.subarray(0, 1024).includes(0))
    return { kind: "text", mime: "text/plain", exts: ["txt", "csv", "json", "md", "log", "xml", "html", "htm", "rtf"], label: "Text file" };
  return { kind: "unknown", mime: "application/octet-stream", exts: [], label: "Unknown binary" };
}

// ---------------------------------------------------------------- minimal ZIP reader (no dependencies)
function readZipEntries(buf) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) return null;
  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  const entries = {};
  for (let n = 0; n < count && off + 46 <= buf.length; n++) {
    if (buf.readUInt32LE(off) !== 0x02014b50) break;
    const nlen = buf.readUInt16LE(off + 28), elen = buf.readUInt16LE(off + 30), clen = buf.readUInt16LE(off + 32);
    const name = buf.toString("utf8", off + 46, off + 46 + nlen);
    entries[name] = { flags: buf.readUInt16LE(off + 8), time: buf.readUInt16LE(off + 12), date: buf.readUInt16LE(off + 14), method: buf.readUInt16LE(off + 10), csize: buf.readUInt32LE(off + 20), usize: buf.readUInt32LE(off + 24), lho: buf.readUInt32LE(off + 42) };
    off += 46 + nlen + elen + clen;
  }
  return entries;
}
function readZipComment(buf) {
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--)
    if (buf.readUInt32LE(i) === 0x06054b50) { const n = buf.readUInt16LE(i + 20); return n ? buf.toString("utf8", i + 22, i + 22 + n).slice(0, 300) : undefined; }
  return undefined;
}
function readZipText(buf, entry, maxBytes = 2 * 1024 * 1024) {
  if (!entry || entry.usize > maxBytes) return null;
  try {
    const nlen = buf.readUInt16LE(entry.lho + 26), elen = buf.readUInt16LE(entry.lho + 28);
    const start = entry.lho + 30 + nlen + elen;
    const data = buf.subarray(start, start + entry.csize);
    if (entry.method === 0) return data.toString("utf8");
    if (entry.method === 8) return zlib.inflateRawSync(data, { maxOutputLength: maxBytes }).toString("utf8");
  } catch (_) { /* ignore */ }
  return null;
}

// ---------------------------------------------------------------- PDF
function pdfString(lit, hex) {
  let bytes;
  if (hex !== undefined) {
    const h = hex.replace(/\s+/g, "");
    bytes = Buffer.from(h.length % 2 ? h + "0" : h, "hex");
  } else {
    const out = [];
    for (let i = 0; i < lit.length; i++) {
      const c = lit.charCodeAt(i);
      if (c === 92 && i + 1 < lit.length) {
        const n = lit[++i];
        const esc = { n: 10, r: 13, t: 9, b: 8, f: 12 };
        if (esc[n] !== undefined) out.push(esc[n]);
        else if (/[0-7]/.test(n)) {
          let o = n;
          while (o.length < 3 && /[0-7]/.test(lit[i + 1] || "")) o += lit[++i];
          out.push(parseInt(o, 8) & 255);
        } else if (n !== "\n" && n !== "\r") out.push(n.charCodeAt(0) & 255);
      } else out.push(c & 255);
    }
    bytes = Buffer.from(out);
  }
  if (bytes[0] === 0xfe && bytes[1] === 0xff) {
    const body = Buffer.from(bytes.subarray(2, 2 + ((bytes.length - 2) & ~1)));
    return body.swap16().toString("utf16le");
  }
  return bytes.toString("latin1");
}
function pdfDate(s) {
  if (!s) return undefined;
  const m = /^D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(Z|[+-]\d{2}(?:'?\d{2}'?)?)?/.exec(s.trim());
  if (!m) return toIso(s);
  const [, y, mo = "01", d = "01", h = "00", mi = "00", se = "00", tz] = m;
  let t = Date.UTC(+y, +mo - 1, +d, +h, +mi, +se);
  if (tz && tz !== "Z") {
    const digits = tz.slice(1).replace(/'/g, "");
    t -= (tz[0] === "-" ? -1 : 1) * (+digits.slice(0, 2) * 60 + +(digits.slice(2, 4) || 0)) * 60000;
  }
  return new Date(t).toISOString();
}
async function analysePdf(buf) {
  const txt = buf.toString("latin1");
  let src = "";
  const refs = [...txt.matchAll(/\/Info\s+(\d+)\s+\d+\s+R/g)];
  if (refs.length) {
    const id = refs[refs.length - 1][1];
    const re = new RegExp(`(?:^|[\\r\\n\\s>])${id}\\s+0\\s+obj([\\s\\S]*?)endobj`, "g");
    let m, last;
    while ((m = re.exec(txt))) last = m;
    if (last) src = last[1];
  }
  const grab = (key) => {
    const m = new RegExp(`/${key}\\s*(?:\\(((?:\\\\.|[^\\\\)])*)\\)|<([0-9A-Fa-f\\s]+)>)`).exec(src);
    return m ? pdfString(m[1], m[2]) : undefined;
  };
  let props = clean({
    title: grab("Title"), subject: grab("Subject"), author: grab("Author"), keywords: grab("Keywords"),
    creatorTool: grab("Creator"), producer: grab("Producer"),
    created: pdfDate(grab("CreationDate")), modified: pdfDate(grab("ModDate")),
  });
  let pages = (txt.match(/\/Type\s*\/Page(?![a-zA-Z])/g) || []).length || undefined;

  // Fallback for PDFs that keep the Info dictionary inside compressed object streams
  if (!Object.keys(props).length) {
    try {
      const { PDFDocument } = require("pdf-lib");
      const d = await PDFDocument.load(buf, { updateMetadata: false, ignoreEncryption: true });
      props = clean({
        title: d.getTitle(), subject: d.getSubject(), author: d.getAuthor(), keywords: d.getKeywords(),
        creatorTool: d.getCreator(), producer: d.getProducer(),
        created: toIso(d.getCreationDate()), modified: toIso(d.getModificationDate()),
      });
      pages = d.getPageCount();
    } catch (_) { /* pdf-lib not installed or file unreadable */ }
  }
  const xmp = (tag) => { const m = new RegExp(`<${tag}>([^<]*)</${tag}>`).exec(txt); return m ? decodeXml(m[1]).trim() : undefined; };
  const eofs = (txt.match(/%%EOF/g) || []).length;
  const linearized = /\/Linearized\s/.test(txt.slice(0, 2048));
  const technical = clean({
    pdfVersion: (/^%PDF-(\d\.\d)/.exec(txt) || [])[1],
    pages,
    encrypted: /\/Encrypt\s/.test(txt),
    incrementalUpdates: Math.max(0, eofs - 1 - (linearized ? 1 : 0)),
    containsJavaScript: /\/JavaScript\b|\/JS\s*[(<]/.test(txt),
    embeddedFiles: /\/EmbeddedFile\b/.test(txt),
    hasXmpMetadata: /<x:xmpmeta/.test(txt),
    xmpCreatorTool: xmp("xmp:CreatorTool"),
    xmpCreateDate: toIso(xmp("xmp:CreateDate")),
    xmpModifyDate: toIso(xmp("xmp:ModifyDate")),
  });
  if (!props.creatorTool && technical.xmpCreatorTool) props.creatorTool = technical.xmpCreatorTool;
  return { props, technical };
}

// ---------------------------------------------------------------- Office Open XML (docx / xlsx / pptx)
function analyseOoxml(buf, entries) {
  const read = (n, max) => readZipText(buf, entries[n], max);
  const core = read("docProps/core.xml") || "";
  const app = read("docProps/app.xml") || "";
  const tag = (xml, name) => {
    const m = new RegExp(`<${name}(?:\\s[^>]*)?>([^<]*)</${name}>`).exec(xml);
    return m && m[1].trim() ? decodeXml(m[1].trim()) : undefined;
  };
  const props = clean({
    title: tag(core, "dc:title"), subject: tag(core, "dc:subject"), keywords: tag(core, "cp:keywords"),
    author: tag(core, "dc:creator"), lastModifiedBy: tag(core, "cp:lastModifiedBy"),
    created: toIso(tag(core, "dcterms:created")), modified: toIso(tag(core, "dcterms:modified")),
    revision: tag(core, "cp:revision"), application: tag(app, "Application"), company: tag(app, "Company"),
  });
  const names = Object.keys(entries);
  let tracked, trackedDel;
  if (entries["word/document.xml"]) {
    const doc = read("word/document.xml", 8 * 1024 * 1024) || "";
    tracked = (doc.match(/<w:ins\s/g) || []).length;
    trackedDel = (doc.match(/<w:del\s/g) || []).length;
  }
  const technical = clean({
    appVersion: tag(app, "AppVersion"),
    totalEditingMinutes: tag(app, "TotalTime"),
    pages: tag(app, "Pages"), words: tag(app, "Words"),
    containsMacros: names.some((n) => /vbaProject\.bin$/i.test(n)),
    hasComments: names.some((n) => /(^|\/)comments[^/]*\.xml$/i.test(n)),
    trackedInsertions: tracked, trackedDeletions: trackedDel,
    embeddedMedia: names.filter((n) => /\/media\//i.test(n)).length || undefined,
  });
  return { props, technical };
}

// ---------------------------------------------------------------- Images
function imageSize(buf, mime) {
  try {
    if (mime === "image/png") return { width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
    if (mime === "image/gif") return { width: buf.readUInt16LE(6), height: buf.readUInt16LE(8) };
    if (mime === "image/jpeg") {
      let i = 2;
      while (i + 9 < buf.length) {
        if (buf[i] !== 0xff) { i++; continue; }
        const m = buf[i + 1];
        if (m >= 0xc0 && m <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(m)) return { width: buf.readUInt16BE(i + 7), height: buf.readUInt16BE(i + 5) };
        if (m === 0xd8 || m === 0x01 || (m >= 0xd0 && m <= 0xd7)) { i += 2; continue; }
        i += 2 + buf.readUInt16BE(i + 2);
      }
    }
  } catch (_) { /* ignore */ }
  return {};
}
async function analyseImage(buf, type) {
  const technical = { ...imageSize(buf, type.mime) };
  let props = {};
  if (exifr) {
    try {
      const x = await exifr.parse(buf, { tiff: true, ifd0: true, exif: true, gps: true, iptc: true, xmp: false, icc: false, reviveValues: true, translateValues: true });
      if (x) {
        props = clean({
          title: x.ImageDescription, author: x.Artist, creatorTool: x.Software, copyright: x.Copyright,
          created: toIso(x.DateTimeOriginal || x.CreateDate), modified: toIso(x.ModifyDate),
        });
        Object.assign(technical, clean({
          cameraMake: x.Make, cameraModel: x.Model, lens: x.LensModel,
          exposureTime: x.ExposureTime, fNumber: x.FNumber, iso: x.ISO, focalLength: x.FocalLength,
          flash: typeof x.Flash === "string" ? x.Flash : undefined,
          orientation: typeof x.Orientation === "string" ? x.Orientation : undefined,
          hostComputer: x.HostComputer,
        }));
        if (typeof x.latitude === "number" && typeof x.longitude === "number")
          technical.gps = { latitude: +x.latitude.toFixed(6), longitude: +x.longitude.toFixed(6) };
      }
    } catch (_) { /* no EXIF / unsupported */ }
  } else {
    technical.note = "Install the 'exifr' package to read EXIF data (camera, GPS, dates).";
  }
  return { props, technical };
}

// ---------------------------------------------------------------- consistency checks
const IMAGE_EDITORS = /photoshop|gimp|lightroom|snapseed|pixlr|canva|affinity|paint\.net|picsart|facetune|illustrator/i;
const PDF_EDITORS = /ilovepdf|smallpdf|sejda|pdfescape|pdf24|foxit|acrobat|nitro|pdf-xchange|pdfsam|pdfelement/i;

function buildFindings({ file, type, props, technical, context, now = Date.now() }) {
  const out = [];
  const add = (level, code, message) => out.push({ level, code, message });

  if (type.exts.length && !type.exts.includes(file.ext))
    add("alert", "EXTENSION_MISMATCH", `File is named .${file.ext || "?"} but its contents are ${type.label}. The extension may have been changed to disguise the file type.`);

  const hasAny = props.author || props.creatorTool || props.producer || props.application || props.created || props.modified;
  const liveCapture = context && ["camera", "voice"].includes(context.source);
  if (!liveCapture && (["pdf", "ooxml"].includes(type.kind) || (type.kind === "image" && exifr))) if (!hasAny)
    add("info", "NO_METADATA", "No author, software or date metadata found. It may never have been present, or it may have been stripped (some apps and messaging services remove it).");

  const c = props.created && Date.parse(props.created), m = props.modified && Date.parse(props.modified);
  if (c && m) {
    if (m < c - 60000) add("alert", "MODIFIED_BEFORE_CREATED", "The modification date is earlier than the creation date, which is inconsistent.");
    else if (m - c > 60000) add("info", "EDITED_AFTER_CREATION", `Last modified ${humanDelta(m - c)} after it was created.`);
  }
  for (const [label, t] of [["creation", c], ["modification", m]])
    if (t && t > now + 86400000) add("alert", "FUTURE_DATE", `The ${label} date is in the future.`);

  const tool = [props.creatorTool, props.producer, props.application].filter(Boolean).join(" / ");
  if (type.kind === "image" && IMAGE_EDITORS.test(tool)) add("warn", "IMAGE_EDITOR", `Image software tag indicates editing software: ${tool}.`);
  if (type.kind === "pdf" && PDF_EDITORS.test(tool)) add("info", "PDF_EDITOR", `Created or processed with a PDF tool: ${tool}.`);

  if (props.author && props.lastModifiedBy && props.author.toLowerCase() !== props.lastModifiedBy.toLowerCase())
    add("info", "DIFFERENT_LAST_EDITOR", `Created by "${props.author}" but last saved by "${props.lastModifiedBy}".`);

  if (technical.incrementalUpdates > 0)
    add("warn", "PDF_INCREMENTAL_UPDATES", `PDF has ${technical.incrementalUpdates} incremental update(s): it was saved again after first being written. Normal for signing or form-filling, but also how edits are appended.`);
  if (technical.xmpModifyDate && props.modified && Math.abs(Date.parse(technical.xmpModifyDate) - Date.parse(props.modified)) > 3600000)
    add("warn", "PDF_DATE_DISAGREEMENT", "The PDF's Info dates and its XMP dates disagree by more than an hour.");
  if (technical.containsJavaScript) add("warn", "PDF_JAVASCRIPT", "PDF contains JavaScript.");
  if (technical.embeddedFiles) add("info", "PDF_EMBEDDED_FILES", "PDF contains embedded file attachments.");
  if (technical.encrypted) add("info", "PDF_ENCRYPTED", "PDF is encrypted; some metadata may be hidden.");

  if (technical.containsMacros) add("alert", "OFFICE_MACROS", "Document contains VBA macros. Do not enable macros unless you trust the source.");
  if (technical.trackedInsertions || technical.trackedDeletions)
    add("info", "TRACKED_CHANGES", `Contains tracked changes (${technical.trackedInsertions || 0} insertions, ${technical.trackedDeletions || 0} deletions).`);
  if (technical.hasComments) add("info", "OFFICE_COMMENTS", "Document contains comments.");

  if (technical.gps) add("warn", "GPS_LOCATION", "Image contains GPS coordinates. Remove location data before sharing if privacy matters.");
  if (type.kind === "image" && technical.cameraModel === undefined && props.creatorTool === undefined && exifr)
    add("info", "NO_CAMERA_INFO", "No camera make/model recorded, which is typical of screenshots, edited or re-exported images.");

  if (type.kind === "media" && !Object.keys(props).length && !Object.keys(technical).length)
    add("info", "MEDIA_LIMITED", "Audio/video detected. Detailed metadata for this container is not parsed yet; file type, size and hashes are shown.");
  if (technical.c2paManifestPresent) add("info", "C2PA_PRESENT", "A Content Credentials (C2PA) manifest is present. Vouch detects it but does not validate its signature or trust chain (use c2patool or enable it with C2PATOOL_PATH). Missing credentials do not mean human-made, and valid ones do not make every claim true.");
  if (technical.encryptedEntries) add("info", "ZIP_ENCRYPTED", `${technical.encryptedEntries} archive entr${technical.encryptedEntries > 1 ? "ies are" : "y is"} password-protected, so contents cannot be inspected.`);
  if (technical.pathTraversalEntries) add("alert", "ZIP_PATH_TRAVERSAL", "Archive contains entries with absolute or parent-directory (../) paths, the 'zip slip' trick for writing files outside the extraction folder.");
  if (technical.executableEntries && technical.executableEntries.length) add("warn", "ZIP_EXECUTABLES", `Archive contains executable or script files: ${technical.executableEntries.slice(0, 4).join(", ")}.`);
  if (technical.compressionRatio > 200 && technical.totalUncompressedBytes > 50 * 1024 * 1024) add("warn", "ZIP_RATIO", `Extremely high compression ratio (${technical.compressionRatio}:1), a possible decompression bomb.`);
  if (technical.archiveComment) add("info", "ZIP_COMMENT", "Archive has a comment (can hold hidden text).");
  if (type.kind === "email") {
    add("info", "EMAIL_CLAIMS", "Email headers are claims made by the sender and mail servers. They are not proof of who sent the message; DKIM/SPF/DMARC are only reported as written in the headers, not validated.");
    if (technical._fromDomain && technical._returnDomain && technical._fromDomain !== technical._returnDomain) add("warn", "EMAIL_DOMAIN_MISMATCH", `From domain (${technical._fromDomain}) differs from Return-Path domain (${technical._returnDomain}).`);
    if (technical._fromDomain && technical._replyDomain && technical._fromDomain !== technical._replyDomain) add("warn", "EMAIL_REPLYTO_MISMATCH", `Replies go to a different domain (${technical._replyDomain}) than the sender (${technical._fromDomain}).`);
    if ((technical.claimedAuthentication || []).some((x) => /=(fail|softfail|none)$/i.test(x))) add("warn", "EMAIL_AUTH_FAIL", `Headers report: ${technical.claimedAuthentication.join(", ")}.`);
  }
  if (type.kind === "executable") {
    add("info", "EXECUTABLE", "Executable file. Vouch only reads header facts and never runs uploaded files.");
    if (technical.compileTimestampClaimed && Date.parse(technical.compileTimestampClaimed) > now + 86400000) add("alert", "FUTURE_DATE", "The claimed compile time is in the future (a linker field, easily forged).");
  }
  if (type.kind === "markup" && (technical.scripts || technical.inlineEventHandlers)) add("warn", "MARKUP_SCRIPT", "Contains script or inline event handlers. Do not open uploaded SVG/HTML directly in a browser session.");
  if (type.kind === "markup" && (technical.foreignObjects || technical.iframes)) add("warn", "MARKUP_EMBEDS", "Contains foreignObject or iframe elements that can embed other content.");
  if (type.kind === "database" && technical.walMode) add("info", "SQLITE_WAL", "Database is in WAL mode: recent changes may live in a separate -wal file that was not uploaded.");
  if (context && context.source === "camera") add("info", "LIVE_CAMERA", "Captured live with the browser camera, so it carries no camera EXIF data.");
  if (context && context.source === "voice") add("info", "LIVE_VOICE", `Recorded live with the browser microphone${context.durationSec ? ` (${context.durationSec}s)` : ""}.`);
  if (context && context.location) add("info", "CAPTURE_LOCATION", "A location was attached by the browser at capture time. It is self-reported and cannot be independently verified.");
  if (context && context.source === "url") add("info", "FETCHED_FROM_URL", `File was downloaded from a link: ${context.sourceUrl}. The server saw the bytes served at that moment.`);
  return out;
}

// ---------------------------------------------------------------- main entry
/** Text worth scanning for invisible characters: plain text files, and the body of Word/Excel documents. */
function textForScan(buf, type, entries) {
  if (type.kind === "text" && buf.length <= 5 * 1024 * 1024) return buf.toString("utf8");
  if (type.kind === "ooxml" && entries) {
    const part = entries["word/document.xml"] || entries["xl/sharedStrings.xml"];
    return part ? readZipText(buf, part, 8 * 1024 * 1024) || "" : "";
  }
  return "";
}

/** Magic-byte type detection, refining ZIP containers into Office documents. */
function detectType(buf) {
  let type = sniffType(buf);
  let entries = null;

  if (type.kind === "zip") {
    entries = readZipEntries(buf);
    const names = entries ? Object.keys(entries) : [];
    if (names.includes("word/document.xml")) type = { kind: "ooxml", mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", exts: ["docx", "docm", "dotx"], label: "Word document (DOCX)" };
    else if (names.includes("xl/workbook.xml")) type = { kind: "ooxml", mime: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", exts: ["xlsx", "xlsm", "xltx"], label: "Excel workbook (XLSX)" };
    else if (names.includes("ppt/presentation.xml")) type = { kind: "ooxml", mime: "application/vnd.openxmlformats-officedocument.presentationml.presentation", exts: ["pptx", "pptm", "potx"], label: "PowerPoint (PPTX)" };
    else type = { ...type, exts: ["zip", "odt", "ods", "odp", "epub", "jar", "apk"] };
  }
  else if (type.kind === "text") type = X.refineText(buf, type);
  return { type, entries };
}

async function analyseFile(buf, filename = "file", opts = {}) {
  const ext = path.extname(filename).replace(".", "").toLowerCase();
  const { type, entries } = detectType(buf);

  let parsed = { props: {}, technical: {} };
  try {
    if (type.kind === "pdf") parsed = await analysePdf(buf);
    else if (type.kind === "ooxml") parsed = analyseOoxml(buf, entries);
    else if (type.kind === "image") parsed = await analyseImage(buf, type);
    else if (type.kind === "media") parsed = X.analyseMedia(buf, type);
    else if (type.kind === "zip") parsed = X.analyseZip(buf, entries || {}, readZipComment(buf));
    else if (type.kind === "email") parsed = X.analyseEml(buf);
    else if (type.kind === "database") parsed = X.analyseSqlite(buf);
    else if (type.kind === "executable") parsed = X.analyseExecutable(buf);
    else if (type.kind === "font") parsed = X.analyseFont(buf);
    else if (type.kind === "markup") parsed = X.analyseMarkup(buf, type);
    if (["image", "pdf", "media"].includes(type.kind) && X.detectC2pa(buf)) parsed.technical.c2paManifestPresent = true;
  } catch (e) {
    parsed.technical.parseError = "Metadata could not be fully read: " + e.message;
  }

  const file = clean({
    name: filename, extension: ext || undefined, sizeBytes: buf.length,
    clientLastModified: opts.clientLastModified ? new Date(opts.clientLastModified).toISOString() : undefined,
  });
  file.ext = ext;
  const findings = buildFindings({ file, type, props: parsed.props, technical: parsed.technical, context: opts.context });

  const extended = await runExternal(buf, { c2paPresent: !!parsed.technical.c2paManifestPresent }).catch(() => undefined);
  for (const k of Object.keys(parsed.technical)) if (k.startsWith("_")) delete parsed.technical[k];

  // Hidden-content checks (steganography and structural anomalies). Never throws into the main report.
  let hidden;
  try {
    hidden = analyseHidden(buf, type, textForScan(buf, type, entries));
    delete hidden._cands;
    for (const c of hidden.checks)
      if (c.level !== "info") findings.push({ level: c.level, code: "HIDDEN_" + c.id, message: `${c.title}. ${c.detail}` });
  } catch (e) {
    hidden = { summary: { level: "unknown", text: "Hidden-content checks could not run: " + e.message }, checks: [], candidates: [], coverage: {} };
  }
  delete file.ext;

  return {
    file: { ...file, detectedType: type.label, mimeType: type.mime, extensionMatches: !type.exts.length || type.exts.includes(ext) },
    hashes: {
      sha256: crypto.createHash("sha256").update(buf).digest("hex"),
      sha1: crypto.createHash("sha1").update(buf).digest("hex"),
      md5: crypto.createHash("md5").update(buf).digest("hex"),
    },
    capture: opts.context,
    properties: parsed.props,
    technical: parsed.technical,
    hidden,
    ...(extended ? { extended } : {}),
    findings,
    riskLevel: findings.some((f) => f.level === "alert") ? "high" : findings.some((f) => f.level === "warn") ? "medium" : "low",
    disclaimer: "Metadata can be edited or removed, so these findings are indicators, not proof of authenticity or tampering. Vouch's blockchain record proves a file is unchanged since registration; metadata analysis helps judge a file before registration.",
  };
}

/** Remove precise GPS coordinates before a snapshot is stored. */
function sanitizeForStorage(report) {
  const copy = JSON.parse(JSON.stringify(report));
  if (copy.hidden && copy.hidden.candidates) // never store decoded secrets in the database snapshot
    copy.hidden.candidates = copy.hidden.candidates.map(({ text, hex, ...rest }) => rest);
  if (copy.technical && copy.technical.gps) { delete copy.technical.gps; copy.technical.gpsPresent = true; }
  return copy;
}

module.exports = { analyseFile, detectType, textForScan, sanitizeForStorage, sniffType, pdfDate, pdfString };
