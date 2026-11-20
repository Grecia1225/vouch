/**
 * Vouch hidden-content analyser (defensive/forensic use).
 *
 * What it does honestly:
 *  - STRUCTURAL: data hidden after a file's end marker, private PNG chunks, unusual JPEG segments,
 *    embedded files, entropy of hidden regions.            -> concrete, extractable evidence
 *  - LSB (PNG, BMP, WAV): chi-square pair test + a decoder for NAIVE sequential LSB embedding.
 *  - TEXT: zero-width characters, Unicode tag characters, homoglyphs, trailing whitespace.
 *
 * What it can NOT do: DCT-domain JPEG methods (JSteg, F5, OutGuess, Steghide), adaptive methods
 * (HUGO, WOW, S-UNIWARD), audio echo/phase/spread-spectrum, or anything password-protected or encrypted.
 * "No evidence found" is therefore never proof that nothing is hidden. Payloads are never executed.
 */
const zlib = require("zlib");
const crypto = require("crypto");

const MAX_PIXELS = 16_000_000;
const MAX_CANDIDATE_BYTES = 5 * 1024 * 1024;

// ---------------------------------------------------------------- basics
const sha256 = (b) => crypto.createHash("sha256").update(b).digest("hex");
function entropy(b) {
  if (!b.length) return 0;
  const h = new Array(256).fill(0);
  for (const x of b) h[x]++;
  let e = 0;
  for (const c of h) if (c) { const p = c / b.length; e -= p * Math.log2(p); }
  return +e.toFixed(3);
}
const isPrintable = (x) => (x >= 0x20 && x <= 0x7e) || x === 10 || x === 13 || x === 9;
const printableRatio = (b) => (b.length ? b.filter(isPrintable).length / b.length : 0);
function preview(b) {
  const head = b.subarray(0, 160);
  if (printableRatio(head) >= 0.85) return { text: head.toString("latin1").replace(/[^\x20-\x7e\n\r\t]/g, ".") };
  return { hex: head.subarray(0, 48).toString("hex").replace(/(..)/g, "$1 ").trim() };
}

// ---------------------------------------------------------------- file signatures (typing and carving)
function identify(buf, off = 0) {
  const at = (s, o = off) => buf.length >= o + s.length && buf.subarray(o, o + s.length).equals(Buffer.from(s, "latin1"));
  if (at("PK\x03\x04")) return { label: "ZIP archive", ext: "zip", family: "archive" };
  if (at("%PDF-")) return { label: "PDF document", ext: "pdf", family: "document" };
  if (at("\x89PNG\r\n\x1a\n")) return { label: "PNG image", ext: "png", family: "image" };
  if (at("GIF87a") || at("GIF89a")) return { label: "GIF image", ext: "gif", family: "image" };
  if (at("\xff\xd8\xff\xe0") || at("\xff\xd8\xff\xe1") || at("\xff\xd8\xff\xdb") || at("\xff\xd8\xff\xee")) return { label: "JPEG image", ext: "jpg", family: "image" };
  if (at("Rar!\x1a\x07")) return { label: "RAR archive", ext: "rar", family: "archive" };
  if (at("7z\xbc\xaf\x27\x1c")) return { label: "7-Zip archive", ext: "7z", family: "archive" };
  if (at("\x1f\x8b\x08")) return { label: "gzip data", ext: "gz", family: "archive" };
  if (at("BZh") && buf[off + 3] >= 0x31 && buf[off + 3] <= 0x39 && at("\x31\x41\x59\x26\x53\x59", off + 4)) return { label: "bzip2 data", ext: "bz2", family: "archive" };
  if (at("\x7fELF")) return { label: "ELF executable", ext: "elf", family: "executable" };
  if (at("SQLite format 3\0")) return { label: "SQLite database", ext: "sqlite", family: "database" };
  if (at("OggS")) return { label: "Ogg media", ext: "ogg", family: "media" };
  if (buf.length >= off + 12 && buf.toString("latin1", off + 4, off + 8) === "ftyp") return { label: "MP4/MOV media", ext: "mp4", family: "media" };
  if (at("MZ") && buf.length >= off + 0x40) {
    const pe = buf.readUInt32LE(off + 0x3c);
    if (pe < 0x1000 && buf.length >= off + pe + 4 && buf.toString("latin1", off + pe, off + pe + 4) === "PE\0\0") return { label: "Windows executable", ext: "exe", family: "executable" };
  }
  return null;
}
const SCAN_PATTERNS = ["PK\x03\x04", "%PDF-", "\x89PNG\r\n\x1a\n", "GIF89a", "GIF87a", "\xff\xd8\xff\xe0", "\xff\xd8\xff\xe1", "\xff\xd8\xff\xdb", "Rar!\x1a\x07", "7z\xbc\xaf\x27\x1c", "\x1f\x8b\x08", "\x7fELF", "SQLite format 3\0", "MZ"];
function scanSignatures(buf, from, to, max = 10) {
  const hits = new Map();
  for (const p of SCAN_PATTERNS) {
    let i = from, guard = 0;
    while ((i = buf.indexOf(Buffer.from(p, "latin1"), i)) !== -1 && i < to && guard++ < 500) {
      if (!hits.has(i)) { const id = identify(buf, i); if (id) hits.set(i, id); }
      i += 1;
    }
  }
  return [...hits.entries()].sort((a, b) => a[0] - b[0]).slice(0, max).map(([offset, id]) => ({ offset, ...id }));
}

// ---------------------------------------------------------------- container structure: where does the real file end?
const PNG_STD = new Set("IHDR PLTE IDAT IEND cHRM gAMA iCCP sBIT sRGB bKGD hIST tRNS pHYs sPLT tIME iTXt tEXt zTXt eXIf acTL fcTL fdAT cICP mDCv cLLi oFFs sCAL pCAL gIFg gIFx gIFt sTER caBX".split(" "));
function walkPng(buf) {
  let pos = 8, end = null;
  const chunks = [];
  while (pos + 8 <= buf.length) {
    const len = buf.readUInt32BE(pos);
    const type = buf.toString("latin1", pos + 4, pos + 8);
    if (pos + 12 + len > buf.length) break;
    chunks.push({ type, offset: pos, length: len });
    pos += 12 + len;
    if (type === "IEND") { end = pos; break; }
  }
  return { end, chunks };
}
const JPEG_KNOWN_APP = [/^JFIF\0/, /^JFXX\0/, /^Exif\0\0/, /^http:\/\/ns\.adobe\.com\//, /^ICC_PROFILE\0/, /^MPF\0/, /^Photoshop 3\.0/, /^Adobe/, /^Ducky/, /^FPXR/, /^Meta\0/, /^Qualcomm/, /^QVCI/, /^HDR_RGB/, /^Apple/, /^Samsung/, /^GoPro/, /^JUMBF|^jumb/];
function walkJpeg(buf) {
  let i = 2, end = null;
  const segments = [];
  while (i + 4 <= buf.length) {
    if (buf[i] !== 0xff) break;
    const m = buf[i + 1];
    if (m === 0xd9) { end = i + 2; break; }
    if (m === 0xd8 || m === 0x01 || (m >= 0xd0 && m <= 0xd7) || m === 0xff) { i += m === 0xff ? 1 : 2; continue; }
    const len = buf.readUInt16BE(i + 2);
    segments.push({ marker: m, offset: i, length: len, id: buf.toString("latin1", i + 4, i + 4 + Math.min(30, Math.max(0, len - 2))) });
    let j = i + 2 + len;
    if (m === 0xda) { // entropy-coded data until the next real marker
      while (j + 1 < buf.length && !(buf[j] === 0xff && buf[j + 1] !== 0x00 && !(buf[j + 1] >= 0xd0 && buf[j + 1] <= 0xd7) && buf[j + 1] !== 0xff)) j++;
    }
    i = j;
  }
  return { end, segments };
}
function gifEnd(buf) {
  try {
    let pos = 13;
    if (buf[10] & 0x80) pos += 3 * (2 << (buf[10] & 7));
    const skipBlocks = () => { while (buf[pos] !== 0) pos += buf[pos] + 1; pos++; };
    while (pos < buf.length) {
      const b = buf[pos];
      if (b === 0x3b) return pos + 1;
      if (b === 0x21) { pos += 2; skipBlocks(); }
      else if (b === 0x2c) { const fl = buf[pos + 9]; pos += 10; if (fl & 0x80) pos += 3 * (2 << (fl & 7)); pos += 1; skipBlocks(); }
      else return null;
    }
  } catch (_) { /* malformed */ }
  return null;
}
function endOfContainer(buf, kind, mime) {
  if (mime === "image/png") return walkPng(buf).end;
  if (mime === "image/jpeg") return walkJpeg(buf).end;
  if (mime === "image/gif") return gifEnd(buf);
  if (mime === "image/bmp" && buf.length > 6) { const s = buf.readUInt32LE(2); return s > 0 && s <= buf.length ? s : null; }
  if (mime === "audio/wav" && buf.length > 12) { const s = 8 + buf.readUInt32LE(4); return s <= buf.length ? s + (s & 1) : null; }
  if (kind === "pdf") { const i = buf.lastIndexOf("%%EOF"); return i >= 0 ? i + 5 : null; }
  if (kind === "zip" || kind === "ooxml") {
    for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) if (buf.readUInt32LE(i) === 0x06054b50) return i + 22 + buf.readUInt16LE(i + 20);
  }
  return null;
}

// ---------------------------------------------------------------- pixel/sample decoders (for LSB analysis)
function decodePng(buf) {
  let pos = 8, ihdr = null;
  const idat = [];
  while (pos + 8 <= buf.length) {
    const len = buf.readUInt32BE(pos), type = buf.toString("latin1", pos + 4, pos + 8);
    const d = buf.subarray(pos + 8, pos + 8 + len);
    if (type === "IHDR") ihdr = { w: d.readUInt32BE(0), h: d.readUInt32BE(4), depth: d[8], ct: d[9], interlace: d[12] };
    else if (type === "IDAT") idat.push(d);
    else if (type === "IEND") break;
    pos += 12 + len;
  }
  if (!ihdr) return { unsupported: "PNG header not found" };
  if (ihdr.depth !== 8 || ihdr.interlace !== 0 || ![0, 2, 6].includes(ihdr.ct))
    return { unsupported: `PNG variant not analysed (bit depth ${ihdr.depth}, colour type ${ihdr.ct}, interlace ${ihdr.interlace}); only 8-bit grey/RGB/RGBA, non-interlaced` };
  if (ihdr.w * ihdr.h > MAX_PIXELS) return { unsupported: "Image too large for LSB analysis" };
  const ch = { 0: 1, 2: 3, 6: 4 }[ihdr.ct], stride = ihdr.w * ch;
  const raw = zlib.inflateSync(Buffer.concat(idat), { maxOutputLength: (stride + 1) * ihdr.h + 16 });
  const out = Buffer.alloc(stride * ihdr.h);
  for (let y = 0; y < ihdr.h; y++) {
    const ft = raw[y * (stride + 1)], line = raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1));
    const cur = y * stride, up = (y - 1) * stride;
    for (let i = 0; i < stride; i++) {
      const a = i >= ch ? out[cur + i - ch] : 0, b = y ? out[up + i] : 0, c = y && i >= ch ? out[up + i - ch] : 0;
      let v = line[i];
      if (ft === 1) v += a; else if (ft === 2) v += b; else if (ft === 3) v += (a + b) >> 1;
      else if (ft === 4) { const p = a + b - c, pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c); v += pa <= pb && pa <= pc ? a : pb <= pc ? b : c; }
      out[cur + i] = v & 255;
    }
  }
  return { samples: out, channels: ch, bins: 256, label: `${ihdr.w}x${ihdr.h} PNG, ${ch} channel(s)` };
}
function decodeBmp(buf) {
  const off = buf.readUInt32LE(10), w = buf.readInt32LE(18), hRaw = buf.readInt32LE(22), bpp = buf.readUInt16LE(28), comp = buf.readUInt32LE(30);
  const h = Math.abs(hRaw);
  if (bpp !== 24 || comp !== 0) return { unsupported: `BMP variant not analysed (${bpp}-bit, compression ${comp}); only uncompressed 24-bit` };
  if (w * h > MAX_PIXELS) return { unsupported: "Image too large for LSB analysis" };
  const row = (w * 3 + 3) & ~3, out = Buffer.alloc(w * h * 3);
  for (let y = 0; y < h; y++) {
    const src = off + (hRaw > 0 ? h - 1 - y : y) * row;
    for (let x = 0; x < w; x++) { out[(y * w + x) * 3] = buf[src + x * 3 + 2]; out[(y * w + x) * 3 + 1] = buf[src + x * 3 + 1]; out[(y * w + x) * 3 + 2] = buf[src + x * 3]; }
  }
  return { samples: out, channels: 3, bins: 256, label: `${w}x${h} BMP` };
}
function decodeWav(buf) {
  let pos = 12, fmt = null, data = null;
  while (pos + 8 <= buf.length) {
    const id = buf.toString("latin1", pos, pos + 4), len = buf.readUInt32LE(pos + 4);
    if (id === "fmt ") fmt = { tag: buf.readUInt16LE(pos + 8), ch: buf.readUInt16LE(pos + 10), bits: buf.readUInt16LE(pos + 22) };
    if (id === "data") { data = buf.subarray(pos + 8, Math.min(buf.length, pos + 8 + len)); break; }
    pos += 8 + len + (len & 1);
  }
  if (!fmt || !data) return { unsupported: "WAV header not understood" };
  if (fmt.tag !== 1 || ![8, 16].includes(fmt.bits)) return { unsupported: `WAV variant not analysed (format ${fmt.tag}, ${fmt.bits}-bit); only 8/16-bit PCM` };
  if (fmt.bits === 8) return { samples: data, channels: fmt.ch, bins: 256, label: `8-bit PCM WAV, ${fmt.ch} channel(s)` };
  const n = data.length >> 1, s = new Int32Array(n);
  for (let i = 0; i < n; i++) s[i] = data.readInt16LE(i * 2) + 32768; // offset is even, so parity (the LSB) is preserved
  return { samples: s, channels: fmt.ch, bins: 65536, label: `16-bit PCM WAV, ${fmt.ch} channel(s)` };
}

// ---------------------------------------------------------------- statistics
function lgamma(x) {
  const c = [76.18009172947146, -86.50532032941677, 24.01409824083091, -1.231739572450155, 0.1208650973866179e-2, -0.5395239384953e-5];
  let y = x, t = x + 5.5; t -= (x + 0.5) * Math.log(t);
  let s = 1.000000000190015;
  for (const k of c) s += k / ++y;
  return -t + Math.log((2.5066282746310005 * s) / x);
}
/** Upper regularised incomplete gamma Q(a, x); chi-square survival function is Q(df/2, chi/2). */
function gammaQ(a, x) {
  if (x <= 0) return 1;
  if (x < a + 1) {
    let sum = 1 / a, del = sum, ap = a;
    for (let n = 0; n < 1000; n++) { ap++; del *= x / ap; sum += del; if (Math.abs(del) < Math.abs(sum) * 1e-13) break; }
    return Math.max(0, 1 - sum * Math.exp(-x + a * Math.log(x) - lgamma(a)));
  }
  let b = x + 1 - a, c = 1e300, d = 1 / b, h = d;
  for (let i = 1; i < 1000; i++) {
    const an = -i * (i - a); b += 2;
    d = an * d + b; if (Math.abs(d) < 1e-300) d = 1e-300;
    c = b + an / c; if (Math.abs(c) < 1e-300) c = 1e-300;
    d = 1 / d; const del = d * c; h *= del;
    if (Math.abs(del - 1) < 1e-13) break;
  }
  return Math.exp(-x + a * Math.log(x) - lgamma(a)) * h;
}
/** Westfeld-Pfitzmann pairs-of-values test. p near 0: pairs are unequal (normal for most cover media).
 *  p not near 0: pair counts are consistent with equalisation, as LSB embedding causes.
 *  shift=1 tests the neighbouring pairs (2i+1, 2i+2) as a control: embedding equalises the aligned pairs only,
 *  so if BOTH are equal the histogram is simply smooth and the test cannot tell (typical of audio and synthetic images). */
function chiPairs(hist, shift = 0) {
  let chi = 0, used = 0;
  for (let i = shift; i + 1 < hist.length; i += 2) {
    const e = (hist[i] + hist[i + 1]) / 2;
    if (e < 5) continue;
    chi += (hist[i] - e) ** 2 / e; used++;
  }
  return used < 8 ? null : { chi: +chi.toFixed(2), df: used - 1, p: gammaQ((used - 1) / 2, chi / 2) };
}
function chiWindows(samples, bins) {
  const marks = [0.1, 0.25, 0.5, 1].map((f) => ({ f, n: Math.max(1, Math.floor(samples.length * f)) }));
  const hist = new Uint32Array(bins), out = [];
  let k = 0;
  for (let i = 0; i < samples.length && k < marks.length; i++) {
    hist[samples[i]]++;
    if (i + 1 === marks[k].n) {
      const r = chiPairs(hist), c = chiPairs(hist, 1);
      out.push({ fraction: marks[k].f, samples: marks[k].n, ...(r || { p: null }), pControl: c ? c.p : null });
      k++;
    }
  }
  return out;
}

// ---------------------------------------------------------------- naive LSB decoder
function lsbStream(samples, step, offset, order, maxBytes) {
  const out = Buffer.alloc(maxBytes);
  let acc = 0, n = 0, o = 0;
  for (let i = offset; i < samples.length && o < maxBytes; i += step) {
    const bit = samples[i] & 1;
    if (order === "msb") acc = (acc << 1) | bit; else acc |= bit << n;
    if (++n === 8) { out[o++] = acc & 255; acc = 0; n = 0; }
  }
  return out.subarray(0, o);
}
function payloadIn(bytes) {
  const sig = identify(bytes, 0);
  if (sig) return { kind: "file", sig, data: bytes };
  // length-prefixed text (32-bit big or little endian)
  for (const le of [false, true]) {
    const L = le ? bytes.readUInt32LE(0) : bytes.readUInt32BE(0);
    if (L >= 4 && L <= bytes.length - 4 && printableRatio(bytes.subarray(4, 4 + Math.min(L, 64))) >= 0.95) return { kind: "text", data: bytes.subarray(4, 4 + L), how: "length-prefixed" };
  }
  // a long printable run near the start
  let best = null;
  for (let i = 0; i < Math.min(bytes.length, 1024); i++) {
    if (!isPrintable(bytes[i])) continue;
    let j = i; while (j < bytes.length && isPrintable(bytes[j])) j++;
    if (!best || j - i > best.len) best = { start: i, len: j - i };
    i = j;
  }
  if (best && ((best.start < 64 && best.len >= 12) || best.len >= 40)) return { kind: "text", data: bytes.subarray(best.start, best.start + Math.min(best.len, 65536)), how: `printable run at byte ${best.start}` };
  return null;
}
function lsbCandidates(media) {
  const out = [];
  const { samples, channels } = media;
  const variants = [{ name: `all ${channels} channel(s) interleaved`, step: 1, off: 0 }];
  if (channels > 1) for (let k = 0; k < Math.min(channels, 3); k++) variants.push({ name: `channel ${"RGB"[k] || k + 1} only`, step: channels, off: k });
  for (const v of variants) for (const order of ["msb", "lsb"]) {
    const bytes = lsbStream(samples, v.step, v.off, order, 4096);
    if (bytes.length < 16) continue;
    const found = payloadIn(bytes);
    if (found) out.push({ id: `lsb:${v.step}:${v.off}:${order}`, label: `LSB payload (${v.name}, ${order.toUpperCase()}-first bits)`, ...found });
  }
  return out;
}

// ---------------------------------------------------------------- text checks
const ZW = new Set(["\u200b", "\u200c", "\u200d", "\u2060", "\u180e", "\ufeff"]);
function decodeBits(bits) {
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8).join(""), 2));
  return Buffer.from(bytes);
}
function scanText(text) {
  const checks = [], candidates = [];
  const cps = Array.from(text);
  // zero-width characters (a leading BOM is normal)
  const zw = cps.filter((c, i) => ZW.has(c) && !(i === 0 && c === "\ufeff"));
  if (zw.length) {
    const freq = {};
    for (const c of zw) freq[c] = (freq[c] || 0) + 1;
    const syms = Object.keys(freq).sort((a, b) => freq[b] - freq[a]);
    let decoded = null;
    if (syms.length >= 2 && zw.length >= 16) {
      for (const [a, b] of [[syms[0], syms[1]], [syms[1], syms[0]]]) {
        const bits = zw.filter((c) => c === a || c === b).map((c) => (c === b ? "1" : "0"));
        const buf = decodeBits(bits);
        if (buf.length >= 2 && printableRatio(buf) >= 0.9) { decoded = buf; break; }
      }
    }
    checks.push({ id: "ZERO_WIDTH", level: "warn", title: `${zw.length} zero-width character(s) found`, detail: decoded ? "They decode to readable text (binary encoding)." : "Invisible characters can carry hidden bits, but they also appear in normal multilingual text. Not decodable with the common binary schemes." });
    if (decoded) candidates.push({ id: "text:zero-width", label: "Text hidden in zero-width characters", kind: "text", data: decoded, how: "binary zero-width" });
  }
  // Unicode tag characters U+E0000..E007F ("ASCII smuggling")
  const tags = cps.filter((c) => { const cp = c.codePointAt(0); return cp >= 0xe0000 && cp <= 0xe007f; });
  if (tags.length) {
    const decoded = Buffer.from(tags.map((c) => c.codePointAt(0) - 0xe0000).filter((x) => x >= 0x20 && x < 0x7f));
    checks.push({ id: "TAG_CHARS", level: "alert", title: `${tags.length} invisible Unicode tag character(s)`, detail: "Tag characters render as nothing but can carry readable ASCII (also used to smuggle instructions to AI systems)." });
    if (decoded.length) candidates.push({ id: "text:tags", label: "Text hidden in Unicode tag characters", kind: "text", data: decoded, how: "tag characters" });
  }
  const mixed = text.match(/\S*\p{Script=Latin}\S*/gu)?.filter((w) => /[\p{Script=Cyrillic}\p{Script=Greek}]/u.test(w)) || [];
  if (mixed.length) checks.push({ id: "HOMOGLYPH", level: "warn", title: `${mixed.length} word(s) mix Latin with Cyrillic/Greek letters`, detail: `Look-alike letters can disguise text or encode data. Example: ${mixed[0].slice(0, 30)}` });
  const lines = text.split(/\r?\n/);
  const trailing = lines.filter((l) => /[ \t]+$/.test(l));
  if (lines.length >= 5 && trailing.length >= 3 && trailing.some((l) => /\t/.test(l.match(/[ \t]+$/)[0])) && trailing.some((l) => / /.test(l.match(/[ \t]+$/)[0])))
    checks.push({ id: "WS_TRAILING", level: "info", title: `Mixed spaces/tabs at the end of ${trailing.length} of ${lines.length} lines`, detail: "Can be formatting, or whitespace steganography such as SNOW. Not decoded." });
  return { checks, candidates };
}

// ---------------------------------------------------------------- main
function descriptor(c, bytes, extra = {}) {
  return { id: c.id, label: c.label, sizeBytes: bytes.length, sha256: sha256(bytes), entropy: entropy(bytes), ...preview(bytes), ...extra };
}

/** Returns the public report plus (internally) the candidate bytes for extraction. */
function run(buf, type) {
  const checks = [], cands = [];
  const coverage = { structural: false, lsb: "not applicable", text: "not applicable" };
  const add = (id, level, title, detail) => checks.push({ id, level, title, detail });
  const addCand = (c) => cands.push(c);

  // 1. Data after the end of the container
  const end = endOfContainer(buf, type.kind, type.mime);
  if (end !== null) {
    coverage.structural = true;
    let tail = buf.subarray(end);
    let t = 0; while (t < tail.length && [0, 9, 10, 13, 32].includes(tail[t])) t++;
    tail = tail.subarray(t);
    if (tail.length > 0) {
      const sig = identify(tail, 0);
      const e = entropy(tail.subarray(0, 65536));
      const risky = sig && ["archive", "executable"].includes(sig.family);
      const legit = type.mime === "image/jpeg" ? " (Can be legitimate: motion photos and multi-picture JPEGs append data.)" : "";
      add("TRAILING_DATA", risky || (!sig && e > 7.5) ? "alert" : "warn",
        `${tail.length} byte(s) after the end of the ${type.label}`,
        `${sig ? `Starts like a ${sig.label}. ` : ""}Entropy ${e}/8${e > 7.5 ? " (looks encrypted or compressed)" : ""}. Viewers ignore this region, which makes it a common hiding place.${legit}`);
      addCand({ id: "trailing", label: "Data after end of file", data: tail.subarray(0, MAX_CANDIDATE_BYTES), kind: sig ? "file" : "data", sig });
      for (const h of scanSignatures(tail, 1, tail.length, 5))
        add("EMBEDDED_FILE", "alert", `Embedded ${h.label} inside the trailing data`, `At byte ${end + t + h.offset} of the file.`);
    }
  }
  // 2. Format-specific structure
  if (type.mime === "image/png") {
    const { chunks } = walkPng(buf);
    const odd = chunks.filter((c) => !PNG_STD.has(c.type));
    for (const c of odd.slice(0, 5)) {
      const data = buf.subarray(c.offset + 8, c.offset + 8 + c.length);
      add("PNG_PRIVATE_CHUNK", c.length > 64 ? "warn" : "info", `Non-standard PNG chunk "${c.type}" (${c.length} bytes)`, "Private chunks are ignored by viewers and can carry arbitrary data.");
      addCand({ id: `chunk:${c.type}@${c.offset}`, label: `PNG chunk ${c.type}`, data, kind: "data" });
    }
    for (const c of chunks.filter((c) => ["tEXt", "zTXt", "iTXt"].includes(c.type) && c.length > 1024).slice(0, 3))
      add("PNG_LARGE_TEXT", "warn", `Large ${c.type} chunk (${c.length} bytes)`, "Text chunks are normally short. Large ones can hold hidden data.");
  }
  if (type.mime === "image/jpeg") {
    const { segments } = walkJpeg(buf);
    for (const s of segments) {
      if (s.marker === 0xfe && s.length > 258) {
        add("JPEG_LARGE_COMMENT", "warn", `Large JPEG comment segment (${s.length - 2} bytes)`, "Comments are normally short.");
        addCand({ id: `jpegseg:${s.offset}`, label: "JPEG comment segment", data: buf.subarray(s.offset + 4, s.offset + 2 + s.length), kind: "data" });
      } else if (s.marker >= 0xe0 && s.marker <= 0xef && s.length > 1026 && !JPEG_KNOWN_APP.some((re) => re.test(s.id))) {
        add("JPEG_UNKNOWN_APP", "warn", `Unrecognised JPEG APP${s.marker - 0xe0} segment (${s.length - 2} bytes)`, `Identifier "${s.id.replace(/[^\x20-\x7e]/g, ".").slice(0, 20)}".`);
        addCand({ id: `jpegseg:${s.offset}`, label: `JPEG APP${s.marker - 0xe0} segment`, data: buf.subarray(s.offset + 4, s.offset + 2 + s.length), kind: "data" });
      }
    }
  }
  // 3. LSB analysis (PNG, BMP, WAV)
  let media = null;
  try {
    if (type.mime === "image/png") media = decodePng(buf);
    else if (type.mime === "image/bmp") media = decodeBmp(buf);
    else if (type.mime === "audio/wav") media = decodeWav(buf);
  } catch (e) { media = { unsupported: "Could not decode samples: " + e.message }; }
  if (media && media.unsupported) coverage.lsb = "unsupported: " + media.unsupported;
  else if (media) {
    coverage.lsb = `analysed (${media.label})`;
    const payloads = lsbCandidates(media);
    for (const p of payloads) {
      add("LSB_PAYLOAD", "alert", `${p.label}: readable ${p.kind === "file" ? p.sig.label : "text"} decoded`, `Simple sequential LSB embedding decodes to a hidden payload (${p.how || p.sig.label}).`);
      addCand({ id: p.id, label: p.label, data: p.data, kind: p.kind, sig: p.sig });
    }
    const w = chiWindows(media.samples, media.bins);
    const first = w[0] || {}, last = w[w.length - 1] || {};
    coverage.chiSquare = w.map((x) => ({ fraction: x.fraction, chi: x.chi, df: x.df, p: x.p == null ? null : +x.p.toPrecision(3), pControl: x.pControl == null ? null : +x.pControl.toPrecision(3) }));
    if (!payloads.length && last.p != null && last.pControl != null) {
      const informative = (x) => x.pControl != null && x.pControl < 0.001; // neighbouring pairs unequal: histogram is not just smooth
      if (first.p >= 0.05 && informative(first) && last.p < 0.001)
        add("LSB_CHI_PARTIAL", "warn", "Statistical sign of LSB embedding in the first part of the data", "Pairs of values are equalised at the start and unequal later, the pattern left by a payload that does not fill the whole file. Statistical evidence only, no payload decoded.");
      else if (last.p >= 0.05 && informative(last))
        add("LSB_CHI_FULL", "warn", "Pairs-of-values test consistent with full-capacity LSB embedding", "Aligned value pairs are equalised while neighbouring pairs are not, as LSB embedding does. Can also come from heavy processing. Statistical evidence only, no payload decoded.");
      else if (last.p >= 0.05)
        add("LSB_CHI_INCONCLUSIVE", "info", "Pairs-of-values test is inconclusive", "The value histogram is smooth (typical of audio and synthetic images), so this statistic cannot separate embedded from natural data.");
    }
  }
  return { checks, cands, coverage, end };
}

function analyseHidden(buf, type, textForScan) {
  const r = run(buf, type);
  if (typeof textForScan === "string" && textForScan.length) {
    r.coverage.text = "analysed";
    const t = scanText(textForScan);
    r.checks.push(...t.checks);
    r.cands.push(...t.candidates);
  }
  const concrete = r.cands.length > 0 || r.checks.some((c) => c.level === "alert");
  const possible = r.checks.some((c) => c.level === "warn");
  const summary = concrete
    ? { level: "likely", text: "Anomaly detected: concrete hidden or unusual data was found (see checks and extractable items)." }
    : possible
      ? { level: "possible", text: "Possible anomaly: statistical or structural signs worth a closer look. No payload was decoded." }
      : { level: "none-found", text: "No evidence of hidden content found by these checks. This is not proof that nothing is hidden." };
  return {
    summary, checks: r.checks, coverage: r.coverage,
    candidates: r.cands.map((c) => descriptor(c, c.data, c.sig ? { detectedType: c.sig.label } : {})),
    limitations: "Not covered: DCT-domain JPEG methods (JSteg, F5, OutGuess, Steghide), adaptive methods (HUGO, WOW, S-UNIWARD), audio echo/phase/spread-spectrum, password-protected or encrypted payloads. Detection is not decoding, and extracted data must never be opened or executed.",
    _cands: r.cands,
  };
}

/** Re-runs the analysis and returns the bytes of one candidate for a logged-in analyst to download. */
function extractCandidate(buf, type, id, textForScan) {
  const r = analyseHidden(buf, type, textForScan);
  const c = r._cands.find((x) => x.id === id);
  if (!c) return null;
  const ext = c.sig ? c.sig.ext : c.kind === "text" ? "txt" : "bin";
  return { buffer: Buffer.from(c.data), filename: `extracted-${id.replace(/[^a-z0-9]+/gi, "-").slice(0, 40)}.${c.kind === "file" && c.sig ? c.sig.ext : ext}.dat` };
}

module.exports = { analyseHidden, extractCandidate, scanText, chiPairs, gammaQ, identify, entropy, decodePng, endOfContainer };
