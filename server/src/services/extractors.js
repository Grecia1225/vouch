/**
 * Metadata extractors for more file families. Pure JavaScript, bounds-checked, never executes anything.
 * Each returns { props, technical } in the same shape as the PDF/Office/image extractors.
 */
const clean = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && v !== null && v !== "" && !(Array.isArray(v) && !v.length)));
const iso = (v) => { const d = v instanceof Date ? v : new Date(v); return isNaN(d) ? undefined : d.toISOString(); };
const latin = (b) => b.toString("latin1").replace(/\0+$/, "").trim();
const utf8 = (b) => b.toString("utf8").replace(/\0+$/, "").trim();

// ================================================================ AUDIO / VIDEO
function decodeId3Text(b) {
  if (!b.length) return "";
  const enc = b[0], body = b.subarray(1);
  if (enc === 1) { // UTF-16 with BOM
    if (body[0] === 0xff && body[1] === 0xfe) return body.subarray(2).toString("utf16le").replace(/\0+$/, "");
    if (body[0] === 0xfe && body[1] === 0xff) { const c = Buffer.from(body.subarray(2, 2 + (body.length - 2 & ~1))); return c.swap16().toString("utf16le").replace(/\0+$/, ""); }
    return body.toString("utf16le").replace(/\0+$/, "");
  }
  if (enc === 2) { const c = Buffer.from(body.subarray(0, body.length & ~1)); return c.swap16().toString("utf16le").replace(/\0+$/, ""); }
  return enc === 3 ? utf8(body) : latin(body);
}
function parseId3(buf) {
  const out = {}, tech = {};
  if (buf.length >= 10 && buf.toString("latin1", 0, 3) === "ID3") {
    const major = buf[3], size = ((buf[6] & 0x7f) << 21) | ((buf[7] & 0x7f) << 14) | ((buf[8] & 0x7f) << 7) | (buf[9] & 0x7f);
    tech.id3Version = `2.${major}`;
    let pos = 10; const end = Math.min(buf.length, 10 + size);
    let pictures = 0, priv = 0;
    while (pos + 10 <= end) {
      const id = buf.toString("latin1", pos, pos + 4);
      if (!/^[A-Z0-9]{4}$/.test(id)) break;
      const fs = major === 4 ? ((buf[pos + 4] & 0x7f) << 21) | ((buf[pos + 5] & 0x7f) << 14) | ((buf[pos + 6] & 0x7f) << 7) | (buf[pos + 7] & 0x7f) : buf.readUInt32BE(pos + 4);
      const data = buf.subarray(pos + 10, pos + 10 + fs);
      if (id === "APIC") pictures++;
      else if (id === "PRIV") priv++;
      else if (id === "COMM" && data.length > 4) { const t = decodeId3Text(Buffer.concat([data.subarray(0, 1), data.subarray(4)])); out.comment = t.split("\0").pop().slice(0, 200); }
      else if (id === "TXXX") { const t = decodeId3Text(data).split("\0"); if (t.length > 1 && t[0]) (out.custom = out.custom || {})[t[0].slice(0, 40)] = t[1].slice(0, 120); }
      else if (id[0] === "T") out[id] = decodeId3Text(data);
      pos += 10 + fs;
    }
    tech.embeddedPictures = pictures || undefined; tech.privateFrames = priv || undefined; tech.tagSizeBytes = size;
  }
  if (buf.length >= 128 && buf.toString("latin1", buf.length - 128, buf.length - 125) === "TAG") {
    const t = buf.subarray(buf.length - 128);
    out.v1 = { title: latin(t.subarray(3, 33)), artist: latin(t.subarray(33, 63)), album: latin(t.subarray(63, 93)), year: latin(t.subarray(93, 97)) };
    tech.id3v1 = true;
  }
  return { out, tech };
}
function parseVorbisComments(b) {
  try {
    let pos = 0;
    const vlen = b.readUInt32LE(pos); pos += 4 + vlen;
    const n = b.readUInt32LE(pos); pos += 4;
    const vendor = b.toString("utf8", 4, 4 + vlen), tags = {};
    for (let i = 0; i < n && i < 200 && pos + 4 <= b.length; i++) {
      const l = b.readUInt32LE(pos); pos += 4;
      const kv = b.toString("utf8", pos, pos + Math.min(l, 400)); pos += l;
      const eq = kv.indexOf("=");
      if (eq > 0) tags[kv.slice(0, eq).toUpperCase()] = kv.slice(eq + 1).slice(0, 300);
    }
    return { vendor, tags };
  } catch { return { vendor: "", tags: {} }; }
}
const tagProps = (t) => clean({ title: t.TITLE, author: t.ARTIST || t.ALBUMARTIST, album: t.ALBUM, subject: t.GENRE, created: undefined, copyright: t.COPYRIGHT || t.ORGANIZATION, comment: t.COMMENT, dateTag: t.DATE, encoderTag: t.ENCODER });

function parseMp4(buf) {
  const MAC_EPOCH = Date.UTC(1904, 0, 1);
  const res = { props: {}, tech: {}, tracks: 0 };
  const items = {};
  let keys = [];
  function walk(start, end, depth, path) {
    let pos = start;
    while (pos + 8 <= end && depth < 7) {
      let size = buf.readUInt32BE(pos), hdr = 8;
      const type = buf.toString("latin1", pos + 4, pos + 8);
      if (size === 1) { size = Number(buf.readBigUInt64BE(pos + 8)); hdr = 16; } else if (size === 0) size = end - pos;
      if (size < hdr || pos + size > end) break;
      const body = pos + hdr, bend = pos + size;
      if (type === "ftyp") res.tech.brand = buf.toString("latin1", body, body + 4);
      else if (type === "mvhd") {
        const v = buf[body], t = v === 1 ? 8 : 4;
        const c = v === 1 ? Number(buf.readBigUInt64BE(body + 4)) : buf.readUInt32BE(body + 4);
        const m = v === 1 ? Number(buf.readBigUInt64BE(body + 12)) : buf.readUInt32BE(body + 8);
        const ts = buf.readUInt32BE(body + 4 + 2 * t), dur = v === 1 ? Number(buf.readBigUInt64BE(body + 8 + 2 * t)) : buf.readUInt32BE(body + 8 + 2 * t);
        if (c) res.props.created = iso(MAC_EPOCH + c * 1000);
        if (m) res.props.modified = iso(MAC_EPOCH + m * 1000);
        if (ts) res.tech.durationSeconds = +(dur / ts).toFixed(2);
      } else if (type === "trak") res.tracks++;
      else if (type === "keys") { // QuickTime metadata keys
        const n = buf.readUInt32BE(body + 4); let p = body + 8; keys = [];
        for (let i = 0; i < n && p + 8 <= bend; i++) { const ks = buf.readUInt32BE(p); keys.push(buf.toString("utf8", p + 8, p + ks)); p += ks; }
      } else if (path.endsWith("ilst")) { // metadata item: value lives in a 'data' child
        const d = body + 0; let p = d;
        while (p + 16 <= bend) {
          const ds = buf.readUInt32BE(p), dt = buf.toString("latin1", p + 4, p + 8);
          if (dt === "data" && ds >= 16) {
            const kind = buf.readUInt32BE(p + 8) & 0xffffff, val = buf.subarray(p + 16, p + ds);
            const name = /^\d+$/.test(Buffer.from(type, "latin1").readUInt32BE(0).toString()) && keys.length && Buffer.from(type, "latin1").readUInt32BE(0) <= keys.length && Buffer.from(type, "latin1").readUInt32BE(0) > 0
              ? keys[Buffer.from(type, "latin1").readUInt32BE(0) - 1] : type;
            if (type === "covr") items.cover = (items.cover || 0) + 1;
            else items[name] = kind === 1 || kind === 0 ? utf8(val).slice(0, 300) : undefined;
            break;
          }
          p += Math.max(8, ds);
        }
      } else if (type.charCodeAt(0) === 0xa9 && path.endsWith("udta")) { // QuickTime text atoms (title, author, GPS...): int16 length, int16 language, text
        items[type] = buf.toString("utf8", body + 4, bend).replace(/\0+$/, "").trim().slice(0, 300);
      } else if (["moov", "udta", "trak", "mdia", "minf", "stbl", "edts", "dinf"].includes(type)) walk(body, bend, depth + 1, path + "/" + type);
      else if (type === "meta") walk(body + (buf.readUInt32BE(body) === 0 && buf.toString("latin1", body + 4, body + 8) !== "hdlr" ? 4 : (buf.toString("latin1", body + 4, body + 8) === "hdlr" ? 0 : 4)), bend, depth + 1, path + "/meta");
      else if (type === "ilst") walk(body, bend, depth + 1, path + "/ilst");
      pos += size;
    }
  }
  walk(0, Math.min(buf.length, 64 * 1024 * 1024), 0, "");
  return { res, items };
}
function parseIso6709(s) {
  const m = /^([+-]\d+(?:\.\d+)?)([+-]\d+(?:\.\d+)?)/.exec(s || "");
  return m ? { latitude: +(+m[1]).toFixed(6), longitude: +(+m[2]).toFixed(6) } : undefined;
}
function analyseMedia(buf, type) {
  const props = {}, tech = {};
  if (type.mime === "audio/mpeg") {
    const { out, tech: t } = parseId3(buf);
    Object.assign(tech, t);
    Object.assign(props, clean({ title: out.TIT2 || (out.v1 && out.v1.title), author: out.TPE1 || (out.v1 && out.v1.artist), creatorTool: out.TSSE || out.TENC, copyright: out.TCOP }));
    Object.assign(tech, clean({ album: out.TALB || (out.v1 && out.v1.album), year: out.TDRC || out.TYER || (out.v1 && out.v1.year), encodedBy: out.TENC, comment: out.comment, customTags: out.custom && JSON.stringify(out.custom) }));
  } else if (type.mime === "audio/flac" || (type.mime === "audio/ogg")) {
    let block = null;
    if (type.mime === "audio/flac") {
      let pos = 4;
      while (pos + 4 <= buf.length) {
        const h = buf[pos], t = h & 0x7f, len = buf.readUIntBE(pos + 1, 3);
        if (t === 0 && len >= 34) {
          const v = buf.readBigUInt64BE(pos + 14), sr = Number(v >> 44n), total = Number(v & 0xfffffffffn);
          tech.sampleRateHz = sr; tech.channels = Number((v >> 41n) & 7n) + 1; tech.bitsPerSample = Number((v >> 36n) & 31n) + 1;
          if (sr && total) tech.durationSeconds = +(total / sr).toFixed(2);
        }
        else if (t === 4) block = buf.subarray(pos + 4, pos + 4 + len);
        else if (t === 6) tech.embeddedPictures = (tech.embeddedPictures || 0) + 1;
        if (h & 0x80) break;
        pos += 4 + len;
      }
    } else {
      const head = buf.subarray(0, Math.min(buf.length, 256 * 1024));
      const i = head.indexOf(Buffer.from("\x03vorbis", "latin1")), j = head.indexOf(Buffer.from("OpusTags", "latin1"));
      if (i >= 0) block = head.subarray(i + 7); else if (j >= 0) block = head.subarray(j + 8);
    }
    if (block) {
      const { vendor, tags } = parseVorbisComments(block);
      Object.assign(props, clean({ title: tags.TITLE, author: tags.ARTIST, creatorTool: tags.ENCODER || vendor, copyright: tags.COPYRIGHT }));
      Object.assign(tech, clean({ album: tags.ALBUM, year: tags.DATE, comment: tags.COMMENT, vendor }));
    }
  } else if (type.mime === "audio/wav") {
    let pos = 12;
    while (pos + 8 <= buf.length) {
      const id = buf.toString("latin1", pos, pos + 4), len = buf.readUInt32LE(pos + 4), b = buf.subarray(pos + 8, pos + 8 + len);
      if (id === "fmt " && len >= 16) { const br = b.readUInt32LE(8); tech.sampleRateHz = b.readUInt32LE(4); tech.channels = b.readUInt16LE(2); tech.bitsPerSample = b.readUInt16LE(14); tech._byteRate = br; }
      else if (id === "data") tech._dataLen = len;
      else if (id === "LIST" && b.toString("latin1", 0, 4) === "INFO") {
        let p = 4;
        while (p + 8 <= b.length) { const k = b.toString("latin1", p, p + 4), l = b.readUInt32LE(p + 4), v = latin(b.subarray(p + 8, p + 8 + l)); p += 8 + l + (l & 1);
          if (k === "INAM") props.title = v; else if (k === "IART") props.author = v; else if (k === "ISFT") props.creatorTool = v; else if (k === "ICOP") props.copyright = v; else if (k === "ICMT") tech.comment = v; else if (k === "ICRD") tech.dateTag = v; else if (k === "IPRD") tech.album = v; }
      } else if (id === "bext") { tech.broadcastOriginator = latin(b.subarray(256, 288)) || undefined; tech.broadcastDate = latin(b.subarray(320, 330)) || undefined; tech.broadcastDescription = latin(b.subarray(0, 256)).slice(0, 120) || undefined; }
      pos += 8 + len + (len & 1);
    }
    if (tech._byteRate && tech._dataLen) tech.durationSeconds = +(tech._dataLen / tech._byteRate).toFixed(2);
    delete tech._byteRate; delete tech._dataLen;
  } else if (type.mime === "video/mp4" || type.mime === "audio/mp4") {
    const { res, items } = parseMp4(buf);
    Object.assign(props, res.props);
    const loc = parseIso6709(items["\u00a9xyz"] || items["com.apple.quicktime.location.ISO6709"]);
    Object.assign(props, clean({ title: items["\u00a9nam"] || items["com.apple.quicktime.title"], author: items["\u00a9ART"] || items["\u00a9aut"] || items["com.apple.quicktime.author"], creatorTool: items["\u00a9too"] || items["com.apple.quicktime.software"], copyright: items["cprt"] }));
    if (!props.created && items["com.apple.quicktime.creationdate"]) props.created = iso(items["com.apple.quicktime.creationdate"]);
    Object.assign(tech, res.tech, clean({
      tracks: res.tracks, album: items["\u00a9alb"], dateTag: items["\u00a9day"], comment: items["\u00a9cmt"], genre: items["\u00a9gen"],
      deviceMake: items["com.apple.quicktime.make"], deviceModel: items["com.apple.quicktime.model"], embeddedPictures: items.cover, gps: loc,
    }));
  }
  return { props: clean(props), technical: clean(tech) };
}

// ================================================================ ARCHIVES (ZIP, non-Office)
const EXEC_EXT = /\.(exe|dll|scr|bat|cmd|ps1|vbs|js|jse|wsf|jar|lnk|msi|com|apk|sh)$/i;
const dosDate = (d, t) => d ? iso(Date.UTC(((d >> 9) & 127) + 1980, ((d >> 5) & 15) - 1, d & 31, (t >> 11) & 31, (t >> 5) & 63, (t & 31) * 2)) : undefined;
function analyseZip(buf, entries, eocdComment) {
  const names = Object.keys(entries);
  let total = 0, enc = 0, exec = [], trav = 0, nested = 0, earliest, latest;
  for (const n of names) {
    const e = entries[n];
    total += e.usize; if (e.flags & 1) enc++;
    if (EXEC_EXT.test(n)) exec.push(n);
    if (/(^|\/)\.\.(\/|$)/.test(n) || n.startsWith("/") || /^[a-z]:/i.test(n)) trav++;
    if (/\.(zip|rar|7z|gz|tar|jar)$/i.test(n)) nested++;
    const t = dosDate(e.date, e.time);
    if (t) { if (!earliest || t < earliest) earliest = t; if (!latest || t > latest) latest = t; }
  }
  return { props: {}, technical: clean({
    earliestEntryModified: earliest, latestEntryModified: latest, entries: names.length, totalUncompressedBytes: total, compressionRatio: buf.length ? +(total / buf.length).toFixed(1) : undefined,
    encryptedEntries: enc || undefined, executableEntries: exec.slice(0, 10), pathTraversalEntries: trav || undefined, nestedArchives: nested || undefined,
    archiveComment: eocdComment || undefined, sampleNames: names.slice(0, 8),
  }) };
}

// ================================================================ EMAIL (.eml)
function analyseEml(buf) {
  const text = buf.subarray(0, 512 * 1024).toString("utf8");
  const split = text.search(/\r?\n\r?\n/);
  const head = (split >= 0 ? text.slice(0, split) : text).replace(/\r?\n[ \t]+/g, " ");
  const h = {}, received = [];
  for (const line of head.split(/\r?\n/)) {
    const m = /^([A-Za-z0-9-]+):\s*(.*)$/.exec(line);
    if (!m) continue;
    const k = m[1].toLowerCase();
    if (k === "received") received.push(m[2]); else if (!(k in h)) h[k] = m[2];
  }
  const dom = (s) => ((/@([A-Za-z0-9.-]+)/.exec(s || "") || [])[1] || "").toLowerCase();
  const auth = h["authentication-results"] || "";
  const attachments = [...text.matchAll(/filename\*?=(?:UTF-8'')?"?([^";\r\n]+)"?/gi)].map((m) => m[1].trim()).slice(0, 15);
  return { props: clean({ title: h.subject, author: h.from, created: iso(h.date), creatorTool: h["x-mailer"] || h["user-agent"] }), technical: clean({
    messageId: h["message-id"], returnPath: h["return-path"], replyTo: h["reply-to"], toCount: h.to ? h.to.split(",").length : undefined,
    receivedHops: received.length || undefined,
    claimedAuthentication: [/spf=\w+/i, /dkim=\w+/i, /dmarc=\w+/i].map((re) => (auth.match(re) || [])[0]).filter(Boolean),
    attachments, _fromDomain: dom(h.from), _returnDomain: dom(h["return-path"]), _replyDomain: dom(h["reply-to"]),
  }) };
}

// ================================================================ SQLITE
function analyseSqlite(buf) {
  const ps = buf.readUInt16BE(16), v = buf.readUInt32BE(96);
  return { props: {}, technical: clean({
    pageSize: ps === 1 ? 65536 : ps, pages: buf.readUInt32BE(28), textEncoding: { 1: "UTF-8", 2: "UTF-16le", 3: "UTF-16be" }[buf.readUInt32BE(56)],
    userVersion: buf.readUInt32BE(60), applicationId: "0x" + buf.readUInt32BE(68).toString(16), schemaFormat: buf.readUInt32BE(44),
    walMode: buf[18] === 2 || buf[19] === 2, sqliteVersion: `${Math.floor(v / 1e6)}.${Math.floor((v % 1e6) / 1e3)}.${v % 1e3}`,
    note: "Only the 100-byte header was read; no table data is opened.",
  }) };
}

// ================================================================ EXECUTABLES (header facts only)
const ELF_MACHINE = { 3: "x86", 8: "MIPS", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V" };
const PE_MACHINE = { 0x14c: "x86", 0x8664: "x86-64", 0x1c0: "ARM", 0xaa64: "ARM64" };
function analyseExecutable(buf) {
  const t = {};
  if (buf.toString("latin1", 0, 2) === "MZ") {
    const pe = buf.readUInt32LE(0x3c);
    if (buf.toString("latin1", pe, pe + 4) === "PE\0\0") {
      const stamp = buf.readUInt32LE(pe + 8), optSize = buf.readUInt16LE(pe + 20), opt = pe + 24, magic = buf.readUInt16LE(opt);
      const dd = opt + (magic === 0x20b ? 112 : 96);
      t.format = magic === 0x20b ? "PE32+" : "PE32"; t.machine = PE_MACHINE[buf.readUInt16LE(pe + 4)] || "0x" + buf.readUInt16LE(pe + 4).toString(16);
      t.sections = buf.readUInt16LE(pe + 6); t.isDll = !!(buf.readUInt16LE(pe + 22) & 0x2000);
      t.compileTimestampClaimed = stamp ? iso(stamp * 1000) : undefined; // a linker field: easily forged, zero in reproducible builds
      t.signaturePresent = dd + 40 <= buf.length && buf.readUInt32LE(dd + 4 * 8 + 4) > 0; // certificate table (not validated)
      t.dotNet = dd + 120 <= buf.length && buf.readUInt32LE(dd + 14 * 8 + 4) > 0;
    }
  } else if (buf.toString("latin1", 1, 4) === "ELF") {
    const le = buf[5] === 1;
    t.format = "ELF"; t.bits = buf[4] === 2 ? 64 : 32; t.endianness = le ? "little" : "big";
    t.fileType = { 1: "relocatable", 2: "executable", 3: "shared object/PIE", 4: "core dump" }[le ? buf.readUInt16LE(16) : buf.readUInt16BE(16)];
    const m = le ? buf.readUInt16LE(18) : buf.readUInt16BE(18); t.machine = ELF_MACHINE[m] || m;
  } else { const m = buf.readUInt32BE(0); t.format = m === 0xcafebabe ? "Mach-O universal binary or Java class" : "Mach-O"; }
  return { props: {}, technical: clean({ ...t, note: "Header facts only. Vouch never runs uploaded files; signature presence is not signature validation." }) };
}

// ================================================================ FONTS (name table)
function analyseFont(buf) {
  const t = {};
  try {
    let base = 0;
    const tag = buf.toString("latin1", 0, 4);
    if (tag === "wOFF" || tag === "wOF2") return { props: {}, technical: { format: tag === "wOFF" ? "WOFF" : "WOFF2", note: "Compressed web font: name table not read." } };
    const n = buf.readUInt16BE(base + 4);
    for (let i = 0; i < n && i < 64; i++) {
      const r = base + 12 + i * 16;
      if (buf.toString("latin1", r, r + 4) !== "name") continue;
      const off = buf.readUInt32BE(r + 8), cnt = buf.readUInt16BE(off + 2), str = off + buf.readUInt16BE(off + 4);
      const names = { 0: "copyright", 1: "family", 5: "version", 8: "manufacturer", 9: "designer", 13: "licenseDescription", 14: "licenseUrl" };
      for (let k = 0; k < cnt && k < 200; k++) {
        const rec = off + 6 + k * 12, plat = buf.readUInt16BE(rec), id = buf.readUInt16BE(rec + 6), len = buf.readUInt16BE(rec + 8), so = buf.readUInt16BE(rec + 10);
        const field = names[id];
        if (!field || t[field]) continue;
        const raw = buf.subarray(str + so, str + so + len);
        t[field] = (plat === 3 || plat === 0 ? Buffer.from(raw.subarray(0, raw.length & ~1)).swap16().toString("utf16le") : raw.toString("latin1")).slice(0, 200);
      }
    }
  } catch (_) { /* unreadable font tables */ }
  return { props: clean({ author: t.designer || t.manufacturer, copyright: t.copyright, title: t.family }), technical: clean({ fontVersion: t.version, licenseDescription: t.licenseDescription, licenseUrl: t.licenseUrl }) };
}

// ================================================================ SVG / HTML / XML
function analyseMarkup(buf, type) {
  const t = buf.subarray(0, 2 * 1024 * 1024).toString("utf8");
  const meta = (name) => { const m = new RegExp(`<meta[^>]+name=["']${name}["'][^>]*content=["']([^"']*)["']`, "i").exec(t); return m ? m[1] : undefined; };
  const tag = (re) => { const m = re.exec(t); return m ? m[1].trim().slice(0, 200) : undefined; };
  const comments = [...t.matchAll(/<!--([\s\S]*?)-->/g)].map((m) => m[1].trim());
  const gen = tag(/Generator:\s*([^\n\-]+)/i) || meta("generator") || tag(/inkscape:version="([^"]+)"/) || (/sodipodi/.test(t) ? "Inkscape" : undefined);
  return { props: clean({
    title: tag(/<title[^>]*>([^<]*)<\/title>/i) || tag(/<dc:title[^>]*>(?:<[^>]+>)*([^<]+)/i), author: meta("author") || tag(/<dc:creator[^>]*>(?:<[^>]+>)*([^<]+)/i),
    creatorTool: gen, created: iso(meta("date") || tag(/<dc:date>([^<]+)/i)),
  }), technical: clean({
    scripts: (t.match(/<script[\s>]/gi) || []).length || undefined, inlineEventHandlers: (t.match(/\son[a-z]+\s*=/gi) || []).length || undefined,
    externalReferences: (t.match(/(?:href|src)=["']https?:\/\//gi) || []).length || undefined, foreignObjects: (t.match(/<foreignObject/gi) || []).length || undefined,
    iframes: (t.match(/<iframe/gi) || []).length || undefined, comments: comments.length || undefined, longestCommentChars: comments.length ? Math.max(...comments.map((c) => c.length)) : undefined,
    description: meta("description"), keywords: meta("keywords"),
  }) };
}

// ================================================================ C2PA / Content Credentials (detection only)
function detectC2pa(buf) {
  const head = buf.subarray(0, Math.min(buf.length, 4 * 1024 * 1024));
  return head.includes("c2pa") && head.includes("jumb");
}

// ================================================================ text type refinement
function refineText(buf, type) {
  const head = buf.subarray(0, 4096).toString("utf8").replace(/^\ufeff/, "");
  const trimmed = head.trimStart();
  if (/^(<\?xml[\s\S]{0,300}?)?<svg[\s>]/i.test(trimmed)) return { kind: "markup", mime: "image/svg+xml", exts: ["svg"], label: "SVG image (XML)" };
  if (/^<!doctype html|^<html[\s>]/i.test(trimmed)) return { kind: "markup", mime: "text/html", exts: ["html", "htm"], label: "HTML document" };
  if (/^<\?xml/i.test(trimmed)) return { kind: "markup", mime: "application/xml", exts: ["xml", "xsd", "rss", "atom", "gpx", "kml", "svg"], label: "XML document" };
  if (/^(received|return-path|from|message-id|mime-version|delivered-to|x-[a-z-]+|date|subject): /im.test(head.split(/\r?\n\r?\n/)[0] || "") && /^(from|date|subject|message-id|mime-version|received|return-path): /im.test(head))
    return { kind: "email", mime: "message/rfc822", exts: ["eml", "mbox", "txt"], label: "Email message (EML)" };
  return type;
}

module.exports = { analyseMedia, analyseZip, analyseEml, analyseSqlite, analyseExecutable, analyseFont, analyseMarkup, detectC2pa, refineText, parseMp4, parseId3 };
