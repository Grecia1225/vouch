const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { analyseFile } = require("../src/services/metadata");

const fx = (n) => fs.readFileSync(path.join(__dirname, "fixtures", n));
const codes = (r) => r.findings.map((f) => f.code);

test("MP3: ID3v2 title, artist, album, year, encoder", async () => {
  const r = await analyseFile(fx("tagged.mp3"), "tagged.mp3");
  assert.deepStrictEqual([r.properties.title, r.properties.author], ["Vouch Test Tune", "Grecia"]);
  assert.strictEqual(r.technical.album, "Demo Album");
  assert.strictEqual(r.technical.year, "2024");
  assert.strictEqual(r.technical.encodedBy, "UnitTest");
  assert.strictEqual(r.technical.id3Version, "2.3");
});

test("M4A/MP4: creation time, title, artist, album, duration", async () => {
  const r = await analyseFile(fx("tagged.m4a"), "tagged.m4a");
  assert.strictEqual(r.properties.created, "2024-03-05T10:20:30.000Z");
  assert.deepStrictEqual([r.properties.title, r.properties.author, r.technical.album], ["Vouch AAC", "Jeevan", "MP4 Album"]);
  assert.strictEqual(r.technical.durationSeconds, 1);
});

test("MOV: GPS location atom is read and flagged", async () => {
  const r = await analyseFile(fx("tagged_video.mov"), "tagged_video.mov");
  assert.deepStrictEqual(r.technical.gps, { latitude: 12.9716, longitude: 77.5946 });
  assert.ok(codes(r).includes("GPS_LOCATION"));
  assert.strictEqual(r.properties.title, "Vouch Clip");
});

test("FLAC and Ogg Vorbis comments, WAV INFO chunk", async () => {
  const f = await analyseFile(fx("tagged.flac"), "tagged.flac");
  assert.deepStrictEqual([f.properties.title, f.properties.author, f.technical.durationSeconds], ["Vouch FLAC", "Vedanth", 1]);
  const o = await analyseFile(fx("tagged.ogg"), "tagged.ogg");
  assert.deepStrictEqual([o.properties.title, o.properties.author], ["Vouch OGG", "Ogg Artist"]);
  const w = await analyseFile(fx("tagged.wav"), "tagged.wav");
  assert.deepStrictEqual([w.properties.title, w.properties.author, w.technical.sampleRateHz], ["Vouch WAV", "Wav Artist", 44100]);
});

test("ZIP archive: comment, executables, path traversal, entry dates", async () => {
  const r = await analyseFile(fx("archive.zip"), "archive.zip");
  assert.strictEqual(r.technical.entries, 3);
  assert.strictEqual(r.technical.archiveComment, "Packed by the test suite");
  assert.deepStrictEqual(r.technical.executableEntries, ["bin/tool.exe"]);
  assert.strictEqual(r.technical.earliestEntryModified, "2021-06-01T12:00:00.000Z");
  assert.ok(["ZIP_PATH_TRAVERSAL", "ZIP_EXECUTABLES", "ZIP_COMMENT"].every((c) => codes(r).includes(c)));
  assert.strictEqual(r.riskLevel, "high");
  assert.ok(!codes(r).includes("NO_METADATA"));
});

test("SQLite: header facts only", async () => {
  const r = await analyseFile(fx("sample.sqlite"), "sample.sqlite");
  assert.strictEqual(r.file.detectedType, "SQLite database");
  assert.strictEqual(r.technical.userVersion, 42);
  assert.strictEqual(r.technical.pageSize, 4096);
  assert.strictEqual(r.technical.textEncoding, "UTF-8");
  assert.strictEqual(r.technical.applicationId, "0x" + (1234567).toString(16));
});

test("EML: headers, domain mismatch, authentication claims, attachments", async () => {
  const eml = [
    "Received: from mail.evil.example by mx.example.net; Tue, 5 Mar 2024 10:00:00 +0000",
    "Received: from relay.example by mail.evil.example; Tue, 5 Mar 2024 09:59:00 +0000",
    "Return-Path: <bounce@evil.example>",
    "From: Bank Support <support@mybank.com>",
    "Reply-To: help@other-domain.example",
    "To: you@example.org, me@example.org",
    "Subject: Urgent: verify your account",
    "Date: Tue, 5 Mar 2024 09:58:00 +0000",
    "Message-ID: <abc123@evil.example>",
    "X-Mailer: MassMailer 3.1",
    "Authentication-Results: mx.example.net; spf=fail; dkim=none; dmarc=fail",
    "MIME-Version: 1.0", "Content-Type: multipart/mixed; boundary=XYZ", "",
    "--XYZ", 'Content-Disposition: attachment; filename="invoice.pdf.exe"', "", "AAAA", "--XYZ--", "",
  ].join("\r\n");
  const r = await analyseFile(Buffer.from(eml), "message.eml");
  assert.strictEqual(r.file.detectedType, "Email message (EML)");
  assert.strictEqual(r.properties.title, "Urgent: verify your account");
  assert.strictEqual(r.properties.created, "2024-03-05T09:58:00.000Z");
  assert.strictEqual(r.technical.receivedHops, 2);
  assert.deepStrictEqual(r.technical.attachments, ["invoice.pdf.exe"]);
  assert.ok(["EMAIL_DOMAIN_MISMATCH", "EMAIL_REPLYTO_MISMATCH", "EMAIL_AUTH_FAIL", "EMAIL_CLAIMS"].every((c) => codes(r).includes(c)), codes(r).join());
  assert.ok(!("_fromDomain" in r.technical), "private helper keys are not exposed");
});

test("SVG: scripts and external references are flagged; metadata is read", async () => {
  const svg = '<?xml version="1.0"?><!-- Generator: Adobe Illustrator 27 --><svg xmlns="http://www.w3.org/2000/svg"><title>Logo</title><metadata><dc:creator>Alice</dc:creator></metadata><script>alert(1)</script><image href="https://evil.example/x.png"/></svg>';
  const r = await analyseFile(Buffer.from(svg), "logo.svg");
  assert.strictEqual(r.file.detectedType, "SVG image (XML)");
  assert.strictEqual(r.properties.title, "Logo");
  assert.strictEqual(r.technical.scripts, 1);
  assert.strictEqual(r.technical.externalReferences, 1);
  assert.ok(codes(r).includes("MARKUP_SCRIPT"));
  assert.match(r.properties.creatorTool, /Illustrator/);
});

test("PE: header facts, forged-able timestamp is labelled 'claimed', future stamp alerts", async () => {
  const b = Buffer.alloc(0x200);
  b.write("MZ", 0, "latin1"); b.writeUInt32LE(0x80, 0x3c);
  b.write("PE\0\0", 0x80, "latin1"); b.writeUInt16LE(0x8664, 0x84); b.writeUInt16LE(3, 0x86);
  b.writeUInt32LE(Math.floor(Date.now() / 1000) + 5 * 86400 * 365, 0x88);
  b.writeUInt16LE(0xf0, 0x94); b.writeUInt16LE(0x2022, 0x96); b.writeUInt16LE(0x20b, 0x98);
  const r = await analyseFile(b, "tool.exe");
  assert.strictEqual(r.file.detectedType, "Windows executable (PE)");
  assert.strictEqual(r.technical.machine, "x86-64");
  assert.strictEqual(r.technical.format, "PE32+");
  assert.ok(r.technical.compileTimestampClaimed);
  assert.ok(codes(r).includes("EXECUTABLE") && codes(r).includes("FUTURE_DATE"));
});

test("ELF: reads a real system binary's header", async (t) => {
  const bin = ["/bin/ls", "/usr/bin/ls"].find((p) => fs.existsSync(p));
  if (!bin) return t.skip("no ELF binary on this system");
  const r = await analyseFile(fs.readFileSync(bin).subarray(0, 4096), "ls");
  assert.strictEqual(r.file.detectedType, "ELF binary");
  assert.strictEqual(r.technical.format, "ELF");
  assert.ok(r.technical.machine);
});

test("Fonts: name table is read from a real system font", async (t) => {
  const dirs = ["/usr/share/fonts", "/usr/local/share/fonts", "/System/Library/Fonts", "C:/Windows/Fonts"];
  let font = null;
  const walk = (d, depth = 0) => { try { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory() && depth < 4) walk(p, depth + 1); else if (!font && /\.ttf$/i.test(e.name)) font = p; } } catch (_) { /* ignore */ } };
  dirs.forEach((d) => !font && walk(d));
  if (!font) return t.skip("no TrueType font on this system");
  const r = await analyseFile(fs.readFileSync(font), path.basename(font));
  assert.strictEqual(r.file.detectedType, "Font file");
  assert.ok(r.properties.title, "family name read");
});

test("C2PA manifest marker is detected but never claimed as validated", async () => {
  const jpg = Buffer.concat([fx("clean.jpg").subarray(0, 100), Buffer.from("....jumb....c2pa....")]);
  const r = await analyseFile(Buffer.concat([jpg, fx("clean.jpg").subarray(100)]), "signed.jpg");
  assert.strictEqual(r.technical.c2paManifestPresent, true);
  assert.match(r.findings.find((f) => f.code === "C2PA_PRESENT").message, /does not validate/);
});

test("optional ExifTool hook: disabled by default, runs safely when enabled (stub tool)", async (t) => {
  assert.strictEqual((await analyseFile(fx("tagged.mp3"), "a.mp3")).extended, undefined);
  if (process.platform === "win32") return t.skip("stub uses a shebang script");
  const stub = path.join(os.tmpdir(), "fake-exiftool-" + process.pid);
  fs.writeFileSync(stub, '#!/usr/bin/env node\nconsole.log(JSON.stringify([{SourceFile:process.argv.pop(),"System:FileName":"x","ID3:Title":"Stub Title","File:FileType":"MP3"}]));\n', { mode: 0o755 });
  process.env.EXIFTOOL_PATH = stub;
  try {
    const r = await analyseFile(fx("tagged.mp3"), "a.mp3");
    assert.deepStrictEqual(r.extended.exiftool, { "ID3:Title": "Stub Title", "File:FileType": "MP3" }); // temp-file details removed
  } finally {
    delete process.env.EXIFTOOL_PATH; fs.unlinkSync(stub);
  }
  process.env.EXIFTOOL_PATH = "/nonexistent/exiftool";
  try {
    const r = await analyseFile(fx("tagged.mp3"), "a.mp3");
    assert.ok(r.extended.exiftoolError, "tool failure is reported, not thrown");
    assert.strictEqual(r.properties.title, "Vouch Test Tune", "built-in parsing still works");
  } finally { delete process.env.EXIFTOOL_PATH; }
});
