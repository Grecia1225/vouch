const test = require("node:test");
const assert = require("node:assert");
const { analyseFile, sniffType, pdfDate } = require("../src/services/metadata");

// Tiny ZIP writer (stored, no compression, CRC left 0: our reader ignores CRC)
function makeZip(files) {
  const locals = [], centrals = [];
  let offset = 0;
  for (const [name, content] of Object.entries(files)) {
    const n = Buffer.from(name), d = Buffer.from(content);
    const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4);
    lh.writeUInt32LE(d.length, 18); lh.writeUInt32LE(d.length, 22); lh.writeUInt16LE(n.length, 26);
    const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6);
    ch.writeUInt32LE(d.length, 20); ch.writeUInt32LE(d.length, 24); ch.writeUInt16LE(n.length, 28); ch.writeUInt32LE(offset, 42);
    locals.push(lh, n, d); centrals.push(ch, n);
    offset += 30 + n.length + d.length;
  }
  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(centrals.length / 2, 8); end.writeUInt16LE(centrals.length / 2, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, end]);
}

const PDF = Buffer.from(
  "%PDF-1.4\n1 0 obj\n<< /Title (Rental Agreement) /Author (Alice) /Creator (Microsoft Word) /Producer (iLovePDF) " +
  "/CreationDate (D:20240101100000Z) /ModDate (D:20240301120000+05'30') >>\nendobj\ntrailer\n<< /Info 1 0 R >>\n%%EOF\n" +
  "1 0 obj\n<< /Title (Rental Agreement) /Author (Alice) /Creator (Microsoft Word) /Producer (iLovePDF) " +
  "/CreationDate (D:20240101100000Z) /ModDate (D:20240301120000+05'30') >>\nendobj\ntrailer\n<< /Info 1 0 R >>\n%%EOF\n", "latin1");

test("detects types from magic bytes, not file names", () => {
  assert.strictEqual(sniffType(Buffer.from("%PDF-1.7")).kind, "pdf");
  assert.strictEqual(sniffType(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0])).mime, "image/png");
  assert.strictEqual(sniffType(Buffer.from([0xff, 0xd8, 0xff, 0xe0])).mime, "image/jpeg");
});

test("parses PDF dates with timezone offsets", () => {
  assert.strictEqual(pdfDate("D:20240301120000+05'30'"), "2024-03-01T06:30:00.000Z");
  assert.strictEqual(pdfDate("D:20240101100000Z"), "2024-01-01T10:00:00.000Z");
});

test("PDF: reads Info dictionary and flags edits", async () => {
  const r = await analyseFile(PDF, "agreement.pdf");
  assert.strictEqual(r.properties.title, "Rental Agreement");
  assert.strictEqual(r.properties.author, "Alice");
  assert.strictEqual(r.properties.creatorTool, "Microsoft Word");
  assert.strictEqual(r.technical.incrementalUpdates, 1);
  const codes = r.findings.map((f) => f.code);
  assert.ok(codes.includes("EDITED_AFTER_CREATION"));
  assert.ok(codes.includes("PDF_INCREMENTAL_UPDATES"));
  assert.ok(codes.includes("PDF_EDITOR"));
  assert.strictEqual(r.riskLevel, "medium");
  assert.strictEqual(r.hashes.sha256.length, 64);
});

test("flags a file whose extension does not match its contents", async () => {
  const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52, 0, 0, 0, 5, 0, 0, 0, 7]);
  const r = await analyseFile(png, "contract.pdf");
  assert.strictEqual(r.file.extensionMatches, false);
  assert.ok(r.findings.some((f) => f.code === "EXTENSION_MISMATCH"));
  assert.strictEqual(r.riskLevel, "high");
  assert.strictEqual(r.technical.width, 5);
  assert.strictEqual(r.technical.height, 7);
});

test("DOCX: reads core/app properties, macros and tracked changes", async () => {
  const zip = makeZip({
    "[Content_Types].xml": "<Types/>",
    "word/document.xml": '<w:document><w:ins w:id="1"/><w:ins w:id="2"/><w:del w:id="3"/></w:document>',
    "word/vbaProject.bin": "x",
    "docProps/core.xml":
      "<cp:coreProperties><dc:title>Offer &amp; Terms</dc:title><dc:creator>Bob</dc:creator><cp:lastModifiedBy>Carol</cp:lastModifiedBy>" +
      "<dcterms:created>2024-02-01T09:00:00Z</dcterms:created><dcterms:modified>2024-02-05T09:00:00Z</dcterms:modified><cp:revision>4</cp:revision></cp:coreProperties>",
    "docProps/app.xml": "<Properties><Application>Microsoft Office Word</Application><TotalTime>95</TotalTime></Properties>",
  });
  const r = await analyseFile(zip, "offer.docx");
  assert.strictEqual(r.file.detectedType, "Word document (DOCX)");
  assert.strictEqual(r.properties.title, "Offer & Terms");
  assert.strictEqual(r.properties.author, "Bob");
  assert.strictEqual(r.properties.lastModifiedBy, "Carol");
  assert.strictEqual(r.technical.trackedInsertions, 2);
  assert.strictEqual(r.technical.trackedDeletions, 1);
  assert.strictEqual(r.technical.containsMacros, true);
  const codes = r.findings.map((f) => f.code);
  assert.ok(codes.includes("OFFICE_MACROS") && codes.includes("DIFFERENT_LAST_EDITOR") && codes.includes("TRACKED_CHANGES"));
});

test("inconsistent dates are flagged", async () => {
  const zip = makeZip({
    "word/document.xml": "<w:document/>",
    "docProps/core.xml": "<cp:coreProperties><dcterms:created>2024-05-01T00:00:00Z</dcterms:created><dcterms:modified>2024-04-01T00:00:00Z</dcterms:modified></cp:coreProperties>",
  });
  const r = await analyseFile(zip, "a.docx");
  assert.ok(r.findings.some((f) => f.code === "MODIFIED_BEFORE_CREATED"));
});

test("never throws on garbage input", async () => {
  const r = await analyseFile(Buffer.from([0, 1, 2, 3, 4, 5, 6, 7]), "weird.bin");
  assert.strictEqual(r.file.detectedType, "Unknown binary");
  assert.ok(Array.isArray(r.findings));
});
