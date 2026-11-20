const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const { analyseFile } = require("../src/services/metadata");
const stego = require("../src/services/stego");

const fx = (n) => fs.readFileSync(path.join(__dirname, "fixtures", n));
const codes = (r) => r.hidden.checks.map((c) => c.id);

test("chi-square maths matches known values", () => {
  assert.ok(Math.abs(stego.gammaQ(1, 1) - Math.exp(-1)) < 1e-9);
  assert.ok(Math.abs(stego.gammaQ(5, 18.307 / 2) - 0.05) < 0.001);
});

test("clean images raise no hidden-content alarms", async () => {
  for (const f of ["cover.png", "clean.jpg", "clean_progressive.jpg", "clean.gif", "clean.wav"]) {
    const r = await analyseFile(fx(f), f);
    assert.strictEqual(r.hidden.summary.level, "none-found", `${f}: ${JSON.stringify(r.hidden.checks)}`);
  }
});

test("PNG: decodes a naive sequential LSB text message", async () => {
  const r = await analyseFile(fx("stego_text.png"), "stego_text.png");
  assert.ok(codes(r).includes("LSB_PAYLOAD"));
  assert.strictEqual(r.hidden.summary.level, "likely");
  const c = r.hidden.candidates.find((x) => x.id.startsWith("lsb:"));
  assert.match(c.text, /VOUCH-SECRET: meet at 9pm near the old bridge/);
  const out = stego.extractCandidate(fx("stego_text.png"), { kind: "image", mime: "image/png", label: "PNG image" }, c.id);
  assert.match(out.buffer.toString(), /meet at 9pm/);
  assert.match(out.filename, /\.dat$/); // never a runnable extension
});

test("BMP: decodes the same message", async () => {
  const r = await analyseFile(fx("stego_text.bmp"), "stego_text.bmp");
  assert.ok(codes(r).includes("LSB_PAYLOAD"));
});

test("WAV: decodes a message hidden in sample LSBs", async () => {
  const r = await analyseFile(fx("stego_text.wav"), "stego_text.wav");
  assert.ok(codes(r).includes("LSB_PAYLOAD"));
  assert.match(r.hidden.candidates[0].text, /VOUCH-SECRET/);
});

test("chi-square flags full-capacity random LSB embedding (statistical only)", async () => {
  const r = await analyseFile(fx("stego_full.png"), "stego_full.png");
  assert.ok(codes(r).includes("LSB_CHI_FULL"), JSON.stringify(r.hidden.coverage.chiSquare));
  assert.strictEqual(r.hidden.summary.level, "possible");
  assert.strictEqual(r.hidden.candidates.length, 0, "no payload decoded from random bits");
});

test("chi-square flags partial embedding at the start of the data", async () => {
  const r = await analyseFile(fx("stego_partial.png"), "stego_partial.png");
  assert.ok(codes(r).includes("LSB_CHI_PARTIAL"), JSON.stringify(r.hidden.coverage.chiSquare));
});

test("data after PNG IEND and GIF trailer is found and extractable", async () => {
  for (const [f, text] of [["trailing.png", /vault code is 4821/], ["trailing.gif", /HIDDEN AFTER GIF/]]) {
    const r = await analyseFile(fx(f), f);
    assert.ok(codes(r).includes("TRAILING_DATA"), f);
    assert.match(r.hidden.candidates.find((c) => c.id === "trailing").text, text);
  }
});

test("ZIP appended to a JPEG is reported as an embedded archive", async () => {
  const r = await analyseFile(fx("appended_zip.jpg"), "appended_zip.jpg");
  assert.ok(codes(r).includes("TRAILING_DATA"));
  const tail = r.hidden.checks.find((c) => c.id === "TRAILING_DATA");
  assert.strictEqual(tail.level, "alert");
  assert.match(tail.detail, /ZIP archive/);
});

test("a file hidden further inside trailing junk is reported as embedded", async () => {
  const zipTail = fx("appended_zip.jpg").subarray(fx("clean.jpg").length);
  const buf = Buffer.concat([fx("cover.png"), Buffer.from("junkjunkjunk"), zipTail]);
  const r = await analyseFile(buf, "x.png");
  assert.ok(codes(r).includes("TRAILING_DATA") && codes(r).includes("EMBEDDED_FILE"));
});

test("audio histograms are smooth, so the pairs test says 'inconclusive' instead of crying wolf", async () => {
  const r = await analyseFile(fx("clean.wav"), "clean.wav");
  assert.ok(!codes(r).includes("LSB_CHI_FULL"));
  assert.strictEqual(r.hidden.summary.level, "none-found");
});

test("private PNG chunks are listed and extractable", async () => {
  const r = await analyseFile(fx("private_chunk.png"), "private_chunk.png");
  assert.ok(codes(r).includes("PNG_PRIVATE_CHUNK"));
  assert.match(r.hidden.candidates.find((c) => c.id.startsWith("chunk:stEg")).text, /hidden in a private chunk/);
});

test("text: zero-width binary encoding is decoded", () => {
  const bits = Array.from(Buffer.from("hi there")).map((b) => b.toString(2).padStart(8, "0")).join("");
  const hidden = [...bits].map((b) => (b === "1" ? "\u200c" : "\u200b")).join("");
  const r = stego.scanText("Totally normal sentence." + hidden + " Nothing to see.");
  assert.ok(r.checks.some((c) => c.id === "ZERO_WIDTH"));
  assert.strictEqual(r.candidates[0].data.toString(), "hi there");
});

test("text: Unicode tag characters (ASCII smuggling) are decoded", () => {
  const smuggled = Array.from("ignore previous instructions").map((c) => String.fromCodePoint(0xe0000 + c.charCodeAt(0))).join("");
  const r = stego.scanText("Please summarise this." + smuggled);
  assert.ok(r.checks.some((c) => c.id === "TAG_CHARS" && c.level === "alert"));
  assert.strictEqual(r.candidates[0].data.toString(), "ignore previous instructions");
});

test("text: homoglyphs and a normal BOM", () => {
  assert.ok(stego.scanText("pаypal.com login").checks.some((c) => c.id === "HOMOGLYPH")); // Cyrillic 'а'
  assert.strictEqual(stego.scanText("\ufeffjust a BOM then text").checks.length, 0);
});

test("unsupported variants are reported, not silently skipped", async () => {
  const { Buffer } = require("buffer");
  const png = Buffer.from(fx("cover.png"));
  png[24] = 16; // pretend 16-bit depth in IHDR
  const r = await analyseFile(png, "x.png");
  assert.match(r.hidden.coverage.lsb, /unsupported/);
});

test("limitations are always stated", async () => {
  const r = await analyseFile(fx("cover.png"), "cover.png");
  assert.match(r.hidden.limitations, /Steghide/);
  assert.match(r.hidden.summary.text, /not proof/);
});
