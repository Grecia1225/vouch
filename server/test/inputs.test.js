const test = require("node:test");
const assert = require("node:assert");
const http = require("http");
const cfg = require("../src/config");
const { isPrivateIp, fetchRemote } = require("../src/services/remoteFile");
const { collectInputs, cleanContext } = require("../src/services/inputs");
const { analyseFile, sniffType } = require("../src/services/metadata");

test("isPrivateIp recognises local and private ranges", () => {
  for (const ip of ["127.0.0.1", "10.1.2.3", "192.168.0.5", "172.16.0.1", "169.254.169.254", "0.0.0.0", "::1", "fd00::1", "::ffff:127.0.0.1"])
    assert.ok(isPrivateIp(ip), ip);
  for (const ip of ["8.8.8.8", "93.184.216.34", "172.32.0.1"]) assert.ok(!isPrivateIp(ip), ip);
});

test("links to private/local addresses and odd schemes are blocked by default", async () => {
  cfg.allowPrivateUrls = false;
  await assert.rejects(() => fetchRemote("http://127.0.0.1:9/x"), /private or local/);
  await assert.rejects(() => fetchRemote("http://localhost:9/x"), /private or local/);
  await assert.rejects(() => fetchRemote("http://169.254.169.254/latest/meta-data"), /private or local/);
  await assert.rejects(() => fetchRemote("file:///etc/passwd"), /http and https/);
  await assert.rejects(() => fetchRemote("http://user:pw@example.com/"), /credentials/);
  await assert.rejects(() => fetchRemote("not a url"), /valid link/);
});

test("fetches a file (following a redirect) and enforces the size limit when allowed", async () => {
  const server = http.createServer((req, res) => {
    if (req.url === "/r") { res.writeHead(302, { Location: "/files/report.txt" }); return res.end(); }
    if (req.url === "/big") { res.writeHead(200); return res.end(Buffer.alloc(cfg.maxFileBytes + 10)); }
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("hello vouch");
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    cfg.allowPrivateUrls = true;
    const r = await fetchRemote(base + "/r");
    assert.strictEqual(r.buffer.toString(), "hello vouch");
    assert.strictEqual(r.filename, "report.txt");
    assert.strictEqual(r.mimeType, "text/plain");
    await assert.rejects(() => fetchRemote(base + "/big"), /10 MB/);
  } finally {
    cfg.allowPrivateUrls = false;
    server.close();
  }
});

test("cleanContext keeps only validated fields", () => {
  const c = cleanContext({ source: "camera", capturedAt: "2024-01-01T00:00:00Z", location: { latitude: 12.34567891, longitude: 78.9, accuracy: 12.6 }, durationSec: 4.4, evil: "x" });
  assert.strictEqual(c.source, "camera");
  assert.strictEqual(c.location.latitude, 12.345679);
  assert.strictEqual(c.location.accuracyMeters, 13);
  assert.strictEqual(c.durationSec, 4);
  assert.ok(!("evil" in c));
  assert.ok(!cleanContext({ location: { latitude: 999, longitude: 1 } }).location);
  assert.strictEqual(cleanContext({ source: "hacker" }, "file").source, "file");
});

test("collectInputs merges files and links, reporting per-item errors", async () => {
  cfg.allowPrivateUrls = false;
  const req = {
    files: [{ originalname: "a.pdf", buffer: Buffer.from("x"), mimetype: "application/pdf" }],
    body: { contexts: JSON.stringify([{ source: "camera", location: { latitude: 1, longitude: 2 } }]), urls: JSON.stringify(["http://127.0.0.1:1/x"]) },
  };
  const items = await collectInputs(req);
  assert.strictEqual(items.length, 2);
  assert.strictEqual(items[0].context.source, "camera");
  assert.ok(items[1].error && /private or local/.test(items[1].error));
  assert.strictEqual(items[1].context.source, "url");
});

test("audio is recognised and live captures are described, not flagged as stripped", async () => {
  assert.strictEqual(sniffType(Buffer.from([0x1a, 0x45, 0xdf, 0xa3, 0, 0, 0, 0])).kind, "media");
  const webm = Buffer.from([0x1a, 0x45, 0xdf, 0xa3, 1, 2, 3, 4, 5, 6]);
  const r = await analyseFile(webm, "voice-1.webm", { context: { source: "voice", durationSec: 7, location: { latitude: 1, longitude: 2 } } });
  const codes = r.findings.map((f) => f.code);
  assert.ok(codes.includes("LIVE_VOICE") && codes.includes("CAPTURE_LOCATION") && codes.includes("MEDIA_LIMITED"));
  assert.strictEqual(r.capture.source, "voice");
  assert.strictEqual(r.file.extensionMatches, true);
});

test("camera photo: no 'stripped metadata' warning for live captures", async () => {
  const jpg = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 16, 74, 70, 73, 70, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0xff, 0xd9]);
  const r = await analyseFile(jpg, "photo-1.jpg", { context: { source: "camera" } });
  assert.ok(!r.findings.some((f) => f.code === "NO_METADATA"));
  assert.ok(r.findings.some((f) => f.code === "LIVE_CAMERA"));
});
