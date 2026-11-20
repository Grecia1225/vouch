/**
 * Vouch measurements that need no blockchain: hashing speed, avalanche effect, tamper detection.
 *   node scripts/measure-hash.js [trials]     (default 2000)
 * Writes ../measurements/hash-results.json and hash-results.md
 */
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const TRIALS = Number(process.argv[2]) || 2000;
const sha = (b) => crypto.createHash("sha256").update(b).digest();
const popcount = (n) => { let c = 0; while (n) { c += n & 1; n >>= 1; } return c; };
const hamming = (a, b) => a.reduce((s, x, i) => s + popcount(x ^ b[i]), 0);
const stats = (xs) => { const m = xs.reduce((a, b) => a + b, 0) / xs.length; return { mean: m, min: Math.min(...xs), max: Math.max(...xs), sd: Math.sqrt(xs.reduce((a, b) => a + (b - m) ** 2, 0) / xs.length) }; };

// 1. Hashing throughput
const throughput = [];
for (const [label, bytes, reps] of [["1 KB", 1024, 2000], ["100 KB", 102400, 200], ["1 MB", 1048576, 40], ["10 MB", 10485760, 8]]) {
  const buf = crypto.randomBytes(bytes);
  sha(buf); // warm up
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < reps; i++) sha(buf);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6 / reps;
  throughput.push({ size: label, bytes, msPerHash: +ms.toFixed(3), mbPerSec: +((bytes / 1048576) / (ms / 1000)).toFixed(1) });
}

// 2. Avalanche effect: flip one random bit, count how many of the 256 hash bits change (ideal: 128)
const dists = [];
for (let i = 0; i < TRIALS; i++) {
  const buf = crypto.randomBytes(4096);
  const h1 = sha(buf);
  const bit = crypto.randomInt(buf.length * 8);
  buf[bit >> 3] ^= 1 << (bit & 7);
  dists.push(hamming(h1, sha(buf)));
}
const avalanche = stats(dists);

// 3. Tamper detection: every modified file must hash differently from the registered original
const tampers = {
  "flip 1 bit": (b) => { const c = Buffer.from(b); const k = crypto.randomInt(c.length * 8); c[k >> 3] ^= 1 << (k & 7); return c; },
  "change 1 byte": (b) => { const c = Buffer.from(b); const k = crypto.randomInt(c.length); c[k] = (c[k] + 1) & 255; return c; },
  "delete 1 byte": (b) => { const k = crypto.randomInt(b.length); return Buffer.concat([b.subarray(0, k), b.subarray(k + 1)]); },
  "append 1 byte": (b) => Buffer.concat([b, Buffer.from([0])]),
  "swap 2 bytes": (b) => { const c = Buffer.from(b); const i = crypto.randomInt(c.length - 1); const t = c[i]; c[i] = c[i + 1]; c[i + 1] = t; return c; },
};
const detection = {};
for (const [name, fn] of Object.entries(tampers)) {
  let detected = 0, effective = 0;
  for (let i = 0; i < TRIALS; i++) {
    const original = crypto.randomBytes(1024 + crypto.randomInt(8192));
    const changed = fn(original);
    if (Buffer.compare(original, changed) === 0) continue; // swapping equal bytes changes nothing: not a tamper
    effective++;
    if (!sha(original).equals(sha(changed))) detected++;
  }
  detection[name] = { trials: effective, detected, rate: +(detected / effective * 100).toFixed(2) };
}

const result = {
  generatedAt: new Date().toISOString(),
  machine: { node: process.version, cpu: os.cpus()[0].model, cores: os.cpus().length, platform: os.platform() },
  trials: TRIALS, throughput,
  avalanche: { ...Object.fromEntries(Object.entries(avalanche).map(([k, v]) => [k, +v.toFixed(2)])), idealBits: 128, hashBits: 256 },
  tamperDetection: detection,
};

const md = `# Hash measurements (no blockchain needed)

Generated ${result.generatedAt} on ${result.machine.cpu} (${result.machine.cores} cores), Node ${result.machine.node}. Numbers depend on the machine: re-run \`node server/scripts/measure-hash.js\` on yours and quote your own.

## SHA-256 speed
| File size | Time per hash | Throughput |
|---|---|---|
${throughput.map((t) => `| ${t.size} | ${t.msPerHash} ms | ${t.mbPerSec} MB/s |`).join("\n")}

The server's 10 MB upload limit means hashing is never the bottleneck: the blockchain write dominates.

## Avalanche effect (${TRIALS} random 4 KB files, 1 random bit flipped)
Bits of the 256-bit hash that changed: mean **${result.avalanche.mean}** (ideal 128), min ${result.avalanche.min}, max ${result.avalanche.max}, standard deviation ${result.avalanche.sd}.

## Tamper detection (${TRIALS} random files per attack)
| Modification | Trials | Detected | Detection rate |
|---|---|---|---|
${Object.entries(detection).map(([k, v]) => `| ${k} | ${v.trials} | ${v.detected} | ${v.rate}% |`).join("\n")}

A modified file hashes differently, so the registered fingerprint no longer matches and verification reports it. (Hash collisions are computationally infeasible for SHA-256; this test shows the property holds in practice, it is not a proof.)
`;
const dir = path.join(__dirname, "../../measurements");
fs.mkdirSync(dir, { recursive: true });
fs.writeFileSync(path.join(dir, "hash-results.json"), JSON.stringify(result, null, 2));
fs.writeFileSync(path.join(dir, "hash-results.md"), md);
console.log(md);
